//go:build ignore
#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"
#include "tcpconnlat.h"

#define AF_INET    2
#define AF_INET6   10

const volatile __u64 targ_min_us = 0;
const volatile pid_t targ_tgid = 0;

struct piddata {
	char comm[TASK_COMM_LEN];
	u64 ts;
	u32 tgid;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct sock *);
	__type(value, struct piddata);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct traffic_key);
	__type(value, struct traffic_value);
} traffic_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__type(value, struct event);
} events SEC(".maps");

static int trace_connect(struct sock *sk)
{
	u32 tgid = bpf_get_current_pid_tgid() >> 32;
	struct piddata piddata = {};

	if (targ_tgid && targ_tgid != tgid)
		return 0;

	bpf_get_current_comm(&piddata.comm, sizeof(piddata.comm));
	piddata.ts = bpf_ktime_get_ns();
	piddata.tgid = tgid;
	bpf_map_update_elem(&start, &sk, &piddata, 0);
	return 0;
}

static int handle_tcp_rcv_state_process(void *ctx, struct sock *sk)
{
	struct piddata *piddatap;
	struct event event = {};
	s64 delta;
	u64 ts;

	if (BPF_CORE_READ(sk, __sk_common.skc_state) != TCP_SYN_SENT)
		return 0;

	piddatap = bpf_map_lookup_elem(&start, &sk);
	if (!piddatap)
		return 0;

	ts = bpf_ktime_get_ns();
	delta = (s64)(ts - piddatap->ts);
	if (delta < 0)
		goto cleanup;

	event.delta_us = delta / 1000U;
	if (targ_min_us && event.delta_us < targ_min_us)
		goto cleanup;
	__builtin_memcpy(&event.comm, piddatap->comm,
			sizeof(event.comm));
	event.ts_us = ts / 1000;
	event.tgid = piddatap->tgid;
	event.lport = BPF_CORE_READ(sk, __sk_common.skc_num);
	event.dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
	event.af = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (event.af == AF_INET) {
		event.saddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		event.daddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	} else {
		BPF_CORE_READ_INTO(&event.saddr_v6, sk,
				__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		BPF_CORE_READ_INTO(&event.daddr_v6, sk,
				__sk_common.skc_v6_daddr.in6_u.u6_addr32);
	}
	bpf_printk("submitting perf event");
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			&event, sizeof(event));

cleanup:
	bpf_map_delete_elem(&start, &sk);
	return 0;
}

static int trace_tcp(bool receiving, struct sock *sk, size_t size) {
	struct traffic_key key = {};
	struct traffic_value *valuep;
	u16 family;
	u32 pid;
	pid = bpf_get_current_pid_tgid() >> 32;
	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (family != AF_INET && family != AF_INET6)
		return 0;
	key.pid = pid;
	bpf_get_current_comm(&key.name, sizeof(key.name));
	key.lport = BPF_CORE_READ(sk, __sk_common.skc_num);
	key.dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
	key.family = family;
	if (family == AF_INET) {
		key.saddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		key.daddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);

	} else {
		BPF_CORE_READ_INTO(&key.saddr_v6, sk,
				__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		BPF_CORE_READ_INTO(&key.daddr_v6, sk,
				__sk_common.skc_v6_daddr.in6_u.u6_addr32);
	}
	valuep = bpf_map_lookup_elem(&traffic_map, &key);
	if (!valuep) {
		struct traffic_value zero;

		if (receiving) {
			zero.tx = 0;
			zero.rx = size;
		} else {
			zero.tx = size;
			zero.rx = 0;
		}
		bpf_map_update_elem(&traffic_map, &key, &zero, BPF_NOEXIST);
	} else {
		if (receiving)
			valuep->rx += size;
		else
			valuep->tx += size;
		bpf_map_update_elem(&traffic_map, &key, valuep, 0);
	}
	return 0;
}

SEC("tracepoint/tcp/tcp_destroy_sock")
int tcp_destroy_sock(struct trace_event_raw_tcp_event_sk *ctx)
{
	const struct sock *sk = ctx->skaddr;
	bpf_map_delete_elem(&start, &sk);
	return 0;
}

SEC("fentry/tcp_v4_connect")
int BPF_PROG(fentry_tcp_v4_connect, struct sock *sk)
{
	return trace_connect(sk);
}

SEC("fentry/tcp_v6_connect")
int BPF_PROG(fentry_tcp_v6_connect, struct sock *sk)
{
	return trace_connect(sk);
}

SEC("fentry/tcp_rcv_state_process")
int BPF_PROG(fentry_tcp_rcv_state_process, struct sock *sk)
{
	bpf_printk("tcp_rcv_state_process");
	return handle_tcp_rcv_state_process(ctx, sk);
}

SEC("fentry/tcp_sendmsg")
int BPF_PROG(fentry_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
	return trace_tcp(false, sk, size);
}

/*
 * tcp_recvmsg() would be obvious to trace, but is less suitable because:
 * - we'd need to trace both entry and return, to have both sock and size
 * - misses tcp_read_sock() traffic
 */
SEC("fentry/tcp_cleanup_rbuf")
int BPF_PROG(fentry_tcp_cleanup_rbuf, struct sock *sk, int copied)
{
	if (copied <= 0) {
		return 0;
	}
	return trace_tcp(true, sk, copied);
}

char LICENSE[] SEC("license") = "GPL";
