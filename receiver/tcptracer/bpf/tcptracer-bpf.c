#include <linux/kconfig.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
#include <linux/ptrace.h>
#pragma clang diagnostic pop
#include <linux/bpf.h>
#include <linux/blk_types.h>
#include <linux/version.h>
#include "bpf_helpers.h"
#include "tcptracer-bpf.h"
#include "tcptracer-maps.h"

#include <uapi/linux/ptrace.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wtautological-compare"
#pragma clang diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"
#pragma clang diagnostic ignored "-Wenum-conversion"
#include <net/sock.h>
#pragma clang diagnostic pop
#include <net/inet_sock.h>
#include <net/net_namespace.h>
#include <linux/tcp.h>

#define bpf_debug(fmt, ...)                                        \
	({                                                             \
		char ____fmt[] = fmt;                                      \
		bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
	})

/* http://stackoverflow.com/questions/1001307/detecting-endianness-programmatically-in-a-c-program */
__attribute__((always_inline))
static bool is_big_endian(void) {
	union {
		uint32_t i;
		char c[4];
	} bint = {0x01020304};

	return bint.c[0] == 1;
}

/* check if IPs are IPv4 mapped to IPv6 ::ffff:xxxx:xxxx
 * https://tools.ietf.org/html/rfc4291#section-2.5.5
 * the addresses are stored in network byte order so IPv4 adddress is stored
 * in the most significant 32 bits of part saddr_l and daddr_l.
 * Meanwhile the end of the mask is stored in the least significant 32 bits.
 */
__attribute__((always_inline))
static bool is_ipv4_mapped_ipv6(u64 saddr_h, u64 saddr_l, u64 daddr_h, u64 daddr_l) {
	if (is_big_endian()) {
		return ((saddr_h == 0 && ((u32)(saddr_l >> 32) == 0x0000FFFF)) || (daddr_h == 0 && ((u32)(daddr_l >> 32) == 0x0000FFFF)));
	} else {
		return ((saddr_h == 0 && ((u32) saddr_l == 0xFFFF0000)) || (daddr_h == 0 && ((u32) daddr_l == 0xFFFF0000)));
	}
}

__attribute__((always_inline))
static bool proc_t_comm_equals(struct proc_t a, struct proc_t b) {
	int i;
	for (i = 0; i < TASK_COMM_LEN; i++) {
		if (a.comm[i] != b.comm[i]) {
			return false;
		}
	}
	return true;
}

__attribute__((always_inline))
static int is_tracer_status_ready(struct tcptracer_status_t *status) {
	switch (status->state) {
		case TCPTRACER_STATE_READY:
			return 1;
		default:
			return 0;
	}
}


__attribute__((always_inline))
static int update_tracer_offset_status_v4(struct tcptracer_status_t *status, struct sock *skp, u64 pid, u64 calling_probe) {
	u64 zero = 0;

	// Only traffic for the expected process name. Extraneous connections from other processes must be ignored here.
	// Userland must take care to generate connections from the correct thread. In Golang, this can be achieved
	// with runtime.LockOSThread.
	struct proc_t proc = {};
	bpf_get_current_comm(&proc.comm, sizeof(proc.comm));

	if (!proc_t_comm_equals(status->proc, proc))
		return 0;

//	bpf_debug("proc: %s, pid: %d, caller: %lu\n", proc.comm, pid, calling_probe);

	// shift existing calling probes by 1
	int cof;
	for (cof = 0; cof < 9; cof++) {
		status->calling_probes[cof+1] = status->calling_probes[cof];
	}
	// prepend current calling probe
	status->calling_probes[0] = calling_probe;

	switch (status->state) {
		case TCPTRACER_STATE_UNINITIALIZED:
			return 0;
		case TCPTRACER_STATE_CHECKING:
			break;
		case TCPTRACER_STATE_CHECKED:
			return 0;
		case TCPTRACER_STATE_READY:
			return 1;
		default:
			return 0;
	}

	struct tcptracer_status_t new_status = {};
	new_status.state = TCPTRACER_STATE_CHECKED;
	new_status.what = status->what;
	new_status.offset_saddr = status->offset_saddr;
	new_status.offset_daddr = status->offset_daddr;
	new_status.offset_sport = status->offset_sport;
	new_status.offset_dport = status->offset_dport;
	new_status.offset_netns = status->offset_netns;
	new_status.offset_ino = status->offset_ino;
	new_status.offset_family = status->offset_family;
	new_status.offset_daddr_ipv6 = status->offset_daddr_ipv6;
	new_status.err = 0;
	new_status.saddr = status->saddr;
	new_status.daddr = status->daddr;
	new_status.sport = status->sport;
	new_status.dport = status->dport;
	new_status.netns = status->netns;
	new_status.family = status->family;
	new_status.iter_type = status->iter_type;
	new_status.protocol_inspection_enabled = status->protocol_inspection_enabled;

	bpf_probe_read(&new_status.proc.comm, sizeof(proc.comm), proc.comm);

	int i;
	for (i = 0; i < 4; i++) {
		new_status.daddr_ipv6[i] = status->daddr_ipv6[i];
	}
	int j;
	for (j = 0; j < 10; j++) {
		new_status.calling_probes[j] = status->calling_probes[j];
	}

	u32 possible_saddr;
	u32 possible_daddr;
	u16 possible_sport;
	u16 possible_dport;
	possible_net_t *possible_skc_net;
	u32 possible_netns;
	u16 possible_family;
	long ret = 0;

	switch (status->what) {
		case GUESS_SADDR:
			possible_saddr = 0;
			bpf_probe_read(&possible_saddr, sizeof(possible_saddr), ((char *) skp) + status->offset_saddr);
			new_status.saddr = possible_saddr;
			break;
		case GUESS_DADDR:
			possible_daddr = 0;
			bpf_probe_read(&possible_daddr, sizeof(possible_daddr), ((char *) skp) + status->offset_daddr);
			new_status.daddr = possible_daddr;
			break;
		case GUESS_FAMILY:
			possible_family = 0;
			bpf_probe_read(&possible_family, sizeof(possible_family), ((char *) skp) + status->offset_family);
			new_status.family = possible_family;
			break;
		case GUESS_SPORT:
			possible_sport = 0;
			bpf_probe_read(&possible_sport, sizeof(possible_sport), ((char *) skp) + status->offset_sport);
			new_status.sport = possible_sport;
			break;
		case GUESS_DPORT:
			possible_dport = 0;
			bpf_probe_read(&possible_dport, sizeof(possible_dport), ((char *) skp) + status->offset_dport);
			new_status.dport = possible_dport;
			break;
		case GUESS_NETNS:
			possible_netns = 0;
			possible_skc_net = NULL;
			bpf_probe_read(&possible_skc_net, sizeof(possible_net_t *), ((char *) skp) + status->offset_netns);
			// if we get a kernel fault, it means possible_skc_net
			// is an invalid pointer, signal an error so we can go
			// to the next offset_netns
			ret = bpf_probe_read(&possible_netns, sizeof(possible_netns), ((char *) possible_skc_net) + status->offset_ino);
			if (ret == -EFAULT) {
				new_status.err = 1;
				break;
			}
			new_status.netns = possible_netns;
			break;
		default:
			// not for us
			return 0;
	}

	bpf_map_update_elem(&tcptracer_status, &zero, &new_status, BPF_ANY);

	return 0;
}

__attribute__((always_inline))
static int update_tracer_offset_status_v6(struct tcptracer_status_t *status, struct sock *skp, u64 pid, u64 calling_probe) {
	u64 zero = 0;

	// Only traffic for the expected process name. Extraneous connections from other processes must be ignored here.
	// Userland must take care to generate connections from the correct thread. In Golang, this can be achieved
	// with runtime.LockOSThread.
	struct proc_t proc = {};
	bpf_get_current_comm(&proc.comm, sizeof(proc.comm));

	if (!proc_t_comm_equals(status->proc, proc)) {
		return 0;
	}

	// shift existing calling probes by 1
	int cof;
	for (cof = 0; cof < 9; cof++) {
		status->calling_probes[cof+1] = status->calling_probes[cof];
	}
	// prepend current calling probe
	status->calling_probes[0] = calling_probe;

	switch (status->state) {
		case TCPTRACER_STATE_UNINITIALIZED:
			return 0;
		case TCPTRACER_STATE_CHECKING:
			break;
		case TCPTRACER_STATE_CHECKED:
			return 0;
		case TCPTRACER_STATE_READY:
			return 1;
		default:
			return 0;
	}

	struct tcptracer_status_t new_status = {};
	new_status.state = TCPTRACER_STATE_CHECKED;
	new_status.what = status->what;
	new_status.offset_saddr = status->offset_saddr;
	new_status.offset_daddr = status->offset_daddr;
	new_status.offset_sport = status->offset_sport;
	new_status.offset_dport = status->offset_dport;
	new_status.offset_netns = status->offset_netns;
	new_status.offset_ino = status->offset_ino;
	new_status.offset_family = status->offset_family;
	new_status.offset_daddr_ipv6 = status->offset_daddr_ipv6;
	new_status.err = 0;
	new_status.saddr = status->saddr;
	new_status.daddr = status->daddr;
	new_status.sport = status->sport;
	new_status.dport = status->dport;
	new_status.netns = status->netns;
	new_status.family = status->family;
	new_status.iter_type = status->iter_type;
	new_status.protocol_inspection_enabled = status->protocol_inspection_enabled;

	bpf_probe_read(&new_status.proc.comm, sizeof(proc.comm), proc.comm);

	int i;
	for (i = 0; i < 4; i++) {
		new_status.daddr_ipv6[i] = status->daddr_ipv6[i];
	}

	int j;
	for (j = 0; j < 10; j++) {
		new_status.calling_probes[j] = status->calling_probes[j];
	}

	u32 possible_daddr_ipv6[4] = {};
	switch (status->what) {
		case GUESS_DADDR_IPV6:
			bpf_probe_read(&possible_daddr_ipv6, sizeof(possible_daddr_ipv6), ((char *) skp) + status->offset_daddr_ipv6);

			int i;
			for (i = 0; i < 4; i++) {
				new_status.daddr_ipv6[i] = possible_daddr_ipv6[i];
			}
			break;
		default:
			// not for us
			return 0;
	}

	bpf_map_update_elem(&tcptracer_status, &zero, &new_status, BPF_ANY);

	return 0;
}

__attribute__((always_inline))
static bool check_family(struct sock *sk, struct tcptracer_status_t *status, u16 expected_family) {
	u16 family = 0;
	bpf_probe_read(&family, sizeof(u16), ((char *) sk) + status->offset_family);
	return family == expected_family;
}

__attribute__((always_inline))
static int read_ipv4_tuple(struct ipv4_tuple_t *tuple, struct tcptracer_status_t *status, struct sock *skp) {
	u32 saddr, daddr, net_ns_inum;
	u16 sport, dport;
	possible_net_t *skc_net;

	saddr = 0;
	daddr = 0;
	sport = 0;
	dport = 0;
	skc_net = NULL;
	net_ns_inum = 0;

	bpf_probe_read(&saddr, sizeof(saddr), ((char *) skp) + status->offset_saddr);
	bpf_probe_read(&daddr, sizeof(daddr), ((char *) skp) + status->offset_daddr);
	bpf_probe_read(&sport, sizeof(sport), ((char *) skp) + status->offset_sport);
	bpf_probe_read(&dport, sizeof(dport), ((char *) skp) + status->offset_dport);
	// Get network namespace id
	bpf_probe_read(&skc_net, sizeof(void *), ((char *) skp) + status->offset_netns);
	bpf_probe_read(&net_ns_inum, sizeof(net_ns_inum), ((char *) skc_net) + status->offset_ino);

	tuple->laddr = saddr;
	tuple->raddr = daddr;
	tuple->lport = sport;
	tuple->rport = dport;
	tuple->netns = net_ns_inum;

	// if addresses or ports are 0, ignore
	if (saddr == 0 || daddr == 0 || sport == 0 || dport == 0) {
		return 0;
	}

	return 1;
}

__attribute__((always_inline))
static int read_ipv6_tuple(struct ipv6_tuple_t *tuple, struct tcptracer_status_t *status, struct sock *skp) {
	u32 net_ns_inum;
	u16 sport, dport;
	u64 saddr_h, saddr_l, daddr_h, daddr_l;
	possible_net_t *skc_net;

	saddr_h = 0;
	saddr_l = 0;
	daddr_h = 0;
	daddr_l = 0;
	sport = 0;
	dport = 0;
	skc_net = NULL;
	net_ns_inum = 0;

	bpf_probe_read(&saddr_h, sizeof(saddr_h), ((char *) skp) + status->offset_daddr_ipv6 + 2 * sizeof(u64));
	bpf_probe_read(&saddr_l, sizeof(saddr_l), ((char *) skp) + status->offset_daddr_ipv6 + 3 * sizeof(u64));
	bpf_probe_read(&daddr_h, sizeof(daddr_h), ((char *) skp) + status->offset_daddr_ipv6);
	bpf_probe_read(&daddr_l, sizeof(daddr_l), ((char *) skp) + status->offset_daddr_ipv6 + sizeof(u64));
	bpf_probe_read(&sport, sizeof(sport), ((char *) skp) + status->offset_sport);
	bpf_probe_read(&dport, sizeof(dport), ((char *) skp) + status->offset_dport);
	// Get network namespace id
	bpf_probe_read(&skc_net, sizeof(void *), ((char *) skp) + status->offset_netns);
	bpf_probe_read(&net_ns_inum, sizeof(net_ns_inum), ((char *) skc_net) + status->offset_ino);

	tuple->laddr_h = saddr_h;
	tuple->laddr_l = saddr_l;
	tuple->raddr_h = daddr_h;
	tuple->raddr_l = daddr_l;
	tuple->lport = sport;
	tuple->rport = dport;
	tuple->netns = net_ns_inum;

	// if addresses or ports are 0, ignore
	if (!(saddr_h || saddr_l) || !(daddr_h || daddr_l) || sport == 0 || dport == 0) {
		return 0;
	}

	return 1;
}

static void update_conn_direction_state(struct conn_stats_t *stats, __u8 direction, __u8 state) {
	if (direction != DIRECTION_UNKNOWN) {
		(*stats).direction = direction;
	}

	if (stats->state == STATE_INITIALIZING && state == STATE_ACTIVE) {
		// We can move from initializing to active
		(*stats).state = STATE_ACTIVE;
	} else if (stats->state == STATE_ACTIVE && state == STATE_CLOSED) {
		// We can move from active to closed
		(*stats).state = STATE_ACTIVE_CLOSED;
	} else if (stats->state == STATE_INITIALIZING && state == STATE_CLOSED) {
		// We can move from initializing to closed
		// If we did not see any activity we report the connection as closed without activity, meaning we treat it as failed
		(*stats).state = STATE_CLOSED;
	}
}

/**
 * Assure a tcp record is created.
 *  - If the direction becomes known, updates the direction
 *  - If the state changes to closed, changes the state
 */
__attribute__((always_inline))
static int assert_tcp_record(struct sock *sk, struct tcptracer_status_t *status, __u8 direction, __u8 state) {
	struct conn_stats_t *val;

	u64 pid = bpf_get_current_pid_tgid();

	// If the tracer is not ready we don't assert the tcp record
	if (!is_tracer_status_ready(status)) {
		return 0;
	}

	if (check_family(sk, status, AF_INET)) {
		struct ipv4_tuple_t t = {};
		if (!read_ipv4_tuple(&t, status, sk)) {
			return 0;
		}

		t.pid = pid >> 32;
		t.lport = ntohs(t.lport); // Making ports human-readable
		t.rport = ntohs(t.rport);

		val = bpf_map_lookup_elem(&tcp_stats_ipv4, &t);
		if (val == NULL) {
			struct conn_stats_t s = {
				.send_bytes = 0,
				.recv_bytes = 0,
				.direction  = direction,
				.state = state
			};
			bpf_map_update_elem(&tcp_stats_ipv4, &t, &s, BPF_ANY);
		} else {
			update_conn_direction_state(val, direction, state);
		}
	} else if (check_family(sk, status, AF_INET6)) {
		struct ipv6_tuple_t t = {};
		if (!read_ipv6_tuple(&t, status, sk)) {
			return 0;
		}

		// IPv4 can be mapped as IPv6
		if (is_ipv4_mapped_ipv6(t.laddr_h, t.laddr_l, t.raddr_h, t.raddr_l)) {
			struct ipv4_tuple_t t2 = {
				t2.laddr = (u32)(t.laddr_l >> 32),
				t2.raddr = (u32)(t.raddr_l >> 32),
				t2.lport = ntohs(t.lport),
				t2.rport = ntohs(t.rport),
				t2.netns = t.netns,
				t2.pid = pid >> 32,
			};

			val = bpf_map_lookup_elem(&tcp_stats_ipv4, &t2);
			if (val == NULL) {
				struct conn_stats_t s = {
					.send_bytes = 0,
					.recv_bytes = 0,
					.direction  = direction,
					.state = state
				};
				bpf_map_update_elem(&tcp_stats_ipv4, &t2, &s, BPF_ANY);
			} else {
				update_conn_direction_state(val, direction, state);
			}
		} else {
			t.pid = pid >> 32;
			t.lport = ntohs(t.lport); // Making ports human-readable
			t.rport = ntohs(t.rport);

			val = bpf_map_lookup_elem(&tcp_stats_ipv6, &t);
			if (val == NULL) {
				struct conn_stats_t s = {
					.send_bytes = 0,
					.recv_bytes = 0,
					.direction  = direction,
					.state = state
				};
				bpf_map_update_elem(&tcp_stats_ipv6, &t, &s, BPF_ANY);
			} else {
				update_conn_direction_state(val, direction, state);
			}
		}
	}
	return 0;
}

/*
 * Will increment the tcp stats, only if the connection was already observed.
 */
__attribute__((always_inline))
static int increment_tcp_stats(struct sock *sk, struct tcptracer_status_t *status, size_t send_bytes, size_t recv_bytes) {
	// If no data went over the line, we do not treat this as an active connection
	if (send_bytes <= 0 && recv_bytes <= 0) {
		return 0;
	}

	// If the tracer is not ready we stop incrementing tcp stats
	if (!is_tracer_status_ready(status)) {
		return 0;
	}

	// Make sure the record exists, and checks if the network tracer is ready
	assert_tcp_record(sk, status, DIRECTION_UNKNOWN, STATE_ACTIVE);

	struct conn_stats_t *val;

	u64 pid = bpf_get_current_pid_tgid();

	if (check_family(sk, status, AF_INET)) {
		struct ipv4_tuple_t t = {};
		if (!read_ipv4_tuple(&t, status, sk)) {
			return 0;
		}

		t.pid = pid >> 32;
		t.lport = ntohs(t.lport); // Making ports human-readable
		t.rport = ntohs(t.rport);

		val = bpf_map_lookup_elem(&tcp_stats_ipv4, &t);
		if (val != NULL) {
			(*val).send_bytes += send_bytes;
			(*val).recv_bytes += recv_bytes;
		}
	} else if (check_family(sk, status, AF_INET6)) {
		struct ipv6_tuple_t t = {};
		if (!read_ipv6_tuple(&t, status, sk)) {
			return 0;
		}

		// IPv4 can be mapped as IPv6
		if (is_ipv4_mapped_ipv6(t.laddr_h, t.laddr_l, t.raddr_h, t.raddr_l)) {
			struct ipv4_tuple_t t2 = {
				t2.laddr = (u32)(t.laddr_l >> 32),
				t2.raddr = (u32)(t.raddr_l >> 32),
				t2.lport = ntohs(t.lport),
				t2.rport = ntohs(t.rport),
				t2.netns = t.netns,
				t2.pid = pid >> 32,
			};

			val = bpf_map_lookup_elem(&tcp_stats_ipv4, &t2);
			if (val != NULL) {
				(*val).send_bytes += send_bytes;
				(*val).recv_bytes += recv_bytes;
			}
		} else {
			t.pid = pid >> 32;
			t.lport = ntohs(t.lport); // Making ports human-readable
			t.rport = ntohs(t.rport);

			val = bpf_map_lookup_elem(&tcp_stats_ipv6, &t);
			if (val != NULL) {
				(*val).send_bytes += send_bytes;
				(*val).recv_bytes += recv_bytes;
			}
		}
	}
	return 0;
}

__attribute__((always_inline))
static int increment_udp_stats(struct sock *sk,
							   struct tcptracer_status_t *status,
							   u64 pid_tgid,
							   size_t send_bytes,
							   size_t recv_bytes) {
	struct conn_stats_ts_t *val;

	// If the network tracer is not ready we don't increment UDP stats
	if (!is_tracer_status_ready(status)) {
		return 0;
	}

	u64 zero = 0;
	u64 ts = bpf_ktime_get_ns();

	if (check_family(sk, status, AF_INET)) {
		struct ipv4_tuple_t t = {};
		if (!read_ipv4_tuple(&t, status, sk)) {
			return 0;
		}

		t.pid = pid_tgid >> 32;
		// Making ports human-readable
		t.lport = ntohs(t.lport);
		t.rport = ntohs(t.rport);

		val = bpf_map_lookup_elem(&udp_stats_ipv4, &t);
		// If already in our map, increment stats in-place
		if (val != NULL) {
			(*val).send_bytes += send_bytes;
			(*val).recv_bytes += recv_bytes;
			(*val).timestamp = ts;
		} else { // Otherwise add the (key, value) to the map
			struct conn_stats_ts_t s = {
				.send_bytes = send_bytes,
				.recv_bytes = recv_bytes,
				.timestamp = ts,
			};
			bpf_map_update_elem(&udp_stats_ipv4, &t, &s, BPF_ANY);
		}
	} else if (check_family(sk, status, AF_INET6)) {
		struct ipv6_tuple_t t = {};
		if (!read_ipv6_tuple(&t, status, sk)) {
			return 0;
		}

		// IPv4 can be mapped as IPv6
		if (is_ipv4_mapped_ipv6(t.laddr_h, t.laddr_l, t.raddr_h, t.raddr_l)) {
			struct ipv4_tuple_t t2 = {
				t2.laddr = (u32)(t.laddr_l >> 32),
				t2.raddr = (u32)(t.raddr_l >> 32),
				t2.lport = ntohs(t.lport),
				t2.rport = ntohs(t.rport),
				t2.netns = t.netns,
				t2.pid = pid_tgid >> 32,
			};

			val = bpf_map_lookup_elem(&udp_stats_ipv4, &t2);
			if (val != NULL) { // If already in our map, increment size in-place
				(*val).send_bytes += send_bytes;
				(*val).recv_bytes += recv_bytes;
			} else { // Otherwise add the key, value to the map
				struct conn_stats_ts_t s = {
					.send_bytes = send_bytes,
					.recv_bytes = recv_bytes,
					.timestamp = ts,
				};
				bpf_map_update_elem(&udp_stats_ipv4, &t2, &s, BPF_ANY);
			}
		} else { // It's IPv6
			t.pid = pid_tgid >> 32;
			t.lport = ntohs(t.lport); // Making ports human-readable
			t.rport = ntohs(t.rport);

			val = bpf_map_lookup_elem(&udp_stats_ipv6, &t);
			// If already in our map, increment size in-place
			if (val != NULL) {
				(*val).send_bytes += send_bytes;
				(*val).recv_bytes += recv_bytes;
				(*val).timestamp = ts;
			} else { // Otherwise add the key, value to the map
				struct conn_stats_ts_t s = {
					.send_bytes = send_bytes,
					.recv_bytes = recv_bytes,
					.timestamp = ts,
				};
				bpf_map_update_elem(&udp_stats_ipv6, &t, &s, BPF_ANY);
			}
		}
	}

	// Update latest timestamp that we've seen - for UDP connection expiration tracking
	bpf_map_update_elem(&latest_ts, &zero, &ts, BPF_ANY);

	return 0;
}

// Used for offset guessing (see: pkg/offsetguess.go)
SEC("kprobe/tcp_v4_connect")
int kprobe__tcp_v4_connect(struct pt_regs *ctx) {
	struct sock *sk;
	u64 pid = bpf_get_current_pid_tgid();

	sk = (struct sock *) PT_REGS_PARM1(ctx);

	bpf_map_update_elem(&connectsock_ipv4, &pid, &sk, BPF_ANY);

	return 0;
}

// Used for offset guessing (see: pkg/offsetguess.go)
SEC("kretprobe/tcp_v4_connect")
int kretprobe__tcp_v4_connect(struct pt_regs *ctx) {
	int ret = PT_REGS_RC(ctx);
	u64 pid = bpf_get_current_pid_tgid();
	struct sock **skpp;
	u64 zero = 0;
	struct tcptracer_status_t *status;

	skpp = bpf_map_lookup_elem(&connectsock_ipv4, &pid);
	if (skpp == 0) {
		return 0; // missed entry
	}

	struct sock *skp = *skpp;

	bpf_map_delete_elem(&connectsock_ipv4, &pid);

	if (ret != 0) {
		// failed to send SYNC packet, may not have populated
		// socket __sk_common.{skc_rcv_saddr, ...}
		return 0;
	}

	status = bpf_map_lookup_elem(&tcptracer_status, &zero);
	if (status == NULL || status->state == TCPTRACER_STATE_UNINITIALIZED) {
		return 0;
	}

	// We should figure out offsets if they're not already figured out
	update_tracer_offset_status_v4(status, skp, pid, __LINE__);

	return assert_tcp_record(skp, status, DIRECTION_OUTGOING, STATE_INITIALIZING);
}

// Used for offset guessing (see: pkg/offsetguess.go)
SEC("kprobe/tcp_v6_connect")
int kprobe__tcp_v6_connect(struct pt_regs *ctx) {
	struct sock *sk;
	u64 pid = bpf_get_current_pid_tgid();

	sk = (struct sock *) PT_REGS_PARM1(ctx);

	bpf_map_update_elem(&connectsock_ipv6, &pid, &sk, BPF_ANY);

	return 0;
}

// Used for offset guessing (see: pkg/offsetguess.go)
SEC("kretprobe/tcp_v6_connect")
int kretprobe__tcp_v6_connect(struct pt_regs *ctx) {
	int ret = PT_REGS_RC(ctx);
	u64 pid = bpf_get_current_pid_tgid();
	u64 zero = 0;
	struct sock **skpp;
	struct tcptracer_status_t *status;

	skpp = bpf_map_lookup_elem(&connectsock_ipv6, &pid);
	if (skpp == 0) {
		return 0; // missed entry
	}

	bpf_map_delete_elem(&connectsock_ipv6, &pid);

	struct sock *skp = *skpp;

	status = bpf_map_lookup_elem(&tcptracer_status, &zero);
	if (status == NULL || status->state == TCPTRACER_STATE_UNINITIALIZED) {
		return 0;
	}

	// We should figure out offsets if they're not already figured out
	update_tracer_offset_status_v6(status, skp, pid, __LINE__);

	if (ret != 0) {
		// failed to send SYNC packet, may not have populated
		// socket __sk_common.{skc_rcv_saddr, ...}
		return 0;
	}

	return assert_tcp_record(skp, status, DIRECTION_OUTGOING, STATE_INITIALIZING);
}

SEC("kretprobe/inet_csk_accept")
int kretprobe__inet_csk_accept(struct pt_regs *ctx)
{
	struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);

	if (newsk == NULL) {
		return 0;
	}

	u64 zero = 0;
	struct tcptracer_status_t *status = bpf_map_lookup_elem(&tcptracer_status, &zero);
	if (status == NULL || status->state == TCPTRACER_STATE_UNINITIALIZED) {
		return 0;
	}

	struct tracked_socket t = {.active = 1};
	t.prev_receive_time_ns = bpf_ktime_get_ns();

	bpf_map_update_elem(&tracked_sockets, &newsk, &t, BPF_ANY);

	return assert_tcp_record(newsk, status, DIRECTION_INCOMING, STATE_INITIALIZING);
}

__attribute__((always_inline))
bool parse_http_response(char *buffer, int size, int *status_code_result) {
	const char http_marker[4] = "HTTP";
	if (size > 11) {
		if (memcmp(buffer, http_marker, sizeof(http_marker)) == 0) {
	        int status_code = 100 * (buffer[9] - '0') + 10 * (buffer[10] - '0') + (buffer[11] - '0');
			if (status_code > 99 && status_code < 1000) {
				*status_code_result = status_code;
				return true;
			}
		}
	}
	return false;
}

__attribute__((always_inline))
bool parse_mysql_greeting(char *buffer, int size, u16 *protocol_version_result) {
	if (size > 4) {
		int packet_length = buffer[0] + buffer[1] * 0x100 + buffer[2] * 0x100;
		int packet_number = (int)buffer[3];

		bool is_greeting_packet = (size - 4) == packet_length && 0 == packet_number;
		if (is_greeting_packet) {
			u16 protocol_version = (u16)buffer[4];
			*protocol_version_result = protocol_version;
			return true;
		}
	}
	return false;
}

#define send_mysql_greeting(_ctx, _re, _protocol_version, _timestamp, _cpu)           \
	({                                                                                  \
		struct event_mysql_greeting greeting;                                             \
		__builtin_memset(&greeting, 0, sizeof(greeting));                                 \
		greeting.protocol_version = _protocol_version;                                    \
		union event_payload payload;                                                      \
		__builtin_memset(&payload, 0, sizeof(payload));                                   \
		payload.mysql_greeting = greeting;                                                \
		_re.event_type = EVENT_MYSQL_GREETING;                                            \
		_re.timestamp = _timestamp;                                                       \
		_re.payload = payload;                                                            \
		bpf_perf_event_output(ctx, &perf_events, _cpu, &_re, sizeof(struct perf_event));  \
	})

#define send_http_response(_ctx, _re, _http_status_code, _response_time, _timestamp, _cpu)   \
	({                                                                                         \
		struct event_http_response http_response;                                                \
		__builtin_memset(&http_response, 0, sizeof(http_response));                               \
		http_response.status_code = _http_status_code;                                            \
		http_response.response_time = _response_time;                                             \
		union event_payload payload;                                                              \
		__builtin_memset(&payload, 0, sizeof(payload));                                           \
		payload.http_response = http_response;                                                    \
		_re.event_type = EVENT_HTTP_RESPONSE;                                                     \
		_re.timestamp = _timestamp;                                                               \
		_re.payload = payload;                                                                    \
		bpf_perf_event_output(_ctx, &perf_events, _cpu, &_re, sizeof(struct perf_event));         \
	})

__attribute__((always_inline))
bool is_ipv4(struct sock *sk, struct tcptracer_status_t *status) {
    if (!check_family(sk, status, AF_INET)) {
        return false;
    }
    return true;
}

__attribute__((always_inline))
bool is_ipv6(struct sock *sk, struct tcptracer_status_t *status) {
    if (!check_family(sk, status, AF_INET6)) {
        return false;
    }
    return true;
}

__attribute__((always_inline))
bool is_v4_or_v6(struct sock *sk, struct tcptracer_status_t *status) {
    if (!is_ipv4(sk, status) &&
        !is_ipv6(sk, status)) {
        return false;
    }
    return true;
}

__attribute__((always_inline))
void get_ip_v4_tuple(struct ipv4_tuple_t *t, struct sock *sk, struct tcptracer_status_t *status) {
    if (!read_ipv4_tuple(t, status, sk)) {
        t = NULL;
        return;
    }
    u64 pid = bpf_get_current_pid_tgid();
    t->lport = ntohs(t->lport);
    t->rport = ntohs(t->rport);
    t->pid = pid >> 32;
}

__attribute__((always_inline))
void get_ip_v6_tuple(struct ipv6_tuple_t *t, struct sock *sk, struct tcptracer_status_t *status) {
    if (!read_ipv6_tuple(t, status, sk)) {
        t = NULL;
        return;
    }
    u64 pid = bpf_get_current_pid_tgid();
    t->lport = ntohs(t->lport);
    t->rport = ntohs(t->rport);
    t->pid = pid >> 32;
}

__attribute__((always_inline))
static int tcp_send(struct pt_regs *ctx, const size_t size) {

	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	struct msghdr *k_msg = (void *)PT_REGS_PARM2(ctx);
	u64 zero = 0;

	struct tcptracer_status_t *status = bpf_map_lookup_elem(&tcptracer_status, &zero);
	if (status == NULL || status->state == TCPTRACER_STATE_UNINITIALIZED) {
		return 0;
	}
    if(!is_v4_or_v6(sk, status)){
        return 0;
    }

    if (status->protocol_inspection_enabled) {
        struct msghdr msg = {};
        bpf_probe_read(&msg, sizeof(msg), k_msg);

        if ((msg.msg_iter.type & ~(READ | WRITE)) == status->iter_type) {
            char *data = bpf_map_lookup_elem(&write_buffer_heap, &zero);
            if (data != NULL) {
                struct iovec iov = {};
                bpf_probe_read(&iov, sizeof(iov), (void *)msg.msg_iter.iov);
                bpf_probe_read(data, MAX_MSG_SIZE, iov.iov_base);

                struct ipv4_tuple_t t = {};
                struct ipv6_tuple_t t6 = {};

                struct tracked_socket *res = bpf_map_lookup_elem(&tracked_sockets, &sk);
                u64 current_time = bpf_ktime_get_ns();
                u64 ttfb = 0;
                if (res != NULL) {
                    ttfb = current_time - res->prev_receive_time_ns;
                }
                u64 cpu = bpf_get_smp_processor_id();
                int http_status_code = 0;
                u16 mysql_greeting_protocol_version = 0;
                struct perf_event response_event;
                memset(&response_event, 0, sizeof(response_event));
                if(is_ipv4(sk, status)) {
                    get_ip_v4_tuple(&t, sk, status);
                    response_event.connection.ipv4_connection = t;
                    response_event.ip_protocol_version = IPV4;
                    if (parse_http_response(data, iov.iov_len, &http_status_code)) {
                        send_http_response(ctx, response_event, http_status_code, ttfb / 1000, current_time, cpu);
                    } else if (parse_mysql_greeting(data, iov.iov_len, &mysql_greeting_protocol_version)) {
                    	send_mysql_greeting(ctx, response_event, mysql_greeting_protocol_version, current_time, cpu);
                    }
                } else {
                    get_ip_v6_tuple(&t6, sk, status);
                    response_event.connection.ipv6_connection = t6;
                    response_event.ip_protocol_version = IPV6;
                    if (parse_http_response(data, iov.iov_len, &http_status_code)) {
                        send_http_response(ctx, response_event, http_status_code, ttfb / 1000, current_time, cpu);
                    } else if (parse_mysql_greeting(data, iov.iov_len, &mysql_greeting_protocol_version)) {
                        send_mysql_greeting(ctx, response_event, mysql_greeting_protocol_version, current_time, cpu);
                    }
                }
            }
        }
	}

	return increment_tcp_stats(sk, status, size, 0);
}

SEC("kprobe/tcp_sendmsg")
int kprobe__tcp_sendmsg(struct pt_regs *ctx) {
	const size_t size = (size_t)PT_REGS_PARM3(ctx);

	return tcp_send(ctx, size);
}

SEC("kprobe/tcp_sendpage")
int kprobe__tcp_sendpage(struct pt_regs *ctx) {
	size_t size = (size_t)PT_REGS_PARM4(ctx);

	return tcp_send(ctx, size);
}

SEC("kprobe/skb_copy_datagram_iter")
int kprobe__skb_copy_datagram_iter(struct pt_regs *ctx) {
    struct sk_buff * skbp = (struct sk_buff *) PT_REGS_PARM1(ctx);
    struct sock *sk = 0;
    bpf_probe_read(&sk, sizeof(sk), &(skbp->sk));
    struct tracked_socket tsock = {};
    tsock.active = 1;
    tsock.prev_receive_time_ns = bpf_ktime_get_ns();
    bpf_map_update_elem(&tracked_sockets, &sk, &tsock, BPF_ANY);
    return 0;
}

SEC("kprobe/tcp_cleanup_rbuf")
int kprobe__tcp_cleanup_rbuf(struct pt_regs *ctx) {
	struct sock *sk = (struct sock *) PT_REGS_PARM1(ctx);
	int copied = (int) PT_REGS_PARM2(ctx);
	if (copied < 0) {
		return 0;
	}
	u64 zero = 0;

	struct tcptracer_status_t *status = bpf_map_lookup_elem(&tcptracer_status, &zero);
	if (status == NULL || status->state == TCPTRACER_STATE_UNINITIALIZED) {
		return 0;
	}

	return increment_tcp_stats(sk, status, 0, copied);
}

SEC("kprobe/tcp_close")
int kprobe__tcp_close(struct pt_regs *ctx) {
	struct sock *sk = (struct sock *) PT_REGS_PARM1(ctx);
	struct tcptracer_status_t *status;
	u64 zero = 0;

	bpf_map_delete_elem(&tracked_sockets, &sk);

	status = bpf_map_lookup_elem(&tcptracer_status, &zero);
	if (status == NULL || status->state != TCPTRACER_STATE_READY) {
		return 0;
	}

	return assert_tcp_record(sk, status, DIRECTION_UNKNOWN, STATE_CLOSED);
}

SEC("kprobe/udp_sendmsg")
int kprobe__udp_sendmsg(struct pt_regs *ctx) {
	struct sock *sk = (struct sock *) PT_REGS_PARM1(ctx);
	size_t size = (size_t) PT_REGS_PARM3(ctx);
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u64 zero = 0;

	struct tcptracer_status_t *status = bpf_map_lookup_elem(&tcptracer_status, &zero);
	if (status == NULL || status->state == TCPTRACER_STATE_UNINITIALIZED) {
		return 0;
	}

	increment_udp_stats(sk, status, pid_tgid, size, 0);

	return 0;
}

// We can only get the accurate number of copied bytes from the return value, so we pass our
// sock* pointer from the kprobe to the kretprobe via a map (udp_recv_sock) to get all required info
//
// The same issue exists for TCP, but we can conveniently use the downstream function tcp_cleanup_rbuf
//
// On UDP side, no similar function exists in all kernel versions, though we may be able to use something like
// skb_consume_udp (v4.10+, https://elixir.bootlin.com/linux/v4.10/source/net/ipv4/udp.c#L1500)
SEC("kprobe/udp_recvmsg")
int kprobe__udp_recvmsg(struct pt_regs *ctx) {
	struct sock *sk = (struct sock *) PT_REGS_PARM1(ctx);
	u64 pid_tgid = bpf_get_current_pid_tgid();

	// Store pointer to the socket using the pid/tgid
	bpf_map_update_elem(&udp_recv_sock, &pid_tgid, &sk, BPF_ANY);

	return 0;
}

SEC("kretprobe/udp_recvmsg")
int kretprobe__udp_recvmsg(struct pt_regs *ctx) {
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u64 zero = 0;

	// Retrieve socket pointer from kprobe via pid/tgid
	struct sock **skpp = bpf_map_lookup_elem(&udp_recv_sock, &pid_tgid);
	if (skpp == 0) { // Missed entry
		return 0;
	}
	struct sock *sk = *skpp;

	// Make sure we clean up that pointer reference
	bpf_map_delete_elem(&udp_recv_sock, &pid_tgid);

	int copied = (int) PT_REGS_RC(ctx);
	if (copied < 0) { // Non-zero values are errors (e.g -EINVAL)
		return 0;
	}

	struct tcptracer_status_t *status = bpf_map_lookup_elem(&tcptracer_status, &zero);
	if (status == NULL || status->state == TCPTRACER_STATE_UNINITIALIZED) {
		return 0;
	}

	increment_udp_stats(sk, status, pid_tgid, 0, copied);

	return 0;
}

// This number will be interpreted by gobpf-elf-loader to set the current running kernel version
__u32 _version SEC("version") = 0xFFFFFFFE;

char _license[] SEC("license") = "GPL";
