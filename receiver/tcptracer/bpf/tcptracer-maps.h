#ifndef TCPTRACER_BPF_TCPTRACER_MAPS_H
#define TCPTRACER_BPF_TCPTRACER_MAPS_H

#include "tcptracer-bpf.h"

#define MAX_MSG_SIZE 1024

// BPF programs are limited to a 512-byte stack. We store this value per CPU
// and use it as a heap allocated value.

struct bpf_map_def SEC("maps/write_buffer_heap") write_buffer_heap = {
        .type = BPF_MAP_TYPE_PERCPU_ARRAY,
        .key_size = sizeof(int),
        .value_size = sizeof(char[MAX_MSG_SIZE]),
        .max_entries = 1,
        .pinning = 0,
        .namespace = "",
};

// The set of file descriptors we are tracking.
struct bpf_map_def SEC("maps/tracked_sockets") tracked_sockets = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(int),
        .value_size = sizeof(struct tracked_socket),
        .max_entries = 10240,
        .pinning = 0,
        .namespace = "",
};

struct bpf_map_def SEC("maps/tcptracer_status") tcptracer_status = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(__u64),
        .value_size = sizeof(struct tcptracer_status_t),
        .max_entries = 1,
        .pinning = 0,
        .namespace = "",
};

// Keeping track of latest timestamp of monotonic clock
struct bpf_map_def SEC("maps/latest_ts") latest_ts = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(__u64),
        .value_size = sizeof(__u64),
        .max_entries = 1,
        .pinning = 0,
        .namespace = "",
};

/* This is a key/value store with the keys being an ipv4_tuple_t for send & recv calls
 * and the values being the struct conn_stats_ts_t *.
 */
struct bpf_map_def SEC("maps/udp_stats_ipv4") udp_stats_ipv4 = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(struct ipv4_tuple_t),
        .value_size = sizeof(struct conn_stats_ts_t),
        .max_entries = 32768,
        .pinning = 0,
        .namespace = "",
};

/* This is a key/value store with the keys being an ipv4_tuple_t for send & recv calls
 * and the values being the struct conn_stats_ts_t *.
 */
struct bpf_map_def SEC("maps/udp_stats_ipv6") udp_stats_ipv6 = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(struct ipv6_tuple_t),
        .value_size = sizeof(struct conn_stats_ts_t),
        .max_entries = 32768,
        .pinning = 0,
        .namespace = "",
};

/* This is a queue for events related to connections. Values are of struct perf_event.
 */
struct bpf_map_def SEC("maps/perf_events") perf_events = {
        .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
        .key_size = sizeof(int),
        .value_size = sizeof(__u32),
        .max_entries = 1024,
        .pinning = 0,
};

/* This is a key/value store with the keys being an ipv4_tuple_t for send & recv calls
 * and the values being the struct conn_stats_t *.
 */
struct bpf_map_def SEC("maps/tcp_stats_ipv4") tcp_stats_ipv4 = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(struct ipv4_tuple_t),
        .value_size = sizeof(struct conn_stats_t),
        .max_entries = 32768,
        .pinning = 0,
        .namespace = "",
};

/* This is a key/value store with the keys being an ipv6_tuple_t for send & recv calls
 * and the values being the struct conn_stats_t *.
 */
struct bpf_map_def SEC("maps/tcp_stats_ipv6") tcp_stats_ipv6 = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(struct ipv6_tuple_t),
        .value_size = sizeof(struct conn_stats_t),
        .max_entries = 32768,
        .pinning = 0,
        .namespace = "",
};

/* These maps are used to match the kprobe & kretprobe of connect for IPv4 */
/* This is a key/value store with the keys being a pid
 * and the values being a struct sock *.
 */
struct bpf_map_def SEC("maps/connectsock_ipv4") connectsock_ipv4 = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(__u64),
        .value_size = sizeof(void *),
        .max_entries = 1024,
        .pinning = 0,
        .namespace = "",
};

/* These maps are used to match the kprobe & kretprobe of connect for IPv6 */
/* This is a key/value store with the keys being a pid
 * and the values being a struct sock *.
 */
struct bpf_map_def SEC("maps/connectsock_ipv6") connectsock_ipv6 = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(__u64),
        .value_size = sizeof(void *),
        .max_entries = 1024,
        .pinning = 0,
        .namespace = "",
};

/* This map is used to match the kprobe & kretprobe of udp_recvmsg */
/* This is a key/value store with the keys being a pid
 * and the values being a struct sock *.
 */
struct bpf_map_def SEC("maps/udp_recv_sock") udp_recv_sock = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(__u64),
        .value_size = sizeof(void *),
        .max_entries = 1024,
        .pinning = 0,
        .namespace = "",
};

#endif //TCPTRACER_BPF_TCPTRACER_MAPS_H
