#ifndef __TCPTRACER_BPF_H
#define __TCPTRACER_BPF_H

#include <linux/types.h>

enum guesses {
    GUESS_SADDR = 0,
    GUESS_DADDR,
    GUESS_FAMILY,
    GUESS_SPORT,
    GUESS_DPORT,
    GUESS_NETNS,
    GUESS_DADDR_IPV6,
    GUESS_MAX
};

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

enum directions {
    DIRECTION_UNKNOWN = 0,
    DIRECTION_OUTGOING,
    DIRECTION_INCOMING,
    DIRECTION_MAX
};

// We observed the connection being initialized
#define STATE_INITIALIZING 0
// We observed the connection being active
#define STATE_ACTIVE 1
// We observed the connection being active and then closed
#define STATE_ACTIVE_CLOSED 2
// We just observed the closing of the connection. We did not see any activity, so we treat this as a failed connection
// It is still reported to be able to close connections coming from /proc
#define STATE_CLOSED 3

struct proc_t {
    char comm[TASK_COMM_LEN];
};

struct conn_stats_t {
	__u64 send_bytes;
	__u64 recv_bytes;
	// These are big to have a 64 bit aligned struct
	__u32 direction;
	// Was the connection active or closed?
	__u32 state;
};

struct conn_stats_ts_t {
	__u64 send_bytes;
	__u64 recv_bytes;
	__u64 timestamp;
};

// tcp_set_state doesn't run in the context of the process that initiated the
// connection so we need to store a map TUPLE -> PID to send the right PID on
// the event
struct ipv4_tuple_t {
	__u32 laddr;
	__u32 raddr;
	__u16 lport;
	__u16 rport;
	__u32 netns;
	__u32 pid;
};

struct ipv6_tuple_t {
	/* Using the type unsigned __int128 generates an error in the ebpf verifier */
	__u64 laddr_h;
	__u64 laddr_l;
	__u64 raddr_h;
	__u64 raddr_l;
	__u16 lport;
	__u16 rport;
	__u32 netns;
	__u32 pid;
};

struct tracked_socket {
    __u16 active;
    __u64 prev_receive_time_ns;
};

enum event_types {
    EVENT_HTTP_RESPONSE = 1,
    EVENT_MYSQL_GREETING,
    EVENT_TYPES_MAX
};

enum ip_protocol_versions {
    IPV4 = 1,
    IPV6,
    IP_PROTOCOL_VERSIONS_MAX
};

union connections {
    struct ipv4_tuple_t ipv4_connection;
    struct ipv6_tuple_t ipv6_connection;
};

struct event_http_response {
    __u16 status_code;
    __u32 response_time;
};

struct event_mysql_greeting {
    __u16 protocol_version;
};

union event_payload
{
	struct event_http_response http_response;
	struct event_mysql_greeting mysql_greeting;
};

struct perf_event
{
	__u16 event_type;
	__u64 timestamp;
	__u16 ip_protocol_version;
	union event_payload payload;
	union connections connection;
};

#define TCPTRACER_STATE_UNINITIALIZED 0
#define TCPTRACER_STATE_CHECKING      1
#define TCPTRACER_STATE_CHECKED       2
#define TCPTRACER_STATE_READY         3

struct tcptracer_status_t {
	__u16 protocol_inspection_enabled;
	__u64 state;

	/* checking */
	struct proc_t proc;
	__u64 what;
	__u64 offset_saddr;
	__u64 offset_daddr;
	__u64 offset_sport;
	__u64 offset_dport;
	__u64 offset_netns;
	__u64 offset_ino;
	__u64 offset_family;
	__u64 offset_daddr_ipv6;

	__u64 err;

	__u32 daddr_ipv6[4];
	__u32 netns;
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u16 padding;

	__u64 calling_probes[10];
	__u16 iter_type;
};

#endif
