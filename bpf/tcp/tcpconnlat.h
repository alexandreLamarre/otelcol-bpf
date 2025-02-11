#ifndef __TCPCONNLAT_H
#define __TCPCONNLAT_H

#define TASK_COMM_LEN	16

struct event {
	__u32 saddr_v4;
	__u8 saddr_v6[16];
	__u32 daddr_v4;
	__u8 daddr_v6[16];
	char comm[TASK_COMM_LEN];
	__u64 delta_us;
	__u64 ts_us;
	__u32 tgid;
	int af;
	__u16 lport;
	__u16 dport;
};

struct traffic_key {
	__u32 saddr_v4;
	__u8 saddr_v6[16];
	__u32 daddr_v4;
	__u8 daddr_v6[16];
	__u32 pid;
	char name[TASK_COMM_LEN];
	__u16 lport;
	__u16 dport;
	__u16 family;
};

struct traffic_value {
	size_t rx;
	size_t tx;
};

#endif /* __TCPCONNLAT_H_ */
