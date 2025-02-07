//go:build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "procexec.h"

static const struct event empty_event = {};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, pid_t);
    __type(value, struct event);
} execs SEC(".maps");


struct{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");


SEC("tracepoint/sched:sched_process_exec")
int sched_sched_process_exec(struct syscall_trace_enter *ctx) {
    // variable declarations
    struct event *event;
    struct task_struct *task;
    u64 id;
    pid_t pid, tgid;
    u64 start_time; 
    // end : variable declarations
     uid_t uid = (u32)bpf_get_current_uid_gid();

    id = bpf_get_current_pid_tgid();
    pid = (pid_t)id;
    tgid = id >> 32;

    // add pid to exec map
    if (bpf_map_update_elem(&execs, &pid, &empty_event, BPF_NOEXIST)) {
        return 0;
    }
    bpf_printk("pid : %d", pid);

    event = bpf_map_lookup_elem(&execs, &pid);
    if (!event) {
        return 0;
    }
    event->pid = tgid;
    event->uid = uid;
    task = (struct task_struct*)bpf_get_current_task();
    // checks task ppid
    event-> ppid = (pid_t)BPF_CORE_READ(task, real_parent, tgid);
    event-> args_count = 0;
    event-> args_size = 0;


    start_time = bpf_ktime_get_ns();
    event->start_time = start_time;
    
    // write a string termination to prevent unexpected EOF
    event->args[0] = '\0';
    return 0;
}


SEC("tracepoint/sched:sched_process_exit")
int sched_sched_process_exit(struct syscall_trace_enter *ctx) {
     // variable declarations
    u64 id;
    pid_t pid;
    struct event *event;
    int ret;
    u64 end_time;
    // end: variable declarations

    end_time = bpf_ktime_get_ns();
    u32 uid = (u32)bpf_get_current_uid_gid();
    id = bpf_get_current_pid_tgid();
    pid = (pid_t)id;

    event = bpf_map_lookup_elem(&execs, &pid);
    if (!event) {
        return 0;
    } 
    event->elapsed = end_time - event->start_time;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    size_t len = EVENT_SIZE(event);
	if (len <= sizeof(*event))
		bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, len);

    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";