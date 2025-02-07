#ifndef __EXECSNOOP_H
#define __EXECSNOOP_H

#include "vmlinux.h"

#define ARGSIZE  128
#define TASK_COMM_LEN 16
#define TOTAL_MAX_ARGS 60
#define FULL_MAX_ARGS_ARR (TOTAL_MAX_ARGS * ARGSIZE)
#define BASE_EVENT_SIZE (size_t)(&((struct event*)0)->args)
#define EVENT_SIZE(e) (BASE_EVENT_SIZE + e->args_size)

struct event
{
    pid_t pid;
    pid_t ppid;
    uid_t uid;
    int retval;
    int args_count;
    unsigned int args_size;
    u64 start_time;
    u64 elapsed;
    char comm[TASK_COMM_LEN];
    char args[FULL_MAX_ARGS_ARR];
};


#endif /* __EXECSNOOP_H */