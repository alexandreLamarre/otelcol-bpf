#ifndef __BPF_HELPERS_H
#define __BPF_HELPERS_H

/* helper macro to place programs, maps, license in
 * different sections in elf_bpf file. Section names
 * are interpreted by elf_bpf loader
 */
#define SEC(NAME) __attribute__((section(NAME), used))

// Table for reading hw perf cpu counters
#define BPF_PERF_ARRAY(_name, _max_entries)      \
	struct _name##_table_t                         \
	{                                              \
		int key;                                     \
		u32 leaf;                                    \
		/* counter = map.perf_read(index) */         \
		u64 (*perf_read)(int);                       \
		int (*perf_counter_value)(int, void *, u32); \
		u32 max_entries;                             \
	};                                             \
	__attribute__((section("maps/perf_array"))) struct _name##_table_t _name = {.max_entries = (_max_entries)}
// Table for cgroup file descriptors
#define BPF_CGROUP_ARRAY(_name, _max_entries) \
	struct _name##_table_t                      \
	{                                           \
		int key;                                  \
		u32 leaf;                                 \
		int (*check_current_task)(int);           \
		u32 max_entries;                          \
	};                                          \
	__attribute__((section("maps/cgroup_array"))) struct _name##_table_t _name = {.max_entries = (_max_entries)}
#define BPF_HASH1(_name) \
	BPF_TABLE("hash", u64, u64, _name, 10240)
#define BPF_HASH2(_name, _key_type) \
	BPF_TABLE("hash", _key_type, u64, _name, 10240)
#define BPF_HASH3(_name, _key_type, _leaf_type) \
	BPF_TABLE("hash", _key_type, _leaf_type, _name, 10240)
#define BPF_HASH4(_name, _key_type, _leaf_type, _size) \
	BPF_TABLE("hash", _key_type, _leaf_type, _name, _size)
// helper for default-variable macro function
#define BPF_HASHX(_1, _2, _3, _4, NAME, ...) NAME
// Define a hash function, some arguments optional
// BPF_HASH(name, key_type=u64, leaf_type=u64, size=10240)
#define BPF_HASH(...)                                                \
	BPF_HASHX(__VA_ARGS__, BPF_HASH4, BPF_HASH3, BPF_HASH2, BPF_HASH1) \
	(__VA_ARGS__)
#define BPF_ARRAY1(_name) \
	BPF_TABLE("array", int, u64, _name, 10240)
#define BPF_ARRAY2(_name, _leaf_type) \
	BPF_TABLE("array", int, _leaf_type, _name, 10240)
#define BPF_ARRAY3(_name, _leaf_type, _size) \
	BPF_TABLE("array", int, _leaf_type, _name, _size)
// helper for default-variable macro function
#define BPF_ARRAYX(_1, _2, _3, NAME, ...) NAME
// Define an array function, some arguments optional
// BPF_ARRAY(name, leaf_type=u64, size=10240)
#define BPF_ARRAY(...)                                        \
	BPF_ARRAYX(__VA_ARGS__, BPF_ARRAY3, BPF_ARRAY2, BPF_ARRAY1) \
	(__VA_ARGS__)
#define BPF_PERCPU_ARRAY1(_name) \
	BPF_TABLE("percpu_array", int, u64, _name, 10240)
#define BPF_PERCPU_ARRAY2(_name, _leaf_type) \
	BPF_TABLE("percpu_array", int, _leaf_type, _name, 10240)
#define BPF_PERCPU_ARRAY3(_name, _leaf_type, _size) \
	BPF_TABLE("percpu_array", int, _leaf_type, _name, _size)
// helper for default-variable macro function
#define BPF_PERCPU_ARRAYX(_1, _2, _3, NAME, ...) NAME
// Define an array function (per CPU), some arguments optional
// BPF_PERCPU_ARRAY(name, leaf_type=u64, size=10240)
#define BPF_PERCPU_ARRAY(...)                                               \
	BPF_PERCPU_ARRAYX(                                                        \
			__VA_ARGS__, BPF_PERCPU_ARRAY3, BPF_PERCPU_ARRAY2, BPF_PERCPU_ARRAY1) \
	(__VA_ARGS__)

/* helper functions called from eBPF programs written in C */
static void *(*bpf_map_lookup_elem)(void *map, void *key) =
	(void *) BPF_FUNC_map_lookup_elem;
static int (*bpf_map_update_elem)(void *map, void *key, void *value,
				  unsigned long long flags) =
	(void *) BPF_FUNC_map_update_elem;
static int (*bpf_map_delete_elem)(void *map, void *key) =
	(void *) BPF_FUNC_map_delete_elem;
static int (*bpf_probe_read)(void *dst, int size, void *unsafe_ptr) =
	(void *) BPF_FUNC_probe_read;
static unsigned long long (*bpf_ktime_get_ns)(void) =
	(void *) BPF_FUNC_ktime_get_ns;
static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) =
	(void *) BPF_FUNC_trace_printk;
static unsigned long long (*bpf_get_smp_processor_id)(void) =
	(void *) BPF_FUNC_get_smp_processor_id;
static unsigned long long (*bpf_get_current_pid_tgid)(void) =
	(void *) BPF_FUNC_get_current_pid_tgid;
static unsigned long long (*bpf_get_current_uid_gid)(void) =
	(void *) BPF_FUNC_get_current_uid_gid;
static int (*bpf_get_current_comm)(void *buf, int buf_size) =
	(void *) BPF_FUNC_get_current_comm;
static int (*bpf_perf_event_read)(void *map, int index) =
	(void *) BPF_FUNC_perf_event_read;
static int (*bpf_clone_redirect)(void *ctx, int ifindex, int flags) =
	(void *) BPF_FUNC_clone_redirect;
static int (*bpf_redirect)(int ifindex, int flags) =
	(void *) BPF_FUNC_redirect;
static int (*bpf_perf_event_output)(void *ctx, void *map,
				    unsigned long long flags, void *data,
				    int size) =
	(void *) BPF_FUNC_perf_event_output;
static int (*bpf_skb_get_tunnel_key)(void *ctx, void *key, int size, int flags) =
	(void *) BPF_FUNC_skb_get_tunnel_key;
static int (*bpf_skb_set_tunnel_key)(void *ctx, void *key, int size, int flags) =
	(void *) BPF_FUNC_skb_set_tunnel_key;
static unsigned long long (*bpf_get_prandom_u32)(void) =
	(void *) BPF_FUNC_get_prandom_u32;

/* llvm builtin functions that eBPF C program may use to
 * emit BPF_LD_ABS and BPF_LD_IND instructions
 */
unsigned long long load_byte(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.byte");
unsigned long long load_half(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.half");
unsigned long long load_word(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.word");

/* a helper structure used by eBPF C program
 * to describe map attributes to elf_bpf loader
 */
#define BUF_SIZE_MAP_NS 256

struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
	unsigned int pinning;
	char namespace[BUF_SIZE_MAP_NS];
};

static int (*bpf_skb_store_bytes)(void *ctx, int off, void *from, int len, int flags) =
	(void *) BPF_FUNC_skb_store_bytes;
static int (*bpf_l3_csum_replace)(void *ctx, int off, int from, int to, int flags) =
	(void *) BPF_FUNC_l3_csum_replace;
static int (*bpf_l4_csum_replace)(void *ctx, int off, int from, int to, int flags) =
	(void *) BPF_FUNC_l4_csum_replace;

#if defined(__x86_64__)

#define PT_REGS_PARM1(x) ((x)->di)
#define PT_REGS_PARM2(x) ((x)->si)
#define PT_REGS_PARM3(x) ((x)->dx)
#define PT_REGS_PARM4(x) ((x)->cx)
#define PT_REGS_PARM5(x) ((x)->r8)
#define PT_REGS_RET(x) ((x)->sp)
#define PT_REGS_FP(x) ((x)->bp)
#define PT_REGS_RC(x) ((x)->ax)
#define PT_REGS_SP(x) ((x)->sp)
#define PT_REGS_IP(x) ((x)->ip)

#elif defined(__s390x__)

#define PT_REGS_PARM1(x) ((x)->gprs[2])
#define PT_REGS_PARM2(x) ((x)->gprs[3])
#define PT_REGS_PARM3(x) ((x)->gprs[4])
#define PT_REGS_PARM4(x) ((x)->gprs[5])
#define PT_REGS_PARM5(x) ((x)->gprs[6])
#define PT_REGS_RET(x) ((x)->gprs[14])
#define PT_REGS_FP(x) ((x)->gprs[11]) /* Works only with CONFIG_FRAME_POINTER */
#define PT_REGS_RC(x) ((x)->gprs[2])
#define PT_REGS_SP(x) ((x)->gprs[15])
#define PT_REGS_IP(x) ((x)->ip)

#elif defined(__aarch64__)

#define PT_REGS_PARM1(x) ((x)->regs[0])
#define PT_REGS_PARM2(x) ((x)->regs[1])
#define PT_REGS_PARM3(x) ((x)->regs[2])
#define PT_REGS_PARM4(x) ((x)->regs[3])
#define PT_REGS_PARM5(x) ((x)->regs[4])
#define PT_REGS_RET(x) ((x)->regs[30])
#define PT_REGS_FP(x) ((x)->regs[29]) /* Works only with CONFIG_FRAME_POINTER */
#define PT_REGS_RC(x) ((x)->regs[0])
#define PT_REGS_SP(x) ((x)->sp)
#define PT_REGS_IP(x) ((x)->pc)

#elif defined(__powerpc__)

#define PT_REGS_PARM1(x) ((x)->gpr[3])
#define PT_REGS_PARM2(x) ((x)->gpr[4])
#define PT_REGS_PARM3(x) ((x)->gpr[5])
#define PT_REGS_PARM4(x) ((x)->gpr[6])
#define PT_REGS_PARM5(x) ((x)->gpr[7])
#define PT_REGS_RC(x) ((x)->gpr[3])
#define PT_REGS_SP(x) ((x)->sp)
#define PT_REGS_IP(x) ((x)->nip)

#endif

#ifdef __powerpc__
#define BPF_KPROBE_READ_RET_IP(ip, ctx)		({ (ip) = (ctx)->link; })
#define BPF_KRETPROBE_READ_RET_IP		BPF_KPROBE_READ_RET_IP
#else
#define BPF_KPROBE_READ_RET_IP(ip, ctx)		({				\
		bpf_probe_read(&(ip), sizeof(ip), (void *)PT_REGS_RET(ctx)); })
#define BPF_KRETPROBE_READ_RET_IP(ip, ctx)	({				\
		bpf_probe_read(&(ip), sizeof(ip),				\
				(void *)(PT_REGS_FP(ctx) + sizeof(ip))); })
#endif

#endif
