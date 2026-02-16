// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* EDR eBPF: network - connect, sendto, accept. Use tracepoint (stable) + kprobe fallback. */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define AF_INET  2
#define AF_INET6 10

struct network_event_t {
	__u8  type;
	__u8  family;
	__u16 dport;
	__u32 pid;
	__u32 tid;
	__u32 uid;
	__u32 saddr_v4;
	__u32 daddr_v4;
	__u8  daddr_v6[16];
	char  comm[TASK_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 64 * 4096);
} network_events SEC(".maps");

/* Tracepoint context: sys_enter_* has common (16) + id (8) + args[6] (48) */
struct sys_enter_ctx {
	__u64 _pad[2];   /* common_type, common_flags, common_preempt_count, common_pid */
	long id;
	unsigned long args[6];
};

static __always_inline void* arg1(struct pt_regs *ctx) { return (void *)PT_REGS_PARM1(ctx); }
static __always_inline void* arg2(struct pt_regs *ctx) { return (void *)PT_REGS_PARM2(ctx); }
static __always_inline void* arg5(struct pt_regs *ctx) { return (void *)PT_REGS_PARM5(ctx); }

/* Read sockaddr from user and fill event. Returns 1 on success. */
static __always_inline int read_sockaddr(void *addr_ptr, struct network_event_t *e)
{
	__u16 family;
	if (bpf_probe_read_user(&family, sizeof(family), addr_ptr) != 0)
		return 0;
	if (family == AF_INET) {
		/* struct sockaddr_in: family, port, addr */
		__u16 port;
		__u32 addr;
		if (bpf_probe_read_user(&port, sizeof(port), (char *)addr_ptr + 2) != 0)
			return 0;
		if (bpf_probe_read_user(&addr, sizeof(addr), (char *)addr_ptr + 4) != 0)
			return 0;
		e->family = AF_INET;
		e->dport = (__u16)((port >> 8) | (port << 8)); /* ntohs */
		e->daddr_v4 = addr;
		e->saddr_v4 = 0;
		__builtin_memset(e->daddr_v6, 0, 16);
		return 1;
	}
	if (family == AF_INET6) {
		__u16 port;
		if (bpf_probe_read_user(&port, sizeof(port), (char *)addr_ptr + 2) != 0)
			return 0;
		if (bpf_probe_read_user(&e->daddr_v6, 16, (char *)addr_ptr + 8) != 0)
			return 0;
		e->family = AF_INET6;
		e->dport = (__u16)((port >> 8) | (port << 8));
		e->daddr_v4 = 0;
		e->saddr_v4 = 0;
		return 1;
	}
	return 0;
}

/* Tracepoint: stabil di semua kernel, tidak tergantung simbol __x64_sys_* */
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect_tp(struct sys_enter_ctx *ctx)
{
	void *addr = (void *)ctx->args[1];
	struct network_event_t *e = bpf_ringbuf_reserve(&network_events, sizeof(*e), 0);
	if (!e) return 0;
	e->type = 1;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->tid = (__u32)bpf_get_current_pid_tgid();
	e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->family = 0;
	e->dport = 0;
	e->daddr_v4 = 0;
	__builtin_memset(e->daddr_v6, 0, 16);
	if (addr)
		read_sockaddr(addr, e);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_sendto_tp(struct sys_enter_ctx *ctx)
{
	void *addr = (void *)ctx->args[4];
	struct network_event_t *e = bpf_ringbuf_reserve(&network_events, sizeof(*e), 0);
	if (!e) return 0;
	e->type = 2;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->tid = (__u32)bpf_get_current_pid_tgid();
	e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->family = 0;
	e->dport = 0;
	e->daddr_v4 = 0;
	__builtin_memset(e->daddr_v6, 0, 16);
	if (addr)
		read_sockaddr(addr, e);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ping and other raw-socket traffic (e.g. ICMP) often use sendmsg(); dest addr in msghdr.msg_name */
SEC("tracepoint/syscalls/sys_enter_sendmsg")
int trace_sendmsg_tp(struct sys_enter_ctx *ctx)
{
	void *msg_ptr = (void *)ctx->args[1];
	void *addr = (void *)0;
	struct network_event_t *e = bpf_ringbuf_reserve(&network_events, sizeof(*e), 0);
	if (!e) return 0;
	e->type = 2; /* sendto/sendmsg both as "sendto" in userspace */
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->tid = (__u32)bpf_get_current_pid_tgid();
	e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->family = 0;
	e->dport = 0;
	e->daddr_v4 = 0;
	__builtin_memset(e->daddr_v6, 0, 16);
	if (msg_ptr && bpf_probe_read_user(&addr, sizeof(addr), msg_ptr) == 0 && addr)
		read_sockaddr(addr, e);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* accept4: tetap kretprobe (tracepoint sys_exit_accept4 ada, tapi addr diisi setelah return) */
SEC("kretprobe/__x64_sys_accept4")
int trace_accept4_ret(struct pt_regs *ctx)
{
	void *addr = (void *)PT_REGS_PARM2(ctx);
	struct network_event_t *e = bpf_ringbuf_reserve(&network_events, sizeof(*e), 0);
	if (!e) return 0;
	e->type = 3;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->tid = (__u32)bpf_get_current_pid_tgid();
	e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->family = 0;
	e->dport = 0;
	e->daddr_v4 = 0;
	__builtin_memset(e->daddr_v6, 0, 16);
	if (addr)
		read_sockaddr(addr, e);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

char _license[] SEC("license") = "GPL";
