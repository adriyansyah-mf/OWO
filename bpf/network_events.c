// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* EDR eBPF: network correlation - tcp connect, udp sendto */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define AF_INET  2
#define AF_INET6 10

struct network_event_t {
	__u8  type;   /* 1=connect, 2=sendto, 3=accept (inbound) */
	__u8  family; /* AF_INET or AF_INET6 */
	__u16 dport;  /* big-endian in kernel, we store host order in userspace */
	__u32 pid;
	__u32 tid;
	__u32 uid;
	__u32 saddr_v4;     /* optional, 0 if not filled */
	__u32 daddr_v4;     /* IPv4 */
	__u8  daddr_v6[16]; /* IPv6 */
	char  comm[TASK_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 64 * 4096);
} network_events SEC(".maps");

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

SEC("kprobe/__x64_sys_connect")
int trace_connect(struct pt_regs *ctx)
{
	void *addr = (void *)arg2(ctx);
	struct network_event_t *e = bpf_ringbuf_reserve(&network_events, sizeof(*e), 0);
	if (!e) return 0;
	e->type = 1; /* connect */
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->tid = (__u32)bpf_get_current_pid_tgid();
	e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	if (!read_sockaddr(addr, e)) {
		bpf_ringbuf_discard(e, 0);
		return 0;
	}
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("kprobe/__x64_sys_sendto")
int trace_sendto(struct pt_regs *ctx)
{
	void *addr = (void *)arg5(ctx);
	struct network_event_t *e = bpf_ringbuf_reserve(&network_events, sizeof(*e), 0);
	if (!e) return 0;
	e->type = 2; /* sendto */
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->tid = (__u32)bpf_get_current_pid_tgid();
	e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	if (!read_sockaddr(addr, e)) {
		bpf_ringbuf_discard(e, 0);
		return 0;
	}
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* accept4: after return, arg2 (addr) is filled with peer (client) address - use kretprobe */
SEC("kretprobe/__x64_sys_accept4")
int trace_accept4_ret(struct pt_regs *ctx)
{
	/* Parm2 is the sockaddr *addr (output); kernel fills it on success */
	void *addr = (void *)PT_REGS_PARM2(ctx);
	struct network_event_t *e = bpf_ringbuf_reserve(&network_events, sizeof(*e), 0);
	if (!e) return 0;
	e->type = 3; /* accept */
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->tid = (__u32)bpf_get_current_pid_tgid();
	e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	if (!read_sockaddr(addr, e)) {
		bpf_ringbuf_discard(e, 0);
		return 0;
	}
	bpf_ringbuf_submit(e, 0);
	return 0;
}

char _license[] SEC("license") = "GPL";
