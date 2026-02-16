// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* EDR eBPF: process creation syscalls - fork, clone, clone3 (tracepoint sys_exit_*). */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16

struct process_event_t {
	__u8  type;   /* 1=fork, 2=clone, 3=clone3 */
	__u32 parent_pid;
	__u32 parent_tid;
	__u32 child_pid;
	__u32 uid;
	char  comm[TASK_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 32 * 4096);
} process_events SEC(".maps");

/* sys_exit tracepoint: common (16) + id (8) + ret (8) */
struct sys_exit_ctx {
	__u64 _pad[2];
	long id;
	long ret;
};

static __always_inline void submit_process_event(__u8 typ, long child_pid)
{
	if (child_pid <= 0)
		return;
	struct process_event_t *e = bpf_ringbuf_reserve(&process_events, sizeof(*e), 0);
	if (!e)
		return;
	e->type = typ;
	e->parent_pid = bpf_get_current_pid_tgid() >> 32;
	e->parent_tid = (__u32)bpf_get_current_pid_tgid();
	e->child_pid = (__u32)child_pid;
	e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
}

SEC("tracepoint/syscalls/sys_exit_fork")
int trace_fork_exit(struct sys_exit_ctx *ctx)
{
	submit_process_event(1, ctx->ret);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_clone")
int trace_clone_exit(struct sys_exit_ctx *ctx)
{
	submit_process_event(2, ctx->ret);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_clone3")
int trace_clone3_exit(struct sys_exit_ctx *ctx)
{
	submit_process_event(3, ctx->ret);
	return 0;
}

char _license[] SEC("license") = "GPL";
