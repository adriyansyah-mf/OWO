// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* EDR eBPF: monitor execve (process execution) via kprobe */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256

struct event_t {
	__u32 pid;
	__u32 tid;
	__u32 uid;
	__u32 gid;
	__u32 ppid;
	__u32 _pad;
	char  comm[TASK_COMM_LEN];
	char  filename[MAX_FILENAME_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 4096);
} events SEC(".maps");

static __always_inline void* get_arg1(struct pt_regs *ctx)
{
	return (void *)PT_REGS_PARM1(ctx);
}

SEC("kprobe/__x64_sys_execve")
int trace_execve(struct pt_regs *ctx)
{
	struct event_t *e;
	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->tid = (__u32)bpf_get_current_pid_tgid();
	e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	e->gid = bpf_get_current_uid_gid() >> 32;
	e->ppid = 0; /* TODO: bpf_get_current_task + real_parent->tgid */
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_probe_read_user_str(&e->filename, sizeof(e->filename), get_arg1(ctx));
	e->filename[MAX_FILENAME_LEN - 1] = '\0';

	bpf_ringbuf_submit(e, 0);
	return 0;
}

char _license[] SEC("license") = "GPL";
