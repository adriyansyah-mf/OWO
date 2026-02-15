// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* EDR eBPF: process exit (exit_group) */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16

struct exit_event_t {
	__u32 pid;
	__u32 tid;
	__u32 uid;
	__s32 exit_code;
	char  comm[TASK_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 64 * 4096);
} exit_events SEC(".maps");

static __always_inline void* arg1(struct pt_regs *ctx) { return (void *)PT_REGS_PARM1(ctx); }

SEC("kprobe/__x64_sys_exit_group")
int trace_exit_group(struct pt_regs *ctx)
{
	__s32 code;
	struct exit_event_t *e = bpf_ringbuf_reserve(&exit_events, sizeof(*e), 0);
	if (!e) return 0;
	if (bpf_probe_read_user(&code, sizeof(code), arg1(ctx)) != 0) {
		bpf_ringbuf_discard(e, 0);
		return 0;
	}
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->tid = (__u32)bpf_get_current_pid_tgid();
	e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	e->exit_code = code;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
	return 0;
}

char _license[] SEC("license") = "GPL";
