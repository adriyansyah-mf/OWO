// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* EDR eBPF: kernel module load (init_module, finit_module) */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define MODULE_NAME_LEN 64

/* type: 1=init_module, 2=finit_module */
struct module_event_t {
	__u8  type;
	__u32 pid;
	__u32 uid;
	char  comm[TASK_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 16 * 4096);
} module_events SEC(".maps");

static __always_inline void submit_module(__u8 type)
{
	struct module_event_t *e = bpf_ringbuf_reserve(&module_events, sizeof(*e), 0);
	if (!e) return;
	e->type = type;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
}

SEC("kprobe/__x64_sys_init_module")
int trace_init_module(struct pt_regs *ctx)
{
	submit_module(1);
	return 0;
}

SEC("kprobe/__x64_sys_finit_module")
int trace_finit_module(struct pt_regs *ctx)
{
	submit_module(2);
	return 0;
}

char _license[] SEC("license") = "GPL";
