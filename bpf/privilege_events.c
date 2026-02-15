// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* EDR eBPF: privilege changes - setuid, setgid, setreuid, setregid */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16

/* type: 1=setuid, 2=setgid, 3=setreuid, 4=setregid, 5=setresuid, 6=setresgid */
struct privilege_event_t {
	__u8  type;
	__u32 pid;
	__u32 tid;
	__u32 uid;
	__u32 gid;
	__u32 new_uid;  /* for setuid/setreuid/setresuid */
	__u32 new_gid;  /* for setgid/setregid/setresgid */
	char  comm[TASK_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 64 * 4096);
} privilege_events SEC(".maps");

static __always_inline void* arg1(struct pt_regs *ctx) { return (void *)PT_REGS_PARM1(ctx); }
static __always_inline void* arg2(struct pt_regs *ctx) { return (void *)PT_REGS_PARM2(ctx); }

#define PRIV_SETUID   1
#define PRIV_SETGID   2
#define PRIV_SETREUID 3
#define PRIV_SETREGID 4
#define PRIV_SETRESUID 5
#define PRIV_SETRESGID 6

static __always_inline void submit_priv(__u8 type, __u32 new_uid, __u32 new_gid)
{
	struct privilege_event_t *e = bpf_ringbuf_reserve(&privilege_events, sizeof(*e), 0);
	if (!e) return;
	e->type = type;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->tid = (__u32)bpf_get_current_pid_tgid();
	e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	e->gid = bpf_get_current_uid_gid() >> 32;
	e->new_uid = new_uid;
	e->new_gid = new_gid;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
}

SEC("kprobe/__x64_sys_setuid")
int trace_setuid(struct pt_regs *ctx)
{
	__u32 uid;
	if (bpf_probe_read_user(&uid, sizeof(uid), arg1(ctx)) != 0)
		return 0;
	submit_priv(PRIV_SETUID, uid, 0);
	return 0;
}

SEC("kprobe/__x64_sys_setgid")
int trace_setgid(struct pt_regs *ctx)
{
	__u32 gid;
	if (bpf_probe_read_user(&gid, sizeof(gid), arg1(ctx)) != 0)
		return 0;
	submit_priv(PRIV_SETGID, 0, gid);
	return 0;
}

SEC("kprobe/__x64_sys_setreuid")
int trace_setreuid(struct pt_regs *ctx)
{
	__u32 ruid, euid;
	if (bpf_probe_read_user(&ruid, sizeof(ruid), arg1(ctx)) != 0)
		return 0;
	if (bpf_probe_read_user(&euid, sizeof(euid), arg2(ctx)) != 0)
		return 0;
	submit_priv(PRIV_SETREUID, euid, 0); /* report effective */
	return 0;
}

SEC("kprobe/__x64_sys_setregid")
int trace_setregid(struct pt_regs *ctx)
{
	__u32 rgid, egid;
	if (bpf_probe_read_user(&rgid, sizeof(rgid), arg1(ctx)) != 0)
		return 0;
	if (bpf_probe_read_user(&egid, sizeof(egid), arg2(ctx)) != 0)
		return 0;
	submit_priv(PRIV_SETREGID, 0, egid);
	return 0;
}

char _license[] SEC("license") = "GPL";
