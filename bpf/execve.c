// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* EDR eBPF: execve via tracepoint (stable across kernels). */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN    16
#define MAX_FILENAME_LEN 256
#define MAX_CMDLINE_LEN  512

struct event_t {
	__u32 pid;
	__u32 tid;
	__u32 uid;
	__u32 gid;
	__u32 ppid;
	__u32 _pad;
	char  comm[TASK_COMM_LEN];
	char  filename[MAX_FILENAME_LEN];
	char  cmdline[MAX_CMDLINE_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 4096);
} events SEC(".maps");

/* Tracepoint sys_enter_execve: common (16) + id (8) + args[6] (48).
 * args[0]=filename, args[1]=argv, args[2]=envp */
struct sys_enter_ctx {
	__u64 _pad[2];
	long id;
	unsigned long args[6];
};

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct sys_enter_ctx *ctx)
{
	void *filename_ptr = (void *)ctx->args[0];
	const char **argv   = (const char **)ctx->args[1];

	struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->pid  = bpf_get_current_pid_tgid() >> 32;
	e->tid  = (__u32)bpf_get_current_pid_tgid();
	e->uid  = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	e->gid  = bpf_get_current_uid_gid() >> 32;
	e->ppid = 0;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	__builtin_memset(e->filename, 0, sizeof(e->filename));
	if (filename_ptr)
		bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename_ptr);
	e->filename[MAX_FILENAME_LEN - 1] = '\0';

	/* Capture argv into cmdline as space-separated string.
	 * Use a compile-time constant (32) for the bpf_probe_read_user_str
	 * size argument -- the eBPF verifier rejects variable-size reads
	 * because it cannot prove R2 (size) is non-negative at every path. */
	__builtin_memset(e->cmdline, 0, sizeof(e->cmdline));
	__u32 pos = 0;
	char *argp;
	int ret;

#pragma unroll
	for (int i = 0; i < 20; i++) {
		if (bpf_probe_read_user(&argp, sizeof(argp), &argv[i]) || !argp)
			break;

		if (i > 0) {
			if (pos < MAX_CMDLINE_LEN - 1)
				e->cmdline[pos & (MAX_CMDLINE_LEN - 1)] = ' ';
			pos++;
		}

		/* Leave at least 32 bytes free so the constant-size read fits */
		if (pos >= MAX_CMDLINE_LEN - 32)
			break;

		/* pos < (MAX_CMDLINE_LEN - 32) == 480 < 512, so
		 * (pos & (MAX_CMDLINE_LEN-1)) == pos, and pos+32 <= 511. */
		ret = bpf_probe_read_user_str(
			e->cmdline + (pos & (MAX_CMDLINE_LEN - 1)),
			32,
			argp);

		if (ret > 1)
			pos += (__u32)(ret - 1);
		else
			break;
	}

	e->cmdline[MAX_CMDLINE_LEN - 1] = '\0';

	bpf_ringbuf_submit(e, 0);
	return 0;
}

char _license[] SEC("license") = "GPL";
