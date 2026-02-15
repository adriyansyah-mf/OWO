// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* EDR eBPF: file operations on monitored paths (/etc, /usr/bin, /bin, /tmp, /dev/shm) */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define MAX_PATH_LEN  256

#define FILE_OPENAT  1
#define FILE_UNLINK  2
#define FILE_RENAME  3

struct file_event_t {
	__u8  type;
	__u32 pid;
	__u32 tid;
	__u32 uid;
	__u32 _pad;
	char  path[MAX_PATH_LEN];
	char  path2[MAX_PATH_LEN]; /* for rename newpath */
	char  comm[TASK_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 4096);
} file_events SEC(".maps");

/* 0 = only watched paths (/etc,/usr/bin,/bin,/tmp,/dev/shm). 1 = all absolute paths (total). Set from userspace. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} file_config SEC(".maps");

static __always_inline int path_watched(const char *p) {
	if (!p) return 0;
	if (p[0] != '/') return 0;
	__u32 key = 0;
	__u32 *watch_all = (__u32 *)bpf_map_lookup_elem(&file_config, &key);
	if (watch_all && *watch_all == 1)
		return 1; /* monitor all absolute paths */
	if (p[1] == 'e' && p[2] == 't' && p[3] == 'c' && (p[4] == '/' || p[4] == '\0')) return 1;
	if (p[1] == 't' && p[2] == 'm' && p[3] == 'p' && (p[4] == '/' || p[4] == '\0')) return 1;
	if (p[1] == 'b' && p[2] == 'i' && p[3] == 'n' && (p[4] == '/' || p[4] == '\0')) return 1;
	if (p[1] == 'd' && p[2] == 'e' && p[3] == 'v' && p[4] == '/' && p[5] == 's' && p[6] == 'h' && p[7] == 'm' && (p[8] == '/' || p[8] == '\0')) return 1;
	if (p[1] == 'u' && p[2] == 's' && p[3] == 'r' && p[4] == '/' && p[5] == 'b' && p[6] == 'i' && p[7] == 'n' && (p[8] == '/' || p[8] == '\0')) return 1;
	return 0;
}

static __always_inline void* arg1(struct pt_regs *ctx) { return (void *)PT_REGS_PARM1(ctx); }
static __always_inline void* arg2(struct pt_regs *ctx) { return (void *)PT_REGS_PARM2(ctx); }
static __always_inline void* arg3(struct pt_regs *ctx) { return (void *)PT_REGS_PARM3(ctx); }

SEC("kprobe/__x64_sys_openat")
int trace_openat(struct pt_regs *ctx)
{
	const char *path = (const char *)arg2(ctx);
	char buf[MAX_PATH_LEN];
	if (bpf_probe_read_user_str(buf, sizeof(buf), path) <= 0)
		return 0;
	if (!path_watched(buf))
		return 0;

	struct file_event_t *e = bpf_ringbuf_reserve(&file_events, sizeof(*e), 0);
	if (!e) return 0;
	e->type = FILE_OPENAT;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->tid = (__u32)bpf_get_current_pid_tgid();
	e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	__builtin_memset(e->path2, 0, sizeof(e->path2));
	bpf_probe_read_user_str(&e->path, sizeof(e->path), path);
	e->path[MAX_PATH_LEN - 1] = '\0';
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("kprobe/__x64_sys_unlink")
int trace_unlink(struct pt_regs *ctx)
{
	const char *path = (const char *)arg1(ctx);
	char buf[MAX_PATH_LEN];
	if (bpf_probe_read_user_str(buf, sizeof(buf), path) <= 0)
		return 0;
	if (!path_watched(buf))
		return 0;

	struct file_event_t *e = bpf_ringbuf_reserve(&file_events, sizeof(*e), 0);
	if (!e) return 0;
	e->type = FILE_UNLINK;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->tid = (__u32)bpf_get_current_pid_tgid();
	e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	__builtin_memset(e->path2, 0, sizeof(e->path2));
	bpf_probe_read_user_str(&e->path, sizeof(e->path), path);
	e->path[MAX_PATH_LEN - 1] = '\0';
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("kprobe/__x64_sys_rename")
int trace_rename(struct pt_regs *ctx)
{
	const char *old = (const char *)arg1(ctx);
	const char *new = (const char *)arg2(ctx);
	char buf[MAX_PATH_LEN];
	if (bpf_probe_read_user_str(buf, sizeof(buf), old) <= 0)
		return 0;
	if (!path_watched(buf)) {
		if (bpf_probe_read_user_str(buf, sizeof(buf), new) <= 0)
			return 0;
		if (!path_watched(buf))
			return 0;
	}

	struct file_event_t *e = bpf_ringbuf_reserve(&file_events, sizeof(*e), 0);
	if (!e) return 0;
	e->type = FILE_RENAME;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->tid = (__u32)bpf_get_current_pid_tgid();
	e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_probe_read_user_str(&e->path, sizeof(e->path), old);
	e->path[MAX_PATH_LEN - 1] = '\0';
	bpf_probe_read_user_str(&e->path2, sizeof(e->path2), new);
	e->path2[MAX_PATH_LEN - 1] = '\0';
	bpf_ringbuf_submit(e, 0);
	return 0;
}

char _license[] SEC("license") = "GPL";
