/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Minimal BPF tracing (pt_regs, PT_REGS_PARM1) for x86_64 kprobe */

#ifndef __BPF_TRACING__
#define __BPF_TRACING__

#include "bpf_helpers.h"

#if defined(__x86_64__) || defined(__TARGET_ARCH_x86)
/* x86_64 SysV ABI: first argument in rdi */
struct pt_regs {
	unsigned long rdi; /* PARM1 */
	unsigned long rsi;
	unsigned long rdx;
	unsigned long rcx;
	unsigned long r8;
	unsigned long r9;
	unsigned long r10;
	unsigned long r11;
	unsigned long r12;
	unsigned long r13;
	unsigned long r14;
	unsigned long r15;
	unsigned long rbp;
	unsigned long rbx;
	unsigned long rsp;
	unsigned long rip;
};

#define PT_REGS_PARM1(x) ((x)->rdi)
#define PT_REGS_PARM2(x) ((x)->rsi)
#define PT_REGS_PARM3(x) ((x)->rdx)
#define PT_REGS_PARM4(x) ((x)->rcx)
#define PT_REGS_PARM5(x) ((x)->r8)
#elif defined(__aarch64__) || defined(__TARGET_ARCH_arm64)
struct pt_regs {
	unsigned long regs[31];
	unsigned long sp;
	unsigned long pc;
};
#define PT_REGS_PARM1(x) ((x)->regs[0])
#define PT_REGS_PARM2(x) ((x)->regs[1])
#define PT_REGS_PARM3(x) ((x)->regs[2])
#define PT_REGS_PARM4(x) ((x)->regs[3])
#define PT_REGS_PARM5(x) ((x)->regs[4])
#else
#error "Unsupported arch"
#endif

#endif /* __BPF_TRACING__ */
