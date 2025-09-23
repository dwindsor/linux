// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Dave Windsor */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* Global counters for test verification */
int ptrace_access_check_calls = 0;
int ptrace_traceme_calls = 0;
int kfunc_may_access_calls = 0;
int kfunc_is_traced_calls = 0;
int kfunc_get_tracer_calls = 0;
int kfunc_get_pid_calls = 0;

/* Declare ptrace kfuncs */
extern bool bpf_ptrace_may_access(struct task_struct *task, unsigned int mode) __ksym;
extern __u32 bpf_ptrace_get_pid(struct task_struct *task) __ksym;
extern bool bpf_task_is_traced(struct task_struct *task) __ksym;
extern struct task_struct *bpf_task_get_tracer(struct task_struct *task) __ksym;
extern void bpf_task_release(struct task_struct *task) __ksym;

SEC("lsm/ptrace_access_check")
int BPF_PROG(ptrace_access_check, struct task_struct *child, unsigned int mode)
{
	__sync_fetch_and_add(&ptrace_access_check_calls, 1);

	/* Test kfunc: check if we may access the child */
	if (bpf_ptrace_may_access(child, mode))
		__sync_fetch_and_add(&kfunc_may_access_calls, 1);

	/* Test kfunc: get child PID for logging */
	if (bpf_ptrace_get_pid(child) > 0)
		__sync_fetch_and_add(&kfunc_get_pid_calls, 1);

	/* Test kfunc: check if child is already traced */
	if (bpf_task_is_traced(child)) {
		struct task_struct *tracer;

		__sync_fetch_and_add(&kfunc_is_traced_calls, 1);

		/* Test kfunc: get the tracer */
		tracer = bpf_task_get_tracer(child);
		if (tracer) {
			__sync_fetch_and_add(&kfunc_get_tracer_calls, 1);
			bpf_task_release(tracer);
		}
	}

	/* Allow the ptrace operation */
	return 0;
}

SEC("lsm/ptrace_traceme")
int BPF_PROG(ptrace_traceme, struct task_struct *parent)
{
	__sync_fetch_and_add(&ptrace_traceme_calls, 1);

	/* Test kfunc: check if parent may access current */
	struct task_struct *current_task = bpf_get_current_task_btf();

	if (bpf_ptrace_may_access(current_task, 0x02 | 0x10)) /* PTRACE_MODE_ATTACH_REALCREDS */
		__sync_fetch_and_add(&kfunc_may_access_calls, 1);

	/* Allow the traceme operation */
	return 0;
}

/* Additional test program to demonstrate ptrace_get_pid kfunc */
SEC("lsm/bprm_check_security")
int BPF_PROG(test_ptrace_get_pid, struct linux_binprm *bprm)
{
	struct task_struct *current_task = bpf_get_current_task_btf();

	/* Test getting current task's PID */
	if (bpf_ptrace_get_pid(current_task) > 0)
		__sync_fetch_and_add(&kfunc_get_pid_calls, 1);

	return 0;
}

char _license[] SEC("license") = "GPL";
