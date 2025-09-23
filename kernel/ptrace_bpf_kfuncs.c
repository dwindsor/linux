// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <linux/bpf_lsm.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/uaccess.h>

__bpf_kfunc_start_defs();

/* Check if current task may access target task for ptrace */
__bpf_kfunc bool bpf_ptrace_may_access(struct task_struct *task, unsigned int mode)
{
	/* Ensure one of FSCREDS or REALCREDS is set (required by __ptrace_may_access) */
	if (!(mode & PTRACE_MODE_FSCREDS) == !(mode & PTRACE_MODE_REALCREDS))
		return false;

	return ptrace_may_access(task, mode);
}

/* Get the PID of a task for logging */
__bpf_kfunc pid_t bpf_ptrace_get_pid(struct task_struct *task)
{
	return task_pid_nr(task);
}

/* Check if task is currently being traced */
__bpf_kfunc bool bpf_task_is_traced(struct task_struct *task)
{
	return (task->ptrace & PT_PTRACED) ? true : false;
}

/* Get the task that is tracing this task. Must be released with bpf_task_release() */
__bpf_kfunc struct task_struct *bpf_task_get_tracer(struct task_struct *task)
{
	struct task_struct *tracer = NULL;

	rcu_read_lock();
	if (task->ptrace & PT_PTRACED) {
		tracer = task->parent;
		if (tracer)
			get_task_struct(tracer);
	}
	rcu_read_unlock();

	return tracer;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_ptrace_kfunc_set_ids)
BTF_ID_FLAGS(func, bpf_ptrace_may_access, KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, bpf_ptrace_get_pid, KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, bpf_task_is_traced, KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, bpf_task_get_tracer, KF_ACQUIRE | KF_TRUSTED_ARGS | KF_RET_NULL)
BTF_KFUNCS_END(bpf_ptrace_kfunc_set_ids)

static int bpf_ptrace_kfuncs_filter(const struct bpf_prog *prog, u32 kfunc_id)
{
	/* Only allow LSM programs to use ptrace kfuncs */
	if (!btf_id_set8_contains(&bpf_ptrace_kfunc_set_ids, kfunc_id) ||
	    prog->type == BPF_PROG_TYPE_LSM)
		return 0;
	return -EACCES;
}

static const struct btf_kfunc_id_set bpf_ptrace_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &bpf_ptrace_kfunc_set_ids,
	.filter = bpf_ptrace_kfuncs_filter,
};

static int __init bpf_ptrace_kfuncs_init(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_LSM, &bpf_ptrace_kfunc_set);
}

late_initcall(bpf_ptrace_kfuncs_init);
