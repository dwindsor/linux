// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Dave Windsor */

#include <test_progs.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include "ptrace_lsm.skel.h"

static int child_pid;

static void cleanup_child(void)
{
	if (child_pid > 0) {
		kill(child_pid, SIGKILL);
		waitpid(child_pid, NULL, 0);
		child_pid = 0;
	}
}

static int spawn_child(void)
{
	int pid;

	pid = fork();
	if (pid == 0) {
		/* Child process - just sleep */
		while (1)
			sleep(1);
	}

	if (pid > 0)
		child_pid = pid;

	return pid;
}

void test_ptrace_lsm(void)
{
	struct ptrace_lsm *skel;
	int err, status;
	pid_t pid;

	skel = ptrace_lsm__open_and_load();
	if (!ASSERT_OK_PTR(skel, "ptrace_lsm__open_and_load"))
		return;

	/* Try to attach programs individually to debug the issue */
	struct bpf_link *link1, *link2, *link3;
	
	link1 = bpf_program__attach(skel->progs.ptrace_access_check);
	if (!ASSERT_OK_PTR(link1, "attach_ptrace_access_check"))
		goto cleanup;
	
	link2 = bpf_program__attach(skel->progs.ptrace_traceme);
	if (!ASSERT_OK_PTR(link2, "attach_ptrace_traceme"))
		goto cleanup_link1;
	
	link3 = bpf_program__attach(skel->progs.test_ptrace_get_pid);
	if (!ASSERT_OK_PTR(link3, "attach_test_ptrace_get_pid"))
		goto cleanup_link2;

	/* Test 1: Spawn a child process */
	pid = spawn_child();
	if (!ASSERT_GT(pid, 0, "spawn_child"))
		goto cleanup_link3;

	/* Test 2: Try to attach to child with ptrace */
	err = ptrace(PTRACE_ATTACH, child_pid, NULL, NULL);
	if (err == 0) {
		/* Wait for child to stop */
		waitpid(child_pid, &status, 0);
		ASSERT_TRUE(WIFSTOPPED(status), "child_stopped");

		/* Test 3: Check BPF program was called */
		ASSERT_GT(skel->bss->ptrace_access_check_calls, 0,
			  "ptrace_access_check_called");

		/* Test 4: Try to read child's memory */
		long data;

		err = ptrace(PTRACE_PEEKDATA, child_pid, 0, &data);
		ASSERT_GE(err, 0, "ptrace_peekdata");

		/* Test 5: Detach from child */
		err = ptrace(PTRACE_DETACH, child_pid, NULL, NULL);
		ASSERT_OK(err, "ptrace_detach");
	}

	/* Test 6: Test PTRACE_TRACEME */
	pid = fork();
	if (pid == 0) {
		/* Child calls PTRACE_TRACEME */
		ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		kill(getpid(), SIGSTOP);
		_exit(0);
	} else if (pid > 0) {
		/* Parent waits for child */
		waitpid(pid, &status, 0);
		ASSERT_TRUE(WIFSTOPPED(status), "traceme_child_stopped");

		/* Check BPF program was called for traceme */
		ASSERT_GT(skel->bss->ptrace_traceme_calls, 0,
			  "ptrace_traceme_called");

		/* Continue and wait for child to exit */
		ptrace(PTRACE_CONT, pid, NULL, NULL);
		waitpid(pid, &status, 0);
		ASSERT_TRUE(WIFEXITED(status), "traceme_child_exited");
	}

	/* Test 7: Check kfunc usage counters */
	ASSERT_GT(skel->bss->kfunc_may_access_calls, 0, "kfunc_may_access_called");
	ASSERT_GT(skel->bss->kfunc_get_pid_calls, 0, "kfunc_get_pid_called");

cleanup_link3:
	bpf_link__destroy(link3);
cleanup_link2:
	bpf_link__destroy(link2);
cleanup_link1:
	bpf_link__destroy(link1);
cleanup:
	cleanup_child();
	ptrace_lsm__destroy(skel);
}
