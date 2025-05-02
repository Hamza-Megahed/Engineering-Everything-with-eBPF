---
title: bpf_send_signal
description: Helper that can raise signals in misbehaving tasks from inside BPF code.
weight: 5
---

`bpf_send_signal()` is a helper function that allows a eBPF program to send a Unix signal (e.g., `SIGUSR1`, `SIGKILL`, etc.) to the current process (the process that triggered execution of the BPF program). If an anomaly is detected (e.g., unauthorized file access, network connections, or excessive resource usage), the eBPF program can send a signal to terminate the offending process. `bpf_send_signal_thread()` helper function is similar to `bpf_send_signal()` except it will send a signal to thread corresponding to the current task.

`bpf_send_signal` has the following prototype:
```c
static long (* const bpf_send_signal)(__u32 sig) = (void *) 109;
```

`sys_ptrace` is a system call in Linux and other Unix-like operating systems that allows one process (the tracer) to observe and control the execution of another process (the tracee). The following example, we attached kprobe to `sys_ptrace` syscall and monitor this call to only allow root (UID = 0) to call this syscall. If UID not zero (non-root user) hen the process will be terminated using `bpf_send_signal()` helper function.

```c
#define __TARGET_ARCH_x86
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define ALLOWED_UID 0

char LICENSE[] SEC("license") = "GPL";

SEC("kprobe/__x64_sys_ptrace")
int BPF_KPROBE__x64_sys_ptrace(void)
{
    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 uid = (__u32)uid_gid;

    if (uid != ALLOWED_UID) {
        bpf_printk("Unauthorized ptrace attempt by uid %d\n", uid);
        bpf_send_signal(9);
    }
    return 0;
}
```

User-space code 
```c
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "signal_ptrace.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct signal_ptrace *skel;
	int err;

	libbpf_set_print(libbpf_print_fn);

	skel = signal_ptrace__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	err = signal_ptrace__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	err = signal_ptrace__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

	for (;;) {
		fprintf(stderr, ".");
		sleep(1);
	}

cleanup:
	signal_ptrace__destroy(skel);
	return -err;
}
```

Compile the code, then generate skeleton file , then compile the loader code. When trying to trigger `ptrace` syscall with a tool like `strace`
```sh
strace /usr/bin/ls
Killed
```

Viewing the trace pipe file `sudo cat /sys/kernel/debug/tracing/trace_pipe` will give similar output:
```sh
strace-3402    [001] ...21 16100.793628: bpf_trace_printk: Unauthorized ptrace attempt by uid 1000
```

Below is an example write-up that describes an imaginary privilege escalation scenario and shows the eBPF code that detects the specific syscall sequence (fork, setuid(0), and execve) to terminate the process.

Imagine an attacker attempts a privilege escalation by using the following assembly code to fork, set UID to 0, and finally execute `/bin/bash` to spawn a root shell:
```c
section .data
  cmd db "/bin/bash", 0

section .text
  global _start

_start:
  ; Fork syscall
  mov eax, 57
  xor edi, edi
  syscall

  test eax, eax
  jz child_process

  ; Parent process

  ; Setuid syscall
  mov eax, 105
  xor edi, edi
  syscall

  cmp eax, 0
  jne exit_program

  ; Execve syscall
  mov eax, 59
  mov rdi, cmd
  xor rsi, rsi
  xor rdx, rdx
  syscall

exit_program:
  mov eax, 60
  xor edi, edi
  syscall

child_process:
  ; Child process
  xor eax, eax
  ret
```

First, we compile it using `nasm -f elf64 -o privilege_escalation.o privilege_escalation.asm` , then link it `ld -o privilege_escalation privilege_escalation.o`

We build an eBPF program that uses `bpf_send_signal` to monitor for a suspicious sequence of syscalls. If the program detects that a process has `forked`, then called `setuid(0)`, and finally executed `execve` to run `/bin/bash` (spawning a root shell), it will immediately fire a signal to terminate that process.

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u8);
} forks SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u8);
} setuid SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_fork")
int trace_fork(struct trace_event_raw_sys_enter *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 val = 1;

    bpf_map_update_elem(&forks, &pid, &val, BPF_ANY);
    bpf_printk("Fork detected: PID %d\n", pid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setuid")
int trace_setuid(struct trace_event_raw_sys_enter *ctx)
{
    u32 uid = ctx->args[0];
    if (uid == 0) {
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        u8 val = 1;
        bpf_map_update_elem(&setuid, &pid, &val, BPF_ANY);
        bpf_printk("Setuid detected: PID %d\n", pid);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 *forked = bpf_map_lookup_elem(&forks, &pid);
    u8 *priv = bpf_map_lookup_elem(&setuid, &pid);

    if (forked && priv) {
        bpf_printk("Privilege escalation detected: fork, setuid(0), execve, PID %d\n", pid);
        bpf_send_signal(9);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

`sudo ./privilege_escalation` 
```sh
priv-3654 [...] Fork detected: PID 3654
priv-3654 [...] Setuid detected: PID 3654
priv-3654 [...] Privilege escalation detected: fork, setuid(0), execve, PID 3654
```

