---
title: Raw Tracepoints
description: Lower level access when you need every byte of the event payload.
weight: 5
---

Raw tracepoints provide a lower-level interface to the same static instrumentation points used by regular tracepoints, but without the overhead of argument type casting and stable ABI guarantees. Introduced in Linux 4.17 by Alexei Starovoitov. Whereas normal tracepoints provide a stable set of arguments, often cast into well-defined data structures, raw tracepoints give direct access to the arguments in the form used by the kernel’s tracepoint handler. This means there’s no guarantee about the argument layout staying consistent across kernel versions—if the kernel’s internal definition of the tracepoint changes, your raw tracepoint program must adapt. Raw tracepoints attach to the same kernel tracepoints as normal tracepoint-based BPF programs. You specify a raw tracepoint by name, just as you would a regular tracepoint, but you load the BPF program with a type that indicates you want raw access, such as `BPF_PROG_TYPE_TRACING` with a section prefix like `raw_tp/` or `tp_btf/`.

### How Raw Tracepoints Work Under the Hood

Raw tracepoints use the same static jump patching mechanism as regular tracepoints, they differ in that they pass unformatted, low-level event data directly to the attached program.

<p style="text-align: center;">
  <img src="/images/docs/chapter3/raw-tracepoint.png" alt="Centered image" />
</p>

The list of all raw tracepoints are available at `/sys/kernel/debug/tracing/available_events` file 

Raw tracepoints are not defined for each individual syscall but are provided as generic entry and exit points (such as sys_enter and sys_exit) for all system calls. Therefore, if you want to target a specific syscall, you must filter events by checking the syscall ID. 

Raw tracepoint uses `bpf_raw_tracepoint_args` data structure as context which is defined in `include/uapi/linux/bpf.h`as the following:
```c
struct bpf_raw_tracepoint_args {
	__u64 args[0];
};
```

To understand what the arguments point to in the case of `sys_enter`, you should examine `include/trace/events/syscalls.h`.
```c
TRACE_EVENT_SYSCALL(sys_enter,
	TP_PROTO(struct pt_regs *regs, long id),
	TP_ARGS(regs, id),
	TP_STRUCT__entry(
		__field(	long,		id		)
		__array(	unsigned long,	args,	6	)
	),

	TP_fast_assign(
		__entry->id	= id;
		syscall_get_arguments(current, regs, __entry->args);
	),

	TP_printk("NR %ld (%lx, %lx, %lx, %lx, %lx, %lx)",
		  __entry->id,
		  __entry->args[0], __entry->args[1], __entry->args[2],
		  __entry->args[3], __entry->args[4], __entry->args[5]),

	syscall_regfunc, syscall_unregfunc
);
```

It has args as `args[0]` -> points to `pt_regs` structure and `args[1]` is the syscall number. 

To access the target syscalls' parameters, you can either cast `ctx->args[0]` to a pointer to a `struct pt_regs` and use it directly, or copy its contents into a local variable of type `struct pt_regs` (e.g., `struct pt_regs regs;`). Then, you can extract the syscall parameters using the `PT_REGS_PARM` macros (such as `PT_REGS_PARM1`, `PT_REGS_PARM2`, etc.).

```c
#define __TARGET_ARCH_x86
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


struct event {
    __u32 pid;
    char comm[16];
    char filename[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} events SEC(".maps");

char LICENSE[] SEC("license") = "GPL";

SEC("raw_tracepoint/sys_enter")
int trace_unlinkat_raw(struct bpf_raw_tracepoint_args *ctx)
{

    struct pt_regs regs;
    if (bpf_probe_read(&regs, sizeof(regs), (void *)ctx->args[0]) != 0)
        return 0;
    
    // The syscall number is stored in ctx->args[1]
    long syscall_id = ctx->args[1];
    if (syscall_id != 263)
        return 0;
    
    const char *pathname = (const char *)PT_REGS_PARM2(&regs);
    
    struct event *evt = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!evt)
        return 0;
    
    evt->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(evt->comm, sizeof(evt->comm));
    
    int ret = bpf_probe_read_user_str(evt->filename, sizeof(evt->filename), pathname);
    if (ret < 0)
        evt->filename[0] = '\0';
    
    bpf_ringbuf_submit(evt, 0);
    return 0;
}
```

User-space code
```c
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "rtp_unlinkat.skel.h"

static volatile bool exiting = false;

static void sig_handler(int signo)
{
    exiting = true;
}

struct event {
    __u32 pid;
    char comm[16];
    char filename[256];
};

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    printf("PID: %u, COMM: %s, FILENAME: %s\n", e->pid, e->comm, e->filename);
    return 0;
}

int main(int argc, char **argv)
{
    struct rtp_unlinkat *skel;
    struct ring_buffer *rb = NULL;
    int err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    skel = rtp_unlinkat__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    err = rtp_unlinkat__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    err = rtp_unlinkat__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        err = 1;
        goto cleanup;
    }

    signal(SIGINT, sig_handler);
    printf("Waiting for events... Press Ctrl+C to exit.\n");


    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    rtp_unlinkat__destroy(skel);
    return err < 0 ? -err : 0;
}
```

The output:
```sh
PID: 3440, COMM: rm, FILENAME: test1
PID: 3442, COMM: rm, FILENAME: test2
```


Let's explore another example other than `sys_enter`. The following is raw tracepoint `task_rename` which is triggered when a process change its command name. Detecting such activity is crucial in security field such as malware try to hide its true identity or mimic a trusted process such as using `prctl(PR_SET_NAME)` to change the name of comm.
By examining task_rename tracing event source code located in `include/trace/events/task.h`,we can see how the tracing mechanism is implemented:
```c
TRACE_EVENT(task_rename,

	TP_PROTO(struct task_struct *task, const char *comm),
	TP_ARGS(task, comm),
	TP_STRUCT__entry(
		__field(	pid_t,	pid)
		__array(	char, oldcomm,  TASK_COMM_LEN)
		__array(	char, newcomm,  TASK_COMM_LEN)
		__field(	short,	oom_score_adj)
	),

	TP_fast_assign(
		__entry->pid = task->pid;
		memcpy(entry->oldcomm, task->comm, TASK_COMM_LEN);
		strscpy(entry->newcomm, comm, TASK_COMM_LEN);
		__entry->oom_score_adj = task->signal->oom_score_adj;
	),
	TP_printk("pid=%d oldcomm=%s newcomm=%s oom_score_adj=%hd",
		__entry->pid, __entry->oldcomm,
		__entry->newcomm, __entry->oom_score_adj)
);
```

From `TP_PTORO`, we can see that the first argument `ctx->args[0]` is pointing to `struct task_struct *task` and the second `ctx->args[1]` argument is pointing to `const char *comm`:
```c
TP_PROTO(struct task_struct *task, const char *comm)
```

`struct task_struct` data structure is defined in `include/linux/sched.h`. Let's see the following code:
```c
#define __TARGET_ARCH_x86
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

struct event {
    u32 pid;
    u32 parent_pid;
    char new_comm[TASK_COMM_LEN];
    char old_comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12);
} events SEC(".maps");

char LICENSE[] SEC("license") = "GPL";

SEC("raw_tracepoint/task_rename")
int raw_tracepoint_task_rename(struct bpf_raw_tracepoint_args *ctx)
{
    struct task_struct *task = (struct task_struct *)ctx->args[0];
    const char *new_comm_ptr = (const char *)ctx->args[1];

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = BPF_CORE_READ(task, pid);

    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    e->parent_pid = BPF_CORE_READ(parent, pid);

    bpf_probe_read_kernel_str(e->old_comm, sizeof(e->old_comm), task->comm);
    bpf_probe_read_kernel_str(e->new_comm, sizeof(e->new_comm), new_comm_ptr);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
```

The first argument `ctx->args[0]` is pointing to `struct task_struct *task` and the second `ctx->args[1]` argument is pointing to `const char *comm`:
```c
    struct task_struct *task = (struct task_struct *)ctx->args[0];
    const char *new_comm_ptr = (const char *)ctx->args[1];
```

User-space code:
```c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "task_rename_ringbuf.skel.h"

struct event {
    __u32 pid;
    __u32 parent_pid;
    char new_comm[16];
    char old_comm[16];
};

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct event *e = data;
    printf("pid=%u, parent_pid=%u, new_comm=%s, old_comm=%s\n",
           e->pid, e->parent_pid, e->new_comm, e->old_comm);
    return 0;
}

int main(int argc, char **argv)
{
    struct task_rename_ringbuf_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    skel = task_rename_ringbuf_bpf__open();
    if (!skel) {
        fprintf(stderr, "ERROR: failed to open BPF skeleton\n");
        return 1;
    }

    err = task_rename_ringbuf_bpf__load(skel);
    if (err) {
        fprintf(stderr, "ERROR: failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    err = task_rename_ringbuf_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "ERROR: failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        err = -errno;
        fprintf(stderr, "ERROR: failed to create ring buffer: %d\n", err);
        goto cleanup;
    }

    printf("Waiting for task_rename events... Press Ctrl+C to exit.\n");
    while (1) {
        err = ring_buffer__poll(rb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "ERROR: polling ring buffer failed: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    task_rename_ringbuf_bpf__destroy(skel);
    return -err;
}
```

Now let's create a simple code to use `prctl(PR_SET_NAME)` to change comm name:
```c
#include <stdio.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <string.h>
#include <errno.h>

int main(void) {
    char current_name[16] = {0};

    if (prctl(PR_GET_NAME, (unsigned long)current_name, 0, 0, 0) != 0) {
        perror("prctl(PR_GET_NAME)");
        return 1;
    }
    printf("Current process name: %s\n", current_name);

    const char *fake_name = "systemd";
    if (prctl(PR_SET_NAME, (unsigned long)fake_name, 0, 0, 0) != 0) {
        perror("prctl(PR_SET_NAME)");
        return 1;
    }

    memset(current_name, 0, sizeof(current_name));
    if (prctl(PR_GET_NAME, (unsigned long)current_name, 0, 0, 0) != 0) {
        perror("prctl(PR_GET_NAME)");
        return 1;
    }
    printf("Process name changed to: %s\n", current_name);

    sleep(120);
    return 0;
}
```

Compile it using `gcc fake.c -o fake` then run it `./fake`

```sh
Waiting for task_rename events... Press Ctrl+C to exit.
pid=7839, parent_pid=7478, new_comm=fake, old_comm=bash
pid=7839, parent_pid=7478, new_comm=systemd, old_comm=fake
```
Then process changed it's comm from fake to systemd. We can confirm by

```sh
cat /proc/7839/comm
systemd
```

Or using `top` command, `top --pid 7839`
```sh
top - 04:57:06 up  4:42,  6 users,  load average: 0.02, 0.01, 0.00
Tasks:   1 total,   0 running,   1 sleeping,   0 stopped,   0 zombie
%Cpu(s):  0.1 us,  0.1 sy,  0.0 ni, 99.8 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st 
MiB Mem :   3921.3 total,   1481.0 free,   1199.2 used,   1534.0 buff/cache     
MiB Swap:   3169.0 total,   3169.0 free,      0.0 used.   2722.1 avail Mem 

    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND                                       
   7839 ebpf      20   0    2560   1616   1616 S   0.0   0.0   0:00.00 systemd
```
