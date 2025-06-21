---
title: bpftrace
description: DTrace style one liners for quick ad hoc tracing of kernel and user processes.
weight: 2
---

bpftrace is a powerful, high-level tracing language for Linux that simplifies the process of creating eBPF (Extended Berkeley Packet Filter) programs. It simplifies the process of instrumenting kernel and user-space code by providing a simple language to attach probes to kernel functions, tracepoints, and user-defined events in a user-friendly syntax, inspired by awk, C, and other tracing tools, enabling users to quickly gain insights into system behavior. By abstracting away the complexities of low-level eBPF programming and leveraging libbpf as its backend, bpftrace allows system administrators, performance engineers, and developers to easily observe and analyze system performance without requiring extensive eBPF expertise. Let's start by looking at the bpftrace command.

## bpftrace Options

When running bpftrace, you can use various command-line options to control its behavior. Some commonly used options include:

```sh
OPTIONS:
    -B MODE        output buffering mode ('full', 'none')
    -f FORMAT      output format ('text', 'json')
    -o file        redirect bpftrace output to file
    -e 'program'   execute this program
    -h, --help     show this help message
    -I DIR         add the directory to the include search path
    --include FILE add an #include file before preprocessing
    -l [search|filename]
                   list kernel probes or probes in a program
    -p PID         enable USDT probes on PID
    -c 'CMD'       run CMD and enable USDT probes on resulting process
    --usdt-file-activation
                   activate usdt semaphores based on file path
    --unsafe       allow unsafe/destructive functionality
    -q             keep messages quiet
    --info         Print information about kernel BPF support
    -k             emit a warning when a bpf helper returns an error (except read functions)
    -kk            check all bpf helper functions
    -V, --version  bpftrace version
    --no-warnings  disable all warning messages
```

For example, we can use `-l` along with `*` for wildcard for listing such as listing all kprobes:
```sh
sudo bpftrace -l 'kprobe:*' 
```

```sh
[...]
kprobe:zswap_store
kprobe:zswap_swapoff
kprobe:zswap_swapon
kprobe:zswap_total_pages
kprobe:zswap_writeback_entry
kprobe:zswap_writeback_show
kprobe:zswap_writeback_write
kprobe:zswap_zpool_param_set
```

We can list probe parameters for a certain function using 
```sh
sudo bpftrace -lv 'fentry:tcp_reset'
```

```sh
fentry:vmlinux:tcp_reset
    struct sock * sk
    struct sk_buff * skb
```

We can list all symbols from object or binary files for uprobe such as the following:
```sh
sudo bpftrace -l 'uprobe:/bin/bash:*'
```

```sh
[...]
uprobe:/bin/bash:async_redirect_stdin
uprobe:/bin/bash:base_pathname
uprobe:/bin/bash:bash_add_history
uprobe:/bin/bash:bash_brace_completion
uprobe:/bin/bash:bash_clear_history
uprobe:/bin/bash:bash_default_completion
uprobe:/bin/bash:bash_delete_histent
uprobe:/bin/bash:bash_delete_history_range
uprobe:/bin/bash:bash_delete_last_history
uprobe:/bin/bash:bash_dequote_text
[...]
```

Using `-e` can be used to execute a program in one-liner. For example,
```sh
sudo bpftrace -e 'uprobe:/bin/bash:shell_execve { printf("shell_execve called\n"); }'
```

```sh
Attaching 1 probe...
open() called
open() called
open() called
```

This program `uprobe:/bin/bash:shell_execve { printf("shell_execve called\n"); }` means this action `printf("shell_execve called\n");` will be executed when `uprobe:/bin/bash:shell_execve` get triggered.

If we want to print out which command is being executed is by printing the first argument with `arg0` using `str` function which reads a NULL terminated string similar to `bpf_probe_read_str` helper function. `argN` is a bpf builtins while hold arguments passed to the function being traced and it can be used with kprobe and uprobe.
```sh
sudo bpftrace -e 'uprobe:/bin/bash:shell_execve { printf("command:%s\n", str(arg0)); }'
```

```sh
Attaching 1 probe...
command:/usr/bin/ls
command:/usr/bin/ping
command:/usr/bin/cat
```

The following table is from the bpftrace manual, listing special variables along with their corresponding helper functions and descriptions.

| Variable                  | BPF Helper                       | Description                                                                                                                                                                                                           |
| ------------------------- | -------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `$1`, `$2`, `...$n`       | n/a                              | The nth positional parameter passed to the bpftrace program. If less than n parameters are passed this evaluates to `0`. For string arguments use the `str()` call to retrieve the value.                             |
| `$#`                      | n/a                              | Total amount of positional parameters passed.                                                                                                                                                                         |
| `arg0`, `arg1`, `...argn` | n/a                              | nth argument passed to the function being traced. These are extracted from the CPU registers. The amount of args passed in registers depends on the CPU architecture. (kprobes, uprobes, usdt).                       |
| `args`                    | n/a                              | The struct of all arguments of the traced function. Available in `tracepoint`, `fentry`, `fexit`, and `uprobe` (with DWARF) probes. Use `args.x` to access argument `x` or `args` to get a record with all arguments. |
| `cgroup`                  | get_current_cgroup_id            | ID of the cgroup the current process belongs to. Only works with cgroupv2.                                                                                                                                            |
| `comm`                    | get_current_comm                 | Name of the current thread.                                                                                                                                                                                           |
| `cpid`                    | n/a                              | Child process ID, if bpftrace is invoked with `-c`.                                                                                                                                                                   |
| `cpu`                     | raw_smp_processor_id             | ID of the processor executing the BPF program.                                                                                                                                                                        |
| `curtask`                 | get_current_task                 | Pointer to `struct task_struct` of the current task.                                                                                                                                                                  |
| `elapsed`                 | ktime_get_ns / ktime_get_boot_ns | Nanoseconds elapsed since bpftrace initialization, based on `nsecs`.                                                                                                                                                  |
| `func`                    | n/a                              | Name of the current function being traced (kprobes, uprobes).                                                                                                                                                         |
| `gid`                     | get_current_uid_gid              | Group ID of the current thread, as seen from the init namespace.                                                                                                                                                      |
| `jiffies`                 | get_jiffies_64                   | Jiffies of the kernel. In 32-bit systems, using this builtin might be slower.                                                                                                                                         |
| `numaid`                  | numa_node_id                     | ID of the NUMA node executing the BPF program.                                                                                                                                                                        |
| `pid`                     | get_current_pid_tgid             | Process ID of the current thread (aka thread group ID), as seen from the init namespace.                                                                                                                              |
| `probe`                   | n/a                              | Name of the current probe.                                                                                                                                                                                            |
| `rand`                    | get_prandom_u32                  | Random number.                                                                                                                                                                                                        |
| `return`                  | n/a                              | The return keyword is used to exit the current probe. This differs from exit() in that it doesn't exit bpftrace.                                                                                                      |
| `retval`                  | n/a                              | Value returned by the function being traced (kretprobe, uretprobe, fexit). For kretprobe and uretprobe, its type is `uint64`, but for fexit it depends. You can look up the type using `bpftrace -lv`.                |
| `tid`                     | get_current_pid_tgid             | Thread ID of the current thread, as seen from the init namespace.                                                                                                                                                     |
| `uid`                     | get_current_uid_gid              | User ID of the current thread, as seen from the init namespace.                                                                                                                                                       |


The following table is from the bpftrace manual, listing bpftrace functions along with their corresponding descriptions.

| Name         | Description                                                      |
| ------------ | ---------------------------------------------------------------- |
| bswap        | Reverse byte order                                               |
| buf          | Returns a hex-formatted string of the data pointed to by d       |
| cat          | Print file content                                               |
| cgroupid     | Resolve cgroup ID                                                |
| cgroup_path  | Convert cgroup id to cgroup path                                 |
| exit         | Quit bpftrace with an optional exit code                         |
| join         | Print the array                                                  |
| kaddr        | Resolve kernel symbol name                                       |
| kptr         | Annotate as kernelspace pointer                                  |
| kstack       | Kernel stack trace                                               |
| ksym         | Resolve kernel address                                           |
| len          | Count ustack/kstack frames                                       |
| macaddr      | Convert MAC address data                                         |
| nsecs        | Timestamps and Time Deltas                                       |
| ntop         | Convert IP address data to text                                  |
| offsetof     | Offset of element in structure                                   |
| override     | Override return value                                            |
| path         | Return full path                                                 |
| percpu_kaddr | Resolve percpu kernel symbol name                                |
| print        | Print a non-map value with default formatting                    |
| printf       | Print formatted                                                  |
| pton         | Convert text IP address to byte array                            |
| reg          | Returns the value stored in the named register                   |
| signal       | Send a signal to the current process                             |
| sizeof       | Return size of a type or expression                              |
| skboutput    | Write skb 's data section into a PCAP file                       |
| str          | Returns the string pointed to by s                               |
| strcontains  | Compares whether the string haystack contains the string needle. |
| strerror     | Get error message for errno code                                 |
| strftime     | Return a formatted timestamp                                     |
| strncmp      | Compare first n characters of two strings                        |
| system       | Execute shell command                                            |
| time         | Print formatted time                                             |
| uaddr        | Resolve user-level symbol name                                   |
| uptr         | Annotate as userspace pointer                                    |
| ustack       | User stack trace                                                 |
| usym         | Resolve user space address                                       |

## How to Code in bpftrace

bpftrace scripts are written using a custom domain-specific language (DSL) that is similar in syntax to awk. A basic script consists of one or more probe definitions followed by one or more actions. Each probe targets a specific event (e.g., kernel tracepoints, function entry/exit, or user-space events).

The following table is from the bpftrace manual, listing bpftrace probes along with their corresponding descriptions.

|Probe Name|Short Name|Description|Kernel/User Level|
|---|---|---|---|
|BEGIN/END|-|Built-in events|Kernel/User|
|self|-|Built-in events|Kernel/User|
|hardware|`h`|Processor-level events|Kernel|
|interval|`i`|Timed output|Kernel/User|
|iter|`it`|Iterators tracing|Kernel|
|fentry/fexit|`f`/`fr`|Kernel functions tracing with BTF support|Kernel|
|kprobe/kretprobe|`k`/`kr`|Kernel function start/return|Kernel|
|profile|`p`|Timed sampling|Kernel/User|
|rawtracepoint|`rt`|Kernel static tracepoints with raw arguments|Kernel|
|software|`s`|Kernel software events|Kernel|
|tracepoint|`t`|Kernel static tracepoints|Kernel|
|uprobe/uretprobe|`u`/`ur`|User-level function start/return|User|
|usdt|`U`|User-level static tracepoints|User|
|watchpoint/asyncwatchpoint|`w`/`aw`|Memory watchpoints|Kernel|

### Basic Structure of a bpftrace Script

```bpftrace
probe_type:probe_identifier
{
    // Action code block
    printf("Hello, world!\n");
}
```

For example, to print a message every time a process calls the `unlinkat()` syscall, you might write:

```c
#!/usr/bin/env bpftrace

tracepoint:syscalls:sys_enter_unlinkat
{
    printf("unlinkat syscall invoked\n");
}
```

`sys_enter_unlinkat` tracepoint's arguments can be listed from `/sys/kernel/debug/tracing/events/syscalls/sys_enter_unlinkat/format`
```sh
name: sys_enter_unlinkat
ID: 849
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:int dfd;	offset:16;	size:8;	signed:0;
	field:const char * pathname;	offset:24;	size:8;	signed:0;
	field:int flag;	offset:32;	size:8;	signed:0;

print fmt: "dfd: 0x%08lx, pathname: 0x%08lx, flag: 0x%08lx", ((unsigned long)(REC->dfd)), ((unsigned long)(REC->pathname)), ((unsigned long)(REC->flag))
```

Therefore, we can use `str(args.pathname)` to extract the name of the file being deleted. `args` is one of the bpftrace builtins which is a data struct of all arguments of the traced function and it can be used with tracepoint, fentry, fexit.
```c
#!/usr/bin/env bpftrace

tracepoint:syscalls:sys_enter_unlinkat
{
    printf("Process %s (PID: %d) is deleting a file %s\n", comm, pid, str(args.pathname));
}
```

```sh
Attaching 1 probe...
Process rm (PID: 2269) is deleting a file test1
Process rm (PID: 2270) is deleting a file test2
```


Let's convert this eBPF kernel code to bpftrace
```c
#define __TARGET_ARCH_x86
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct event {
    pid_t pid;
    char filename[256];
    umode_t mode;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY); // Type of BPF map
    __uint(max_entries, 1024);                   // Maximum number of entries in the map
    __type(key, int);                            // Type of the key
    __type(value, int);                          // Type of the value
} mkdir SEC(".maps");

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/do_mkdirat")
int BPF_KPROBE(do_mkdirat, int dfd, struct filename *name, umode_t mode)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    struct event ev = {};
    ev.pid = pid;
    ev.mode = mode;
    const char *filename = BPF_CORE_READ(name, name);
    bpf_probe_read_str(ev.filename, sizeof(ev.filename), filename);
    bpf_perf_event_output(ctx, &mkdir, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
    return 0;
}
```

Let's build the same code without Maps as it will be explained shortly
```c
#!/usr/bin/env bpftrace

kprobe:do_mkdirat
{
  printf("PID: %d, mode: %d, filename: %s\n", pid, arg2, str(((struct filename *)arg1)->name));
}
```
The idea is to cast `arg1` to a pointer to `struct filename` before accessing `name` field.

## bpftrace Maps
Maps in bpftrace are defined with `@` such as `@testmap`. The following table is from bpftrace manual, listing bpftrace map functions along with their corresponding descriptions.

| Name    | Description                                                                                                                             |
| ------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| avg     | Calculate the running average of `n` between consecutive calls.                                                                         |
| clear   | Clear all keys/values from a map.                                                                                                       |
| count   | Count how often this function is called.                                                                                                |
| delete  | Delete a single key from a map.                                                                                                         |
| has_key | Return true (1) if the key exists in this map. Otherwise return false (0).                                                              |
| hist    | Create a log2 histogram of n using buckets per power of 2, 0 <= k <= 5, defaults to 0.                                                  |
| len     | Return the number of elements in a map.                                                                                                 |
| lhist   | Create a linear histogram of n. lhist creates M ((max - min) / step) buckets in the range [min, max) where each bucket is step in size. |
| max     | Update the map with n if n is bigger than the current value held.                                                                       |
| min     | Update the map with n if n is smaller than the current value held.                                                                      |
| stats   | Combines the count, avg and sum calls into one.                                                                                         |
| sum     | Calculate the sum of all n passed.                                                                                                      |
| zero    | Set all values for all keys to zero.                                                                                                    |

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

Let's see the previous code in bpftrace:
```c
#!/usr/bin/env bpftrace         

tracepoint:syscalls:sys_enter_fork
{
    @forks[pid] = 1;
    printf("Fork detected: PID %d\n", pid);
}

tracepoint:syscalls:sys_enter_setuid
{
    if (uid == 0)
    {
        @setuid[pid] = 1;
        printf("Setuid detected: PID %d\n", pid);
    }
}

tracepoint:syscalls:sys_enter_execve
{
    if (@forks[pid] == 1 && @setuid[pid] == 1)
    {
        printf("Privilege escalation detected: fork, setuid(0), execve, PID %d\n", pid);
        signal(9)
    }
}
```

Define a map named `forks`, and when the `sys_enter_setuid` tracepoint is triggered, insert the current `pid` as the key with a value of `1`.
```c
@forks[pid] = 1;
```

Define a map named `setuid`, and when the `sys_enter_fork` tracepoint is triggered with a UID of zero, insert the current `pid` as the key and `1` as the value.
```c
@setuid[pid] = 1;
```

If `sys_enter_execve` is triggered, then it will check if the current `pid` triggered by `sys_enter_setuid` and ``sys_enter_fork``
```c
if (@forks[pid] == 1 && @setuid[pid] == 1)
```

`signal` function is equivalent to `bpf_send_signal` helper function to terminate the process.
```c
signal(9)
```

We have to run this code with `--unsafe` because we running dangerous function which is `signal`, then to run it `sudo bpftrace --unsafe priv-esc.bt`.
This code is much smaller and simpler than eBPF kernel code, and no need for user-space code.

The next script attaches probes to the `sys_enter_read` and `sys_enter_write` syscalls (separated with comma `,`) and uses a map to count the number of system calls per process using `count()` map function.
```c
#!/usr/bin/env bpftrace

tracepoint:syscalls:sys_enter_read,
tracepoint:syscalls:sys_enter_write
{
    @syscalls[comm] = count();
}

interval:s:5 {
   printf("\033[H\033[2J");
   print(@syscalls);
}

```

This will activate every 5 seconds (using interval probe) to clear the screen using ANSI escape sequences `printf("\033[H\033[2J");`, then print the content of `syscalls` map.
```c
interval:s:5 { 
   printf("\033[H\033[2J");
   print(@syscalls);
}
```

```sh
@syscalls[systemd-timesyn]: 1
@syscalls[systemd-journal]: 1
@syscalls[systemd]: 4
@syscalls[rtkit-daemon]: 8
@syscalls[sudo]: 10
@syscalls[gnome-shell]: 13
@syscalls[gvfsd-wsdd]: 16
@syscalls[bash]: 20
@syscalls[ls]: 26
@syscalls[bpftrace]: 47
@syscalls[sshd-session]: 818
```

## bpftrace Tools

The following tools from bpftrace github repository. They cover a wide range of functions from tracing I/O and network events to monitoring process and syscall activity.

|Name|Description|
|---|---|
|bashreadline.bt|Print entered bash commands system wide. Examples.|
|biolatency.bt|Block I/O latency as a histogram. Examples.|
|biosnoop.bt|Block I/O tracing tool, showing per I/O latency. Examples.|
|biostacks.bt|Show disk I/O latency with initialization stacks. Examples.|
|bitesize.bt|Show disk I/O size as a histogram. Examples.|
|capable.bt|Trace security capability checks. Examples.|
|cpuwalk.bt|Sample which CPUs are executing processes. Examples.|
|dcsnoop.bt|Trace directory entry cache (dcache) lookups. Examples.|
|execsnoop.bt|Trace new processes via exec() syscalls. Examples.|
|gethostlatency.bt|Show latency for getaddrinfo/gethostbyname[2] calls. Examples.|
|killsnoop.bt|Trace signals issued by the kill() syscall. Examples.|
|loads.bt|Print load averages. Examples.|
|mdflush.bt|Trace md flush events. Examples.|
|naptime.bt|Show voluntary sleep calls. Examples.|
|opensnoop.bt|Trace open() syscalls showing filenames. Examples.|
|oomkill.bt|Trace OOM killer. Examples.|
|pidpersec.bt|Count new processes (via fork). Examples.|
|runqlat.bt|CPU scheduler run queue latency as a histogram. Examples.|
|runqlen.bt|CPU scheduler run queue length as a histogram. Examples.|
|setuids.bt|Trace the setuid syscalls: privilege escalation. Examples.|
|ssllatency.bt|Summarize SSL/TLS handshake latency as a histogram. Examples.|
|sslsnoop.bt|Trace SSL/TLS handshake, showing latency and return value. Examples.|
|statsnoop.bt|Trace stat() syscalls for general debugging. Examples.|
|swapin.bt|Show swapins by process. Examples.|
|syncsnoop.bt|Trace sync() variety of syscalls. Examples.|
|syscount.bt|Count system calls. Examples.|
|tcpaccept.bt|Trace TCP passive connections (accept()). Examples.|
|tcpconnect.bt|Trace TCP active connections (connect()). Examples.|
|tcpdrop.bt|Trace kernel-based TCP packet drops with details. Examples.|
|tcplife.bt|Trace TCP session lifespans with connection details. Examples.|
|tcpretrans.bt|Trace TCP retransmits. Examples.|
|tcpsynbl.bt|Show TCP SYN backlog as a histogram. Examples.|
|threadsnoop.bt|List new thread creation. Examples.|
|undump.bt|Capture UNIX domain socket packages. Examples.|
|vfscount.bt|Count VFS calls. Examples.|
|vfsstat.bt|Count some VFS calls, with per-second summaries. Examples.|
|writeback.bt|Trace file system writeback events with details. Examples.|
|xfsdist.bt|Summarize XFS operation latency distribution as a histogram. Examples.|
