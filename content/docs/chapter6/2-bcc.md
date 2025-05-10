---
title: BCC
description: BPF Compiler Collection a Python and Lua toolkit that wraps Clang so you can embed small eBPF snippets in scripts and run them with just a few lines of loader code.
weight: 3
---

BCC in short  is a toolkit that makes eBPF development easier by providing a higher-level interface. It compiles your eBPF C code at runtime to match the target kernel’s data structures. BCC works with languages like Python, Lua, and C++, and includes helpful macros and shortcuts for simpler programming. Essentially, BCC takes your eBPF program as a C string, preprocesses it, and then compiles it using clang.

The following is a crash course on BCC. I strongly recommend reading the BCC manual as well—it’s incredibly detailed and covers topics that are too extensive for this chapter.
## Probes Definition
1. kprobe: `kprobe__` followed by the name of kernel function name. For example, int kprobe__do_mkdirat(struct pt_regs *ctx). struct pt_regs *ctx as a context for kprobe. Arguments can be extracted using PT_REGS_PARM1(ctx), PT_REGS_PARM2(ctx), ... macros.
2. kretprobe: `kretprobe__` followed by the name of kernel function name. For example, `int kretprobe__do_mkdirat(struct pt_regs *ctx)`. Return value can be extracted using `PT_REGS_RC(ctx)` macro.
3. uprobes: Can be declared as regular C function. For example, `int function(struct pt_regs *ctx)`. Arguments can be extracted using PT_REGS_PARM1(ctx), PT_REGS_PARM2(ctx), ... macros.
4. uretprobes: Can be declared as regular C function`int function(struct pt_regs *ctx)`. Return value can be extracted using `PT_REGS_RC(ctx)` macro.
5. Tracepoints: `TRACEPOINT_PROBE` followed by `(category, event)` . For example,  `TRACEPOINT_PROBE(sched,sched_process_exit)`. Arguments are available in an `args` struct and you can list of argument from the `format` file. Foe example, `args->pathname` in case of `TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat)`.
6. Raw Tracepoints: `RAW_TRACEPOINT_PROBE(event)`.  
For example, `RAW_TRACEPOINT_PROBE(sys_enter)`. As stated before, raw tracepoint uses `bpf_raw_tracepoint_args` as context and it has args as `args[0]` -> points to `pt_regs` structure and `args[1]` is the syscall number. To access the target functions' parameters, you can either cast `ctx->args[0]` to a pointer to a `struct pt_regs` and use it directly, or copy its contents into a local variable of type `struct pt_regs` (e.g., `struct pt_regs regs;`). Then, you can extract the syscall parameters using the `PT_REGS_PARM` macros (such as `PT_REGS_PARM1`, `PT_REGS_PARM2`, etc.).

```c
    // Copy the pt_regs structure from the raw tracepoint args.
    if (bpf_probe_read(&regs, sizeof(regs), (void *)ctx->args[0]) != 0)
        return 0;
        
    // Get the second parameter (pathname) from the registers.
    const char *pathname = (const char *)PT_REGS_PARM2(&regs);
```

7. LSM: `LSM_PROBE(hook_name,typeof(arg1), typeof(arg1)...)`. For example, to prevent creating a new directory:
```c
LSM_PROBE(path_mkdir, const struct path *dir, struct dentry *dentry, umode_t mode, int ret)
{
    bpf_trace_printk("LSM path_mkdir: mode=%d, ret=%d\n", mode, ret);
    return -1;
}
```

## Data handling

1. **bpf_probe_read_kernel** helper function with the following prototype:  
```c
int bpf_probe_read_kernel(void *dst, int size, const void *src)
```
`bpf_probe_read_kernel` is used for copying arbitrary data (e.g., structures, buffers) from kernel space and returns 0 on success.

2. **bpf_probe_read_kernel_str** helper function with the following prototype:  
```c
int bpf_probe_read_kernel_str(void *dst, int size, const void *src)
```
`bpf_probe_read_kernel_str` is used for reading null-terminated strings from kernel space and returns the length of the string including the trailing NULL on success.

3. **bpf_probe_read_user** helper function with the following prototype:  
```c
int bpf_probe_read_user(void *dst, int size, const void *src)
```
`bpf_probe_read_user` is used for copying arbitrary data (e.g., structures, buffers) from user space and returns 0 on success.

4. **bpf_probe_read_user_str** helper function with the following prototype:  
```c
int bpf_probe_read_user_str(void *dst, int size, const void *src)  
```
`bpf_probe_read_user_str` is used for reading null-terminated strings from user space and returns the length of the string including the trailing NULL on success.

5. **bpf_ktime_get_ns**: returns `u64` time elapsed since system boot in nanoseconds.
6. **bpf_get_current_pid_tgid**: returns `u64` current tgid and pid.
7. **bpf_get_current_uid_gid**: returns `u64` current pid and gid.
8. **bpf_get_current_comm(void *buf, __u32 size_of_buf)**:  copy current process name into pointer`buf` and sizeof at least 16 bytes.
For example:
```c
    char comm[TASK_COMM_LEN]; // TASK_COMM_LEN = 16, defined in include/linux/sched.h
    bpf_get_current_comm(&comm, sizeof(comm));
```

9. `bpf_get_current_task` helper function returns current task as a pointer to `struct task_struct`.

## Buffers

1. `BPF_PERF_OUTPUT(name)`: creates eBPF table to push data out to user-space using perf buffer.
2. `perf_submit`: a method of a `BPF_PERF_OUTPUT` to submit data to user-space. `perf_submit` has the following prototype: `int perf_submit((void *)ctx, (void *)data, u32 data_size)`.
3. `BPF_RINGBUF_OUTPUT`:  creates eBPF table to push data out to user-space using ring buffer. It has the following prototype `BPF_RINGBUF_OUTPUT(name, page_cnt)`, `page_cnt` is number of memory pages for ring buffer size.
4. `ringbuf_output`: a method of the `BPF_RINGBUF_OUTPUT` to submit data to user-space.`ringbuf_output` has the following prototype: `int ringbuf_output((void *)data, u64 data_size, u64 flags)`.
5. `ringbuf_reserve`: a method of the `BPF_RINGBUF_OUTPUT` to reserve a space in ring buffer and allocate data structure pointer for output data. It has the following prototype: `void* ringbuf_reserve(u64 data_size)`.
6. `ringbuf_submit`: a method of the `BPF_RINGBUF_OUTPUT` to submit data to user-space. `ringbuf_submit` has the following prototype: `void ringbuf_submit((void *)data, u64 flags)`.

## Maps

1. `BPF_HASH`: creates hash map. For example, `BPF_HASH(my_hash, u64, u64);`.
2. `BPF_ARRAY`: creates array map.

BCC has also `BPF_HISTOGRAM`, `BPF_STACK_TRACE`, `BPF_PERF_ARRAY`, `BPF_PERCPU_HASH`, `BPF_PERCPU_ARRAY`, `BPF_LPM_TRIE`,`BPF_PROG_ARRAY`, `BPF_CPUMAP`, `BPF_ARRAY_OF_MAPS` and `BPF_HASH_OF_MAPS`.

## Map Operations

1. `*val map.lookup(&key)`: return a pointer to value if exists.
2. `map.delete(&key)`: delete a key from map.
3. `map.update(&key, &val)`: updates value for a given key.
4. `map.insert(&key, &val)`: inserts a value for a given key.
5. `map.increment(key[, increment_amount])`: increments the key by `increment_amount`.

## BCC Python

1. `BPF(text=prog)`: creates eBPF object.
2. `BPF.attach_kprobe(event="event", fn_name="name")`: attach a probe into kernel function `event` and use `name` as kprobe handler.
3. `BPF.attach_kretprobe(event="event", fn_name="name")`: the same as `attach_kprobe`.
4. `BPF.attach_tracepoint(tp="tracepoint", fn_name="name")`: attach a probe into `tracepoint` and use `name` as tracepoint handler.
5. `BPF.attach_uprobe(name="location", sym="symbol", fn_name="name")`: attach a probe to`location` with `symbol`use `name` as uprobe handler. For example,
```c
b.attach_uprobe(name="/bin/bash", sym="shell_execve", fn_name="bash_exec")
```
Attach a probe to `shell_execve` symbol in binary or object file`/bin/bash`and use `bash_exec` as a handler.

6. `BPF.attach_uretprobe(name="location", sym="symbol", fn_name="name")`: the same as `attach_uprobe`.
7. `BPF.attach_raw_tracepoint(tp="tracepoint", fn_name="name")`: the same as `attach_tracepoint`.
8. `BPF.attach_xdp(dev="device", fn=b.load_func("fn_name",BPF.XDP), flags)`: attach XDP to `device`, use `fn_name` as handler for each ingress packet. Flags are defined in `include/uapi/linux/if_link.h` as the following:
```java
#define XDP_FLAGS_UPDATE_IF_NOEXIST	(1U << 0) //-->
#define XDP_FLAGS_SKB_MODE		(1U << 1)
#define XDP_FLAGS_DRV_MODE		(1U << 2)
#define XDP_FLAGS_HW_MODE		(1U << 3)
```
XDP_FLAGS_UPDATE_IF_NOEXIST	(1U << 0): This flag attaches the XDP program if there isn’t already one present. 
XDP_FLAGS_SKB_MODE (1U << 1): This flag attaches the XDP program in generic mode.
XDP_FLAGS_DRV_MODE (1U << 2): This flag attaches the XDP program in native driver mode.
XDP_FLAGS_HW_MODE (1U << 3): This flag is used for offloading the XDP program to supported hardware (NICs that support XDP offload).

9. `BPF.remove_xdp("device")`: removes XDP program from interface `device`.
10. `BPF.detach_kprobe(event="event", fn_name="name")`: detach a kprobe.
11. `BPF.detach_kretprobe(event="event", fn_name="name")`: detach a kretprobe.

## Output

1. `BPF.perf_buffer_poll(timeout=T)`: polls data from perf buffer.
2. `BPF.ring_buffer_poll(timeout=T)`: polls data from ring buffer.
3. `table.open_perf_buffer(callback, page_cnt=N, lost_cb=None)`: opens a perf ring buffer for `BPF_PERF_OUTPUT`.
4. `table.open_ring_buffer(callback, ctx=None)`: opens a buffer ring for `BPF_RINGBUF_OUTPUT`.
5. `BPF.trace_print`: reads from `/sys/kernel/debug/tracing/trace_pipe` and prints the contents.

## Examples

Let's look at example The following eBPF kernel code yo attack kprobe to `do_mkdirat` kernel function.

```c
from bcc import BPF

prog = r"""
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>

#define MAX_FILENAME_LEN 256

int kprobe__do_mkdirat(struct pt_regs *ctx)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    char fname[MAX_FILENAME_LEN] = {};

    struct filename *name = (struct filename *)PT_REGS_PARM2(ctx);
    const char *name_ptr = 0;

    bpf_probe_read(&name_ptr, sizeof(name_ptr), &name->name);

    bpf_probe_read_str(fname, sizeof(fname), name_ptr);

    umode_t mode = PT_REGS_PARM3(ctx);

    bpf_trace_printk("KPROBE ENTRY pid = %d, filename = %s, mode = %u", pid, fname, mode);
    return 0;
}
"""

b = BPF(text=prog)
print("Tracing mkdir calls... Hit Ctrl-C to exit.")
b.trace_print()
```

`bpf_trace_printk` function is similar to `bpf_printk` macro. First, we create an eBPF object from the C code using `b = BPF(text=prog)`. We don't have to add `attach_kprobe` because we followed the naming convention of kprobe which is `kprobe__` followed by the name of kernel function name `kprobe__do_mkdirat`. 
Run `sudo python3 bcc-mkdir.py`:
```sh
b'  mkdir-1706 [...] KPROBE ENTRY pid = 1706, filename = test1, mode = 511'
b'  mkdir-1708 [...] KPROBE ENTRY pid = 1708, filename = test2, mode = 511'
```

We don't have to compile because BCC compiles eBPF C code at runtime and there is no need to write a separate user-space. If you notice, the previous code is exactly similar to the following:
```c
#define __TARGET_ARCH_x86
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

SEC("kprobe/do_mkdirat")
int kprobe_mkdir(struct pt_regs *ctx)
{
    pid_t pid;
    const char *filename;
    umode_t mode;

    pid = bpf_get_current_pid_tgid() >> 32;
    struct filename *name = (struct filename *)PT_REGS_PARM2(ctx);
    filename = BPF_CORE_READ(name, name);
	mode = PT_REGS_PARM3(ctx);
   
    bpf_printk("KPROBE ENTRY pid = %d, filename = %s, mode = %u\n", pid, filename,mode);

    return 0;
}
```


Let's explore another example which uses Tracepoints with ring buffer map.
```c
from bcc import BPF

prog = """

struct event {
    u32 pid;
    char comm[16];
    char filename[256];
};

BPF_RINGBUF_OUTPUT(events, 4096);

TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat) {
    struct event *evt = events.ringbuf_reserve(sizeof(*evt));
    if (!evt)
        return 0;

    evt->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(evt->comm, sizeof(evt->comm));
    // In the tracepoint for unlinkat, the second argument (args->pathname) is the filename.
    bpf_probe_read_user_str(evt->filename, sizeof(evt->filename), args->pathname);

    events.ringbuf_submit(evt, 0);
    return 0;
}
"""

def print_event(cpu, data, size):
    event = b["events"].event(data)
    print("PID: %d, COMM: %s, File: %s" %
          (event.pid,
           event.comm.decode('utf-8'),
           event.filename.decode('utf-8')))

b = BPF(text=prog)
b["events"].open_ring_buffer(print_event)

print("Tracing unlinkat syscall... Hit Ctrl-C to end.")
while True:
    try:
        b.ring_buffer_poll(100)
    except KeyboardInterrupt:
        exit()
```

The `print_event` callback function to the ring buffer which will be called every time an event is received from the ring buffer. `print_event` takes cpu number, pointer to raw data of the event data structure defined in eBPF code and size of the event data.
```python
def print_event(cpu, data, size):
```
Then, event is defined automatically using BCC from eBPF data structure `event`:
```python
event = b["events"].event(data)
```

Then, printing out the contents of the event:
```python
print("PID: %d, COMM: %s, File: %s" %
      (event.pid,
      event.comm.decode('utf-8'),
      event.filename.decode('utf-8')))
```

Then,we create an eBPF object from the C code using `b = BPF(text=prog)`. Then, we opened the ring buffer associated with the map named `events` with callback function (`print_event`) to process data that is submitted to the ring buffer.
```python
b["events"].open_ring_buffer(print_event)
```

We don't need to use `BPF.attach_tracepoint` because we followed the naming convention for `tracepoints` which is `TRACEPOINT_PROBE(_category_, _event_)`. Finally, we start polling from the ring buffer with 100ms timeout.
```python
b.ring_buffer_poll(100)  # 100ms timeout
```

If you noticed, this code is similar to what we did in tracepoint.
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

char _license[] SEC("license") = "GPL";

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int trace_unlinkat(struct trace_event_raw_sys_enter* ctx) {
    struct event *evt;

    evt = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!evt)
        return 0;

    evt->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    bpf_probe_read_user_str(&evt->filename, sizeof(evt->filename), (const char *)ctx->args[1]);

    bpf_ringbuf_submit(evt, 0);

    return 0;
}
```


## BCC Tools

The following tables are from the BCC GitHub repository. These tables contain useful tools for different aspects of system analysis, including general tracing and debugging, memory and process monitoring, performance and timing, CPU and scheduler statistics, network and socket monitoring, as well as storage and filesystems diagnostics. Each category offers a range of tools designed to help you quickly diagnose issues, tune performance, and gather insights into system behavior using BPF-based instrumentation.

### General

|Name|Description|
|---|---|
|argdist|Display function parameter values as a histogram or frequency count.|
|bashreadline|Print entered bash commands system wide.|
|bpflist|Display processes with active BPF programs and maps.|
|capable|Trace security capability checks.|
|compactsnoop|Trace compact zone events with PID and latency.|
|criticalstat|Trace and report long atomic critical sections in the kernel.|
|deadlock|Detect potential deadlocks on a running process.|
|drsnoop|Trace direct reclaim events with PID and latency.|
|funccount|Count kernel function calls.|
|inject|Targeted error injection with call chain and predicates.|
|klockstat|Traces kernel mutex lock events and displays lock statistics.|
|opensnoop|Trace open() syscalls.|
|readahead|Show performance of read-ahead cache.|
|reset-trace|Reset the state of tracing. Maintenance tool only.|
|stackcount|Count kernel function calls and their stack traces.|
|syncsnoop|Trace sync() syscall.|
|threadsnoop|List new thread creation.|
|tplist|Display kernel tracepoints or USDT probes and their formats.|
|trace|Trace arbitrary functions, with filters.|
|ttysnoop|Watch live output from a tty or pts device.|
|ucalls|Summarize method calls or Linux syscalls in high-level languages.|
|uflow|Print a method flow graph in high-level languages.|
|ugc|Trace garbage collection events in high-level languages.|
|uobjnew|Summarize object allocation events by object type and number of bytes allocated.|
|ustat|Collect events such as GCs, thread creations, object allocations, exceptions, etc.|
|uthreads|Trace thread creation events in Java and raw pthreads.|

### Memory and Process Tools

|Name|Description|
|---|---|
|execsnoop|Trace new processes via exec() syscalls.|
|exitsnoop|Trace process termination (exit and fatal signals).|
|killsnoop|Trace signals issued by the kill() syscall.|
|kvmexit|Display the exit_reason and its statistics of each vm exit.|
|memleak|Display outstanding memory allocations to find memory leaks.|
|numasched|Track the migration of processes between NUMAs.|
|oomkill|Trace the out-of-memory (OOM) killer.|
|pidpersec|Count new processes (via fork).|
|rdmaucma|Trace RDMA Userspace Connection Manager Access events.|
|shmsnoop|Trace System V shared memory syscalls.|
|slabratetop|Kernel SLAB/SLUB memory cache allocation rate top.|

### Performance and Time Tools

|Name|Description|
|---|---|
|dbslower|Trace MySQL/PostgreSQL queries slower than a threshold.|
|dbstat|Summarize MySQL/PostgreSQL query latency as a histogram.|
|funcinterval|Time interval between the same function as a histogram.|
|funclatency|Time functions and show their latency distribution.|
|funcslower|Trace slow kernel or user function calls.|
|hardirqs|Measure hard IRQ (hard interrupt) event time.|
|mysqld_qslower|Trace MySQL server queries slower than a threshold.|
|ppchcalls|Summarize ppc hcall counts and latencies.|
|softirqs|Measure soft IRQ (soft interrupt) event time.|
|syscount|Summarize syscall counts and latencies.|

### CPU and Scheduler Tools

|Name|Description|
|---|---|
|cpudist|Summarize on- and off-CPU time per task as a histogram.|
|cpuunclaimed|Sample CPU run queues and calculate unclaimed idle CPU.|
|llcstat|Summarize CPU cache references and misses by process.|
|offcputime|Summarize off-CPU time by kernel stack trace.|
|offwaketime|Summarize blocked time by kernel off-CPU stack and waker stack.|
|profile|Profile CPU usage by sampling stack traces at a timed interval.|
|runqlat|Run queue (scheduler) latency as a histogram.|
|runqlen|Run queue length as a histogram.|
|runqslower|Trace long process scheduling delays.|
|wakeuptime|Summarize sleep-to-wakeup time by waker kernel stack.|
|wqlat|Summarize work waiting latency on workqueue.|

### Network and Sockets Tools

|Name|Description|
|---|---|
|gethostlatency|Show latency for getaddrinfo/gethostbyname[2] calls.|
|bindsnoop|Trace IPv4 and IPv6 bind() system calls (bind()).|
|netqtop|Trace and display packets distribution on NIC queues.|
|sofdsnoop|Trace FDs passed through unix sockets.|
|solisten|Trace TCP socket listen.|
|sslsniff|Sniff OpenSSL written and readed data.|
|tcpaccept|Trace TCP passive connections (accept()).|
|tcpconnect|Trace TCP active connections (connect()).|
|tcpconnlat|Trace TCP active connection latency (connect()).|
|tcpdrop|Trace kernel-based TCP packet drops with details.|
|tcplife|Trace TCP sessions and summarize lifespan.|
|tcpretrans|Trace TCP retransmits and TLPs.|
|tcprtt|Trace TCP round trip time.|
|tcpstates|Trace TCP session state changes with durations.|
|tcpsubnet|Summarize and aggregate TCP send by subnet.|
|tcpsynbl|Show TCP SYN backlog.|
|tcptop|Summarize TCP send/recv throughput by host. Top for TCP.|
|tcptracer|Trace TCP established connections (connect(), accept(), close()).|
|tcpcong|Trace TCP socket congestion control status duration.|

### Storage and Filesystems Tools

| Name       | Description                                                   |
| ---------- | ------------------------------------------------------------- |
| bitesize   | Show per process I/O size histogram.                          |
| cachestat  | Trace page cache hit/miss ratio.                              |
| cachetop   | Trace page cache hit/miss ratio by processes.                 |
| dcsnoop    | Trace directory entry cache (dcache) lookups.                 |
| dcstat     | Directory entry cache (dcache) stats.                         |
| biolatency | Summarize block device I/O latency as a histogram.            |
| biotop     | Top for disks: Summarize block device I/O by process.         |
| biopattern | Identify random/sequential disk access patterns.              |
| biosnoop   | Trace block device I/O with PID and latency.                  |
| dirtop     | File reads and writes by directory. Top for directories.      |
| filelife   | Trace the lifespan of short-lived files.                      |
| filegone   | Trace why file gone (deleted or renamed).                     |
| fileslower | Trace slow synchronous file reads and writes.                 |
| filetop    | File reads and writes by filename and process. Top for files. |
| mdflush    | Trace md flush events.                                        |
| mountsnoop | Trace mount and umount syscalls system-wide.                  |
| virtiostat | Show VIRTIO device IO statistics.                             |

### Filesystems Tools

| Name        | Description                                                    |
| ----------- | -------------------------------------------------------------- |
| btrfsdist   | Summarize btrfs operation latency distribution as a histogram. |
| btrfsslower | Trace slow btrfs operations.                                   |
| ext4dist    | Summarize ext4 operation latency distribution as a histogram.  |
| ext4slower  | Trace slow ext4 operations.                                    |
| nfsslower   | Trace slow NFS operations.                                     |
| nfsdist     | Summarize NFS operation latency distribution as a histogram.   |
| vfscount    | Count VFS calls.                                               |
| vfsstat     | Count some VFS calls, with column output.                      |
| xfsdist     | Summarize XFS operation latency distribution as a histogram.   |
| xfsslower   | Trace slow XFS operations.                                     |
| zfsdist     | Summarize ZFS operation latency distribution as a histogram.   |
| zfsslower   | Trace slow ZFS operations.                                     |
