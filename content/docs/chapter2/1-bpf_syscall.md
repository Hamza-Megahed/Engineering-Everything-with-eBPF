---
title: bpf() syscall
description: Single entry point the kernel exposes for loading programs, creating maps any more.
weight: 2
---

### Introduction to the bpf() System Call

The bpf() system call serves as a central mechanism in the Linux kernel for working with the Extended Berkeley Packet Filter (eBPF) subsystem. Originally introduced as a tool to filter packets in the kernel’s networking stack, Berkeley Packet Filters (BPF) allowed user space to define small programs that run efficiently in kernel space. Over time, this concept has evolved significantly from “classic” BPF (cBPF) to “extended” BPF (eBPF), which unlocks a far richer set of capabilities. The extended model supports versatile data structures, the ability to attach programs to a variety of kernel subsystems, and the invocation of helper functions that simplify complex operations.

The bpf() system call accepts a command argument determining the exact operation to be performed, and a corresponding attribute structure that passes parameters specific to that operation. Among these operations are commands to load eBPF programs into the kernel, create and manage eBPF maps, attach programs to hooks, and query or manipulate existing eBPF objects. This wide range of functionality makes bpf() a cornerstone of eBPF-based tooling in modern Linux systems.

The kernel ensures eBPF programs cannot crash or destabilize the system through rigorous static analysis at load time. As a result, the bpf() system call provides a secure yet flexible interface for extending kernel functionality.

In the **`/include/uapi/linux/bpf.h`** header file, you will find a list of all the commands used in the `bpf()` syscall. These commands define the actions that can be performed on eBPF objects, such as loading programs, creating maps, attaching programs to kernel events, and more. The commands are organized as part of the `enum bpf_cmd`, which is used as an argument to specify the desired operation when invoking the `bpf()` syscall.

Here’s an example of how the `enum bpf_cmd` is defined in the kernel source:

```c
enum bpf_cmd {
	BPF_MAP_CREATE,
	BPF_MAP_LOOKUP_ELEM,
	BPF_MAP_UPDATE_ELEM,
	BPF_MAP_DELETE_ELEM,
	BPF_MAP_GET_NEXT_KEY,
	BPF_PROG_LOAD,
	BPF_OBJ_PIN,
	BPF_OBJ_GET,
	BPF_PROG_ATTACH,
	BPF_PROG_DETACH,
	BPF_PROG_TEST_RUN,
	BPF_PROG_RUN = BPF_PROG_TEST_RUN,
	BPF_PROG_GET_NEXT_ID,
	BPF_MAP_GET_NEXT_ID,
	BPF_PROG_GET_FD_BY_ID,
	BPF_MAP_GET_FD_BY_ID,
	BPF_OBJ_GET_INFO_BY_FD,
	BPF_PROG_QUERY,
	BPF_RAW_TRACEPOINT_OPEN,
	BPF_BTF_LOAD,
	BPF_BTF_GET_FD_BY_ID,
	BPF_TASK_FD_QUERY,
	BPF_MAP_LOOKUP_AND_DELETE_ELEM,
	BPF_MAP_FREEZE,
	BPF_BTF_GET_NEXT_ID,
	BPF_MAP_LOOKUP_BATCH,
	BPF_MAP_LOOKUP_AND_DELETE_BATCH,
	BPF_MAP_UPDATE_BATCH,
	BPF_MAP_DELETE_BATCH,
	BPF_LINK_CREATE,
	BPF_LINK_UPDATE,
	BPF_LINK_GET_FD_BY_ID,
	BPF_LINK_GET_NEXT_ID,
	BPF_ENABLE_STATS,
	BPF_ITER_CREATE,
	BPF_LINK_DETACH,
	BPF_PROG_BIND_MAP,
	BPF_TOKEN_CREATE,
	__MAX_BPF_CMD,
};
```



We are not going through the full list but among these commands, one of the most important is `bpf_prog_load`. This command is used to load an eBPF program into the kernel. By invoking `bpf()` with the `BPF_PROG_LOAD` command, the kernel verifies the program’s safety, ensuring that it won’t cause any harm to the system. Upon success, the program is loaded into the kernel, and the system call returns a file descriptor associated with this eBPF program, allowing the program to be attached to various kernel events or subsystems, such as network interfaces, tracepoints, or XDP.

In the kernel’s BPF subsystem, specifically in `kernel/bpf/syscall.c`, a switch statement is used to dispatch commands defined by the enum bpf_cmd to their corresponding handler functions.
```c
	switch (cmd) {
	case BPF_MAP_CREATE:
		err = map_create(&attr);
		break;
	case BPF_MAP_LOOKUP_ELEM:
		err = map_lookup_elem(&attr);
		break;
	case BPF_MAP_UPDATE_ELEM:
		err = map_update_elem(&attr, uattr);
		break;
	case BPF_MAP_DELETE_ELEM:
		err = map_delete_elem(&attr, uattr);
		break;
	case BPF_MAP_GET_NEXT_KEY:
		err = map_get_next_key(&attr);
		break;
	case BPF_MAP_FREEZE:
		err = map_freeze(&attr);
		break;
	case BPF_PROG_LOAD:
		err = bpf_prog_load(&attr, uattr, size);
		break;
	[...]
```

Now, let’s take a closer look at how `bpf_prog_load` works in practice and how  eBPF programs can be loaded into the kernel.

### bpf_prog_load

As outlined in `man 2 bpf`, the `bpf_prog_load` operation is used to load an eBPF program into the Linux kernel via the `bpf()` syscall. When successful, this operation returns a new file descriptor associated with the loaded eBPF program. This file descriptor can then be used for operations such as attaching the program to specific kernel events (e.g., networking, tracing), checking its status, or even unloading it when necessary. The `BPF_PROG_LOAD` operation is invoked through the `bpf()` syscall to load the eBPF program into the kernel. 

```c
char bpf_log_buf[LOG_BUF_SIZE];

int bpf_prog_load(enum bpf_prog_type type,
                  const struct bpf_insn *insns, int insn_cnt,
                  const char *license)
{
    union bpf_attr attr = {
        .prog_type = type,
        .insns = ptr_to_u64(insns),
        .insn_cnt = insn_cnt,
        .license = ptr_to_u64(license),
        .log_buf = ptr_to_u64(bpf_log_buf),
        .log_size = LOG_BUF_SIZE,
        .log_level = 1,
    };

    return bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
}
```

 **Key Parameters:**
- `prog_type`: Specifies the type of eBPF program (e.g., `BPF_PROG_TYPE_XDP`, `BPF_PROG_TYPE_KPROBE`).
- `insns`: The array of eBPF instructions (bytecode) that the program consists of.
- `insn_cnt`: The number of instructions in the **`insns`** array.
- `license`: This attribute specifies the license under which the eBPF program is distributed. It is important for ensuring compatibility with kernel helper functions that are `GPL-only`. Some eBPF helpers are restricted to being used only in programs that have a GPL-compatible license. Examples of such licenses include "GPL", "GPL v2", or "Dual BSD/GPL". If the program’s license is not compatible with the GPL, it may not be allowed to invoke these specific helper functions.
- `log_buf`: A buffer where the kernel stores the verification log if the program fails verification.
- `log_size`: The size of the verification log buffer.

When a user-space process issues a `BPF_PROG_LOAD` command, the kernel invokes the `bpf_prog_load(&attr, uattr, size)` function which is defined in `kernel/bpf/syscall.c` kernel source code:
```c
static int bpf_prog_load(union bpf_attr *attr, bpfptr_t uattr, u32 uattr_size)
{
	enum bpf_prog_type type = attr->prog_type;
	struct bpf_prog *prog, *dst_prog = NULL;
	struct btf *attach_btf = NULL;
	struct bpf_token *token = NULL;
	bool bpf_cap;
	int err;
	char license[128];

    [...]
```

 **libbpf Wrapper for `bpf_prog_load`:**

To simplify working with eBPF programs, libbpf provides the `bpf_prog_load()` function, which abstracts the complexity of interacting with the kernel via the `bpf()` syscall. This wrapper is located in `/tools/lib/bpf/bpf.c` and provides additional functionality like retrying failed program loads and setting detailed log options.

```c
int bpf_prog_load(enum bpf_prog_type prog_type,
                  const char *prog_name, const char *license,
                  const struct bpf_insn *insns, size_t insn_cnt,
                  struct bpf_prog_load_opts *opts)
```

This function simplifies the process of loading eBPF programs by wrapping around the **`bpf()`** syscall, handling retries, and providing additional configuration options. `bpf_prog_load_opts` Structure:

This structure provides additional configuration options when loading an eBPF program, as seen below:

```c
struct bpf_prog_load_opts {
    size_t sz;                          // Size of this structure for compatibility
    int attempts;                        // Retry attempts if bpf() returns -EAGAIN
    enum bpf_attach_type expected_attach_type;  // Expected attachment type
    __u32 prog_btf_fd;                  // BTF file descriptor
    __u32 prog_flags;                   // Program flags
    __u32 prog_ifindex;                 // Interface index for programs like XDP
    __u32 kern_version;                  // Kernel version for compatibility
    const int *fd_array;                 // Array of file descriptors for attachments
    const void *func_info;               // Function info for BTF
    __u32 func_info_cnt;                 // Function info count
    __u32 func_info_rec_size;           // Function info record size
    const void *line_info;               // Line info for BTF
    __u32 line_info_cnt;                 // Line info count
    __u32 line_info_rec_size;           // Line info record size
    __u32 log_level;                    // Log verbosity for verifier logs
    __u32 log_size;                     // Log buffer size
    char *log_buf;                      // Log buffer
    __u32 log_true_size;                // Actual log size
    __u32 token_fd;                     // Token file descriptor (optional)
    __u32 fd_array_cnt;                 // Length of fd_array
    size_t :0;                          // Padding for compatibility
};
```

At the heart of eBPF lies the concept of eBPF maps. Maps are generic, dynamic, kernel-resident data structures accessible from both eBPF programs and user space applications. They allow you to share state and pass information between user space and eBPF code.
The Linux man page (`man 2 bpf`) states:
> "eBPF maps are a generic data structure for storage of different data types. Data types are generally treated as binary blobs. A user just specifies the size of the key and the size of the value at map-creation time."

Now, let’s dive into the world of eBPF maps and explore how these powerful data structures are created, accessed, and used within the kernel. By understanding how to interact with maps, you’ll unlock the ability to efficiently store and retrieve data across different eBPF programs.

