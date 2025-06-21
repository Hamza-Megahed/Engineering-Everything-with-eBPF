---
title: eBPF Maps
description: Kernel-resident hash tables arrays LRU caches and ring buffers that store data shared between eBPF programs and user processes making stateful tasks possible.
weight: 3
---

### Introduction to eBPF Maps

One of the key design elements that make eBPF so flexible and powerful is the concept of maps. An eBPF map is a data structure residing in the kernel, accessible both by eBPF programs and user space applications. Maps provide a stable way to share state, pass configuration or lookup data, store metrics, and build more complex logic around kernel events.

Unlike traditional kernel data structures, eBPF maps are created, managed, and destroyed via well-defined syscalls and helper functions. They offer a form of persistent kernel memory to eBPF programs, ensuring that data can outlast a single function call or event. This allows administrators and developers to build sophisticated tools for tracing, networking, security, performance monitoring, and more—without modifying or recompiling the kernel.

The Linux kernel defines numerous map types (more than 30 as of this writing), each optimized for different use cases. Some store generic key-value pairs, others store arrays or are used specifically for attaching events, referencing other maps, or implementing special data structures like tries. Choosing the right map type depends on the data and the operations you need to perform.

Before we start with explaining eBPF maps, we need to install either `gcc` or `clang`, along with `libbpf-dev`, to compile our examples. These tools are essential for building and linking the necessary components for eBPF programs. On Debian and Ubuntu, you can install them using the following command:
`sudo apt install gcc libbpf-dev`

Below, we explore ten commonly used eBPF map types, detailing their conceptual purpose, common use cases, and providing code snippets demonstrating their creation using the `bpf_create_map()` API.

From the large collection defined in the kernel’s `/include/uapi/linux/bpf.h`, 
```c
enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC,
	BPF_MAP_TYPE_HASH,
	BPF_MAP_TYPE_ARRAY,
	BPF_MAP_TYPE_PROG_ARRAY,
	BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	BPF_MAP_TYPE_PERCPU_HASH,
	BPF_MAP_TYPE_PERCPU_ARRAY,
	BPF_MAP_TYPE_STACK_TRACE,
	BPF_MAP_TYPE_CGROUP_ARRAY,
	BPF_MAP_TYPE_LRU_HASH,
	BPF_MAP_TYPE_LRU_PERCPU_HASH,
	BPF_MAP_TYPE_LPM_TRIE,
	BPF_MAP_TYPE_ARRAY_OF_MAPS,
	BPF_MAP_TYPE_HASH_OF_MAPS,
	BPF_MAP_TYPE_DEVMAP,
	BPF_MAP_TYPE_SOCKMAP,
	BPF_MAP_TYPE_CPUMAP,
	BPF_MAP_TYPE_XSKMAP,
	BPF_MAP_TYPE_SOCKHASH,
	BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED,
	BPF_MAP_TYPE_CGROUP_STORAGE = BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED,
	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE_DEPRECATED,
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE_DEPRECATED,
	BPF_MAP_TYPE_QUEUE,
	BPF_MAP_TYPE_STACK,
	BPF_MAP_TYPE_SK_STORAGE,
	BPF_MAP_TYPE_DEVMAP_HASH,
	BPF_MAP_TYPE_STRUCT_OPS,
	BPF_MAP_TYPE_RINGBUF,
	BPF_MAP_TYPE_INODE_STORAGE,
	BPF_MAP_TYPE_TASK_STORAGE,
	BPF_MAP_TYPE_BLOOM_FILTER,
	BPF_MAP_TYPE_USER_RINGBUF,
	BPF_MAP_TYPE_CGRP_STORAGE,
	BPF_MAP_TYPE_ARENA,
	__MAX_BPF_MAP_TYPE
};
```

we’ll focus on these ten map types:

1. BPF_MAP_TYPE_HASH
2. BPF_MAP_TYPE_ARRAY
3. BPF_MAP_TYPE_PERF_EVENT_ARRAY
4. BPF_MAP_TYPE_PROG_ARRAY
5. BPF_MAP_TYPE_PERCPU_HASH
6. BPF_MAP_TYPE_PERCPU_ARRAY
7. BPF_MAP_TYPE_LPM_TRIE
8. BPF_MAP_TYPE_ARRAY_OF_MAPS
9. BPF_MAP_TYPE_HASH_OF_MAPS
10. BPF_MAP_TYPE_RINGBUF

These map types are either widely used or particularly illustrative of eBPF’s capabilities. Together, they represent a broad spectrum of data structures and functionalities.

### Maps in eBPF program 

In eBPF, there are two main components: the eBPF program (which runs in the kernel) and the user-space code (both components will be explained later). It is common to define maps in the eBPF program, but maps are actually created and managed in user-space using the `bpf()` syscall.

The eBPF program (kernel-side) defines how the map should look and how it will be used by the program. This definition specifies the map's type, key size, value size, and other parameters. However, the actual creation of the map (allocating memory for it in the kernel and linking it to the eBPF program) occurs in user-space. This process involves invoking the `bpf()` syscall with the `BPF_MAP_CREATE` command.

In practice, BTF (BPF Type Format) style maps are the preferred method for defining maps in eBPF programs. Using BTF provides a more flexible, type-safe way to define maps and makes it easier to manage complex data structures. We will explain BTF (BPF Type Format) later in details. When a user-space process issues a BPF_MAP_CREATE command, the kernel invokes the `map_create(&attr)` function which look like the following:
```c
static int map_create(union bpf_attr *attr)
{
	const struct bpf_map_ops *ops;
	struct bpf_token *token = NULL;
	int numa_node = bpf_map_attr_numa_node(attr);
	u32 map_type = attr->map_type;
	struct bpf_map *map;
	bool token_flag;
	int f_flags;
	[...]
```

The `bpf_map_create()` function is part of the libbpf library, which provides a user-space interface for interacting with eBPF in Linux. Internally, `bpf_map_create()` sets up the necessary parameters for creating an eBPF map and then makes a call to the `bpf()` syscall with the `BPF_MAP_CREATE` command. This function simplifies the process for the user by abstracting away the complexities of directly using the `bpf()` syscall. It configures the map, including its type, key size, value size, and the number of entries, and once these parameters are prepared, `bpf_map_create()` invokes the `bpf()` syscall with the `BPF_MAP_CREATE` command, instructing the kernel to create the eBPF map. In essence, `bpf_map_create()` serves as a user-friendly wrapper around the `bpf()` syscall's `BPF_MAP_CREATE` command or `map_create` function, making it easier for user-space programs to create eBPF maps.

`bpf_map_create()` wrapper function is defined in the Kernel source code under `tools/lib/bpf/bpf.c`. The function prototype is as follows:

```c
int bpf_map_create(enum bpf_map_type map_type,
                   const char *map_name,
                   __u32 key_size,
                   __u32 value_size,
                   __u32 max_entries,
                   const struct bpf_map_create_opts *opts);
```

- `map_type`: Specifies the type of the map (e.g., `BPF_MAP_TYPE_HASH`).
- `map_name`: The name of the map.
- `key_size`: Size of the key in the map.
- `value_size`: Size of the value in the map.
- `max_entries`: Maximum number of entries the map can hold.
- `opts`: A pointer to the `bpf_map_create_opts` structure, which contains additional options for map creation (such as flags, BTF information, etc.).

The definition for the `bpf_map_create_opts` structure, part of `libbpf`, can be found in `/tools/lib/bpf/bpf.h`

```c
struct bpf_map_create_opts {
    size_t sz;                     /* Size of this struct for forward/backward compatibility */
    __u32 btf_fd;                  /* BTF (BPF Type Format) file descriptor for type information */
    __u32 btf_key_type_id;         /* BTF key type ID for the map */
    __u32 btf_value_type_id;       /* BTF value type ID for the map */
    __u32 btf_vmlinux_value_type_id; /* BTF vmlinux value type ID for maps */
    __u32 inner_map_fd;            /* File descriptor for an inner map (for nested maps) */
    __u32 map_flags;               /* Flags for the map (e.g., read-only, etc.) */
    __u64 map_extra;               /* Extra space for future expansion or additional settings */
    __u32 numa_node;               /* NUMA node to assign the map */
    __u32 map_ifindex;             /* Network interface index for map assignment */
    __s32 value_type_btf_obj_fd;   /* File descriptor for the BTF object corresponding to the value type */
    __u32 token_fd;                /* BPF token FD passed in a corresponding command's token_fd field */
    size_t :0;                      /* Reserved for future compatibility (bitfield) */
};
```

- `sz`: Size of the structure, ensuring forward/backward compatibility.
- `btf_fd`, `btf_key_type_id`, `btf_value_type_id`, and `btf_vmlinux_value_type_id`: These fields are related to the `BPF Type Format` (BTF), which provides type information for the map’s key and value types
- `inner_map_fd`: The file descriptor of an inner map if the map is being used as part of a nested structure.
- `map_flags`: Flags that modify the behavior of the map, such as setting the map to read-only or enabling special features (e.g., memory-mapping).
- `map_extra`: Reserved for future extensions to the structure or additional configuration.
- `numa_node`: Specifies the NUMA node for memory locality when creating the map (used for NUMA-aware systems).
- `map_ifindex`: Specifies the network interface index for associating the map with a specific network interface.
- `value_type_btf_obj_fd`: A file descriptor pointing to the BTF object representing the map’s value type.
- `token_fd`: A token FD for passing file descriptors across different BPF operations.

These fields allow for fine-grained control over how the eBPF map behaves, including its memory allocation, access permissions, and type information. Don't worry about these details now, as some of them will be used shortly when we dive into more examples.

Now that we've covered the basics of map creation, let’s start exploring some of the most commonly used eBPF map types. 
{{< alert title="Note" >}}All the following snippets of code use different contexts for working with the same BPF map. "The Map Definition in eBPF Program" snippet is used within the eBPF kernel code to declare the map (using section annotations like `SEC(".maps")`) so that the eBPF program can use it. The "Hash Map User-Space Example snippet", on the other hand, shows how user-space code (using libbpf and BPF syscalls) can interact with the map—such as creating or obtaining a file descriptor for the map.{{< /alert >}}

### 1. Hash Map

A hash map stores key-value pairs. Each key maps to a corresponding value, and both the key and value have fixed sizes determined at creation time. The hash map provides fast lookups and updates, making it a great choice for data that changes frequently. Common uses include tracking connection states in networking, counting events keyed by process ID or file descriptor, or caching metadata for quick lookups.

<p style="text-align: center;">
  <img src="/images/docs/chapter2/hash-map.png" alt="Centered image" />
</p>

**BTF Map Definition in eBPF Program**

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, 1024);
} hash_map_example SEC(".maps");
```


**Hash Map User-Space Example**

```c
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <unistd.h>

int create_hash_map(void) {
    int fd = bpf_map_create(BPF_MAP_TYPE_HASH, "hash_map_example",
                            sizeof(int),      // key_size
                            sizeof(int),     // value_size
                            1024,             // max_entries
                            NULL);               // map_flags
    if (fd < 0) {
        fprintf(stderr, "Failed to create hash map: %s\n", strerror(errno));
    }
    return fd;
}

int main() {
    int fd = create_hash_map();
    if (fd >= 0) {
        printf("Hash map created successfully with fd: %d\n", fd);
        close(fd);
    }
    return 0;
}
```

We can compile it using `gcc -o hash_map hash_map.c -lbpf` and `-lbpf` which tells the compiler to link against the `libbpf` library, or by using `clang -o ring_buff ring_buff.c -lbpf`
{{< alert title="Note" >}}You should always use `close()` when you're done using a BPF map file descriptor to ensure proper resource management, prevent resource leaks, and allow the system to release the map's resources.
{{< /alert >}}
{{< alert title="Note" >}}Loading most eBPF programs into the kernel requires root privileges, as they require access to restricted kernel resources and system calls. However, it's possible for non-root users to load eBPF programs if they have been granted specific capabilities, such as `CAP_BPF`.
{{< /alert >}}

To run this program, you need to use the sudo command`sudo ./hash_map`


### 2. Array Map

An array map stores a fixed number of elements indexed by integer keys. Unlike a hash map, array keys are not arbitrary—they are simply indexes from 0 to max_entries -1. This simplifies lookups and can provide stable, predictable memory usage. Array maps are perfect for scenarios where you know the exact number of elements you need and require constant-time indexed access. Typical uses include lookup tables, static configuration data, or indexing CPU-related counters by CPU number.

<p style="text-align: center;">
  <img src="/images/docs/chapter2/array-map.png" alt="Centered image" />
</p>

**BTF Map Definition in eBPF Program**

```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, 256);
} array_map_example SEC(".maps");
```


**Array Map User-Space Example**

```c
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <unistd.h>

int create_array_map(void) {
    int fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "array_map_example",
                            sizeof(int),   // key_size
                            sizeof(int),  // value_size
                            256,           // max_entries
                            NULL);            // map_flags
    if (fd < 0) {
        fprintf(stderr, "Failed to create array map: %s\n", strerror(errno));
    }
    return fd;
}

int main() {
    int fd = create_array_map();
    if (fd >= 0) {
        printf("Array map created successfully with fd: %d\n", fd);
        close(fd);
    }
    return 0;
}
```

### 3. Perf Event Array Map

The Perf Event Array map provides a mechanism to redirect perf events (such as hardware counters or software events) into user space using the perf ring buffer infrastructure. By attaching eBPF programs to perf events and using this map, you can efficiently gather performance metrics from the kernel, making it a cornerstone of low-overhead performance monitoring and observability tools.

<p style="text-align: center;">
  <img src="/images/docs/chapter2/perf-event-map.png" alt="Centered image" />
</p>

**BTF Map Definition in eBPF Program**

```c
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, 64);
} perf_event_array_example SEC(".maps");
```
{{< alert title="Note" >}}You can ignore `max_entries` as it will be set automatically to the number of CPUs on your computer by `libbpf` as per https://nakryiko.com/posts/bpf-ringbuf/.{{< /alert >}}

**Pert Event Array Map User-Space Example**

```c
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <unistd.h>

int create_perf_event_array_map(void) {
    int fd = bpf_map_create(BPF_MAP_TYPE_PERF_EVENT_ARRAY, "perf_event_array_example",
                            sizeof(int),   // key_size
                            sizeof(int),   // value_size (fd)
                            64,            // max_entries (for events)
                            NULL);            // map_flags
    if (fd < 0) {
        fprintf(stderr, "Failed to create perf event array map: %s\n", strerror(errno));
    }
    return fd;
}

int main() {
    int fd = create_perf_event_array_map();
    if (fd >= 0) {
        printf("perf event array map created successfully with fd: %d\n", fd);
        close(fd);
    }
    return 0;
}
```

### 4. Prog Array Map

A program array holds references to other eBPF programs, enabling tail calls. Tail calls allow one eBPF program to jump into another without returning, effectively chaining multiple programs into a pipeline. This map type is essential for building modular and dynamic eBPF toolchains that can be reconfigured at runtime without reloading the entire set of programs.

<p style="text-align: center;">
  <img src="/images/docs/chapter2/prog-array-map.png" alt="Centered image" />
</p>

**BTF Map Definition in eBPF Program**

```c
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, 32);
} prog_array_example SEC(".maps");
```

**Prog Array Map User-Space Example**

```c
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <unistd.h>

int create_prog_array_map(void) {
    int fd = bpf_map_create(BPF_MAP_TYPE_PROG_ARRAY, "prog_array_example",
                            sizeof(int), // key_size
                            sizeof(int), // value_size (prog FD)
                            32,          // max_entries
                            NULL);
    if (fd < 0) {
        fprintf(stderr, "Failed to create prog array map: %s\n", strerror(errno));
    }
    return fd;
}

int main() {
    int fd = create_prog_array_map();
    if (fd >= 0) {
        printf("Prog array map created successfully with fd: %d\n", fd);
        close(fd);
    }
    return 0;
}
```

### 5. PERCPU Hash Map

A per-CPU hash map is similar to a standard hash map but stores distinct values for each CPU. This design minimizes lock contention and cache-line ping-ponging, allowing for extremely high-performance counting or state tracking when updates are frequent. Each CPU updates its own version of the value, and user space can aggregate these values later.

<p style="text-align: center;">
  <img src="/images/docs/chapter2/percpu-hash-map.png" alt="Centered image" />
</p>

**BTF Map Definition in eBPF Program**

```c
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, 1024);
} percpu_hash_example SEC(".maps");
```

**PERCPU Hash Map User-Space Example**

```c
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <unistd.h>

int create_percpu_hash_map(void) {
    int fd = bpf_map_create(BPF_MAP_TYPE_PERCPU_HASH, "percpu_hash_example",
                            sizeof(int),    // key_size
                            sizeof(int),   // value_size
                            1024,           // max_entries
                            NULL);
    if (fd < 0) {
        fprintf(stderr, "Failed to create PERCPU hash map: %s\n", strerror(errno));
    }
    return fd;
}

int main() {
    int fd = create_percpu_hash_map();
    if (fd >= 0) {
        printf("PERCPU hash map created successfully with fd: %d\n", fd);
        close(fd);
    }
    return 0;
}
```


### 6. PERCPU Array Map

A per-CPU array, like the per-CPU hash, stores distinct copies of array elements for each CPU. This further reduces contention, making it ideal for per-CPU statistics counters, histograms, or other metrics that need to be incremented frequently without facing synchronization overhead.

<p style="text-align: center;">
  <img src="/images/docs/chapter2/percpu-array-map.png" alt="Centered image" />
</p>

**BTF Map Definition in eBPF Program**

```c
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, 1024);
} percpu_array_example SEC(".maps");
```

**PERCPU Array Map User-Space Example**

```c
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <unistd.h>

int create_percpu_array_map(void) {
    int fd = bpf_map_create(BPF_MAP_TYPE_PERCPU_ARRAY, "percpu_array_example",
                            sizeof(int),    // key_size
                            sizeof(int),   // value_size
                            128,            // max_entries
                            NULL);
    if (fd < 0) {
        fprintf(stderr, "Failed to create PERCPU array map: %s\n", strerror(errno));
    }
    return fd;
}

int main() {
    int fd = create_percpu_array_map();
    if (fd >= 0) {
        printf("PERCPU array map created successfully with fd: %d\n", fd);
        close(fd);
    }
    return 0;
}
```

### 7. LPM Trie Map

The LPM (Longest Prefix Match) Trie map is designed for prefix-based lookups, commonly used in networking. For example, you might store IP prefixes (like CIDR blocks) and quickly determine which prefix best matches a given IP address. This is useful for routing, firewall rules, or policy decisions based on IP addresses.

{{< alert title="Note" >}}When creating an LPM Trie map, it is important to use the `BPF_F_NO_PREALLOC` flag. This flag prevents the kernel from pre-allocating memory for all entries at map creation time, allowing the map to dynamically allocate memory as needed.{{< /alert >}}

For example, if you create a map that is intended to hold 1,000 entries, the kernel might allocate memory for all 1,000 entries at map creation time. However, in the case of an LPM Trie map, the situation is different. An LPM Trie map is used for prefix-based lookups, such as storing CIDR blocks or IP address prefixes for example `192.168.0.0/24`. The number of entries and the amount of memory required for the map can vary depending on the data stored. You can still specify a `max_entries` value when creating an LPM Trie map, but it is important to note that the kernel will ignore this value. The actual number of entries in an LPM Trie map depends on how many prefixes are inserted, and the map dynamically allocates memory based on the prefixes.

<p style="text-align: center;">
  <img src="/images/docs/chapter2/lpm-trie-map.png" alt="Centered image" />
</p>

**BTF Map Definition in eBPF Program**

```c
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, 1024);
} lpm_trie_example SEC(".maps");
```

**LPM Trie Map User-Space Example**

```c
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <unistd.h>

int create_lpm_trie_map(void) {

    struct bpf_map_create_opts opts = {0};
    opts.sz = sizeof(opts);
    opts.map_flags = BPF_F_NO_PREALLOC;

    int fd = bpf_map_create(BPF_MAP_TYPE_LPM_TRIE, "lpm_trie_example",
                            8,     // key_size
                            sizeof(long), // value_size
                            1024,  // max_entries and it will ignored
                            &opts);
    if (fd < 0) {
        fprintf(stderr, "Failed to create LMP trie map: %s\n", strerror(errno));
    }
    return fd;
}

int main() {
    int fd = create_lpm_trie_map();
    if (fd >= 0) {
        printf("LMP trie map created successfully with fd: %d\n", fd);
        close(fd);
    }
    return 0;
}
```


### 8. Array of Maps Map

An array-of-maps stores references to other maps. Each element in this array is itself a map FD. This structure allows building hierarchical or modular configurations. For example, you might keep a set of hash maps, each representing a different tenant or set of rules, and select which one to use at runtime by indexing into the array-of-maps. 
In the following example, we will first create a hash map to serve as the inner map, and then use this hash map as the reference for creating an array of maps.

<p style="text-align: center;">
  <img src="/images/docs/chapter2/array-of-maps.png" alt="Centered image" />
</p>

**BTF Map Definition in eBPF Program**

```c
struct inner_map {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, 1024);
} hash_map_example SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS); 
    __type(key, int);
    __type(value, int);
    __uint(max_entries, 4);    
    __array(values, struct { 
        __uint(type, BPF_MAP_TYPE_HASH);
        __type(key, int);
        __type(value, int);
        __uint(max_entries, 1024);
    });
} array_of_maps_map_example SEC(".maps");
```


**Array of Maps Map User-Space Example**

```c
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <unistd.h>

int create_inner_hash_map(void) {
    int fd = bpf_map_create(BPF_MAP_TYPE_HASH, "hash_map_example",
                            sizeof(int),      // key_size
                            sizeof(int),     // value_size
                            1024,             // max_entries
                            NULL);               // map_flags
    if (fd < 0) {
        fprintf(stderr, "Failed to create hash map: %s\n", strerror(errno));
    }
    return fd;
}

int create_array_of_maps(int inner_map_fd) {
    struct bpf_map_create_opts opts = {0};
    opts.sz = sizeof(opts);
    opts.inner_map_fd = inner_map_fd;  // Specify the inner map FD
   
    int fd = bpf_map_create(BPF_MAP_TYPE_ARRAY_OF_MAPS, "array_of_maps_map_example",
                            sizeof(int),  // key_size
                            sizeof(int),  // value_size (placeholder for map FD)
                            4,            // max_entries
                            &opts);
    if (fd < 0) {
        fprintf(stderr, "Failed to create Array of maps map: %s\n", strerror(errno));
    }
    return fd;
}

int main() {
	// Step 1: Create the inner hash map
    int inner_map_fd = create_inner_hash_map();
    if (inner_map_fd >= 0) {
        printf("Hash map created successfully with fd: %d\n", inner_map_fd);
        close(inner_map_fd);
    }

    // Step 2: Create the array of maps, using the inner map FD
    int array_of_maps_fd = create_array_of_maps(inner_map_fd);
    if (array_of_maps_fd >= 0) {
        printf("Array of maps map created successfully with fd: %d\n", array_of_maps_fd);
        close(array_of_maps_fd);
    }

    if (inner_map_fd >= 0) {
        close(inner_map_fd);
    }
    if (array_of_maps_fd >= 0) {
        close(array_of_maps_fd);
    }
    return 0;
}
```

### 9. Hash of Maps Maps

A hash-of-maps extends the concept of array-of-maps to dynamic keying. Instead of indexing by integer, you can use arbitrary keys to select which map is referenced. This allows flexible and dynamic grouping of maps, where user space can manage complex configurations by updating keys and associated map FDs. Again, `bpf_create_map()` cannot set `inner_map_fd`, so this example is minimal.

<p style="text-align: center;">
  <img src="/images/docs/chapter2/hash-of-maps.png" alt="Centered image" />
</p>

**BTF Map Definition in eBPF Program**

```c
struct inner_map {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, 1024);
} hash_map_example SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS); 
    __type(key, int);
    __type(value, int);
    __uint(max_entries, 4);    
    __array(values, struct { 
        __uint(type, BPF_MAP_TYPE_HASH);
        __type(key, int);
        __type(value, int);
        __uint(max_entries, 1024);
    });
} hash_of_maps_map_example SEC(".maps");
```

**Hash of Maps Map User-Space Example**

```c
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <unistd.h>

int create_inner_hash_map(void) {
    int fd = bpf_map_create(BPF_MAP_TYPE_HASH, "hash_map_example",
                            sizeof(int),      // key_size
                            sizeof(int),     // value_size
                            1024,             // max_entries
                            NULL);               // map_flags
    if (fd < 0) {
        fprintf(stderr, "Failed to create hash map: %s\n", strerror(errno));
    }
    return fd;
}

int create_hash_of_maps(int inner_map_fd) {
    struct bpf_map_create_opts opts = {0};
    opts.sz = sizeof(opts);
    opts.inner_map_fd = inner_map_fd;  // Specify the inner map FD

    int fd = bpf_map_create(BPF_MAP_TYPE_HASH_OF_MAPS, "hash_of_maps_map_example",
                            sizeof(int),  // key_size
                            sizeof(int),  // value_size (placeholder for map FD)
                            4,            // max_entries
                            &opts);
    if (fd < 0) {
        fprintf(stderr, "Failed to create hash of maps map: %s\n", strerror(errno));
    }
    return fd;
}

int main() {
	// Step 1: Create the inner hash map
    int inner_map_fd = create_inner_hash_map();
    if (inner_map_fd >= 0) {
        printf("Hash map created successfully with fd: %d\n", inner_map_fd);
    }

    // Step 2: Create the array of maps, using the inner map FD
    int array_of_maps_fd = create_hash_of_maps(inner_map_fd);
    if (array_of_maps_fd >= 0) {
        printf("Array_of_maps map created successfully with fd: %d\n", array_of_maps_fd);
    }
 
    if (inner_map_fd >= 0) {
        close(inner_map_fd);
    }
    if (array_of_maps_fd >= 0) {
        close(array_of_maps_fd);
    }
    return 0;
}
```

### 10. Ring Buffer Map

The ring buffer map is a relatively new addition that enables lock-free communication from kernel to user space. Instead of performing lookups or updates for each record, the kernel-side eBPF program writes events into the ring buffer, and user space reads them as a continuous stream. A ring buffer is a circular data structure that uses a continuous block of memory to store data sequentially. When data is added to the buffer and the end is reached, new data wraps around to the beginning, potentially overwriting older data if it hasn't been read yet.  
A typical ring buffer uses two pointers (or "heads"): one for writing and one for reading. The write pointer marks where new data is added, while the read pointer indicates where data should be consumed. This dual-pointer system allows for efficient and concurrent operations, ensuring that the writer doesn't overwrite data before the reader has processed it. Additionally, the ring buffer is shared across all CPUs, consolidating events from multiple cores into a single stream. This greatly reduces overhead for high-volume event reporting, making it ideal for profiling, tracing, or continuous monitoring tools.

<p style="text-align: center;">
  <img src="/images/docs/chapter2/ring-buffer.png" alt="Centered image" />
</p>

**BTF Map Definition in eBPF Program**

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096); //It must be a power of 2
} ring_buffer_map_example SEC(".maps");
```
{{< alert title="Note" >}}`max_entries` in `BPF_MAP_TYPE_RINGBUF` must be a power of 2 such as `4096`.{{< /alert >}}

**Ring Buffer Map User-Space Example**

```c
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <unistd.h>

int create_ringbuf_map(void) {
    // The size of the ringbuf is given in bytes by max_entries.
    int fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, "ring_buffer_map_example",
                            0,    // key_size = 0 for ringbuf
                            0,    // value_size = 0 for ringbuf
                            4096,
                            NULL);
    if (fd < 0) {
        fprintf(stderr, "Failed to create ring buffer map: %s\n", strerror(errno));
    }
    return fd;
}

int main() {
    int fd = create_ringbuf_map();
    if (fd >= 0) {
        printf("Ring buffer map created successfully with fd: %d\n", fd);
        close(fd);
    }
    return 0;
}
```

### The Right eBPF Map Type

By combining these map types with your eBPF programs, you can build sophisticated, runtime-configurable kernel instrumentation, security monitors, network traffic analyzers, and performance profiling tools. Each map type adds a new capability or performance characteristic, allowing developers to craft solutions that were previously challenging or impossible without kernel modifications. This flexibility not only enhances existing solutions but also opens up new possibilities for kernel-level programming. Given the ongoing evolution of eBPF, selecting the right map type for your use case becomes even more important. When doing so, it's essential to consider factors such as access patterns, data size, performance requirements, and the complexity of your architecture. Here are some things to keep in mind:

- **Access Pattern and Data Size**:
    If you have a known, fixed number of entries indexed by integer keys, the ideal choice might be a `BPF_MAP_TYPE_ARRAY`. If keys are dynamic or unpredictable, `BPF_MAP_TYPE_HASH` might be the go-to.
- **Performance and Concurrency**:
    Under heavy load, where multiple CPUs frequently update shared data, per-CPU maps (`BPF_MAP_TYPE_PERCPU_HASH` or `BPF_MAP_TYPE_PERCPU_ARRAY`) can reduce contention. Similarly, `BPF_MAP_TYPE_RINGBUF` is the perfect fit for high-throughput streaming scenarios.
- **Complexity and Modularity**:
    If you need to dynamically chain programs or manage multiple maps at runtime, you could use `BPF_MAP_TYPE_PROG_ARRAY`, `BPF_MAP_TYPE_ARRAY_OF_MAPS`, or `BPF_MAP_TYPE_HASH_OF_MAPS` to facilitate more sophisticated architectures.
- **Networking and Prefix Matching**:
    For IP-based lookups, `BPF_MAP_TYPE_LPM_TRIE` offers a specialized structure optimized for network prefixes and routing logic.
- **Observability and Tracing**:
    `BPF_MAP_TYPE_PERF_EVENT_ARRAY` ties into the Linux perf subsystem, enabling advanced performance monitoring and event correlation in conjunction with eBPF programs.


