---
title: eBPF Map Operations
description: Create read update delete batch pin freeze everything you need to manage maps.
weight: 4
---

## eBPF Map Operations Overview

eBPF map operations are a set of functions defined in the Linux kernel that allow interaction with eBPF maps. These operations enable reading, writing, deleting, and managing data within the maps. The operations are part of the `bpf_cmd` defined in the kernel source file `/include/uapi/linux/bpf.h`. Some commonly used operations include:
- `BPF_MAP_CREATE`: Creates a new eBPF map. This operation sets up a map.
- `BPF_MAP_UPDATE_ELEM`: Inserts or updates a key-value pair.
- `BPF_MAP_LOOKUP_ELEM`: Retrieves the value associated with a given key.
- `BPF_MAP_DELETE_ELEM`: Deletes a key-value pair by its key.
- `BPF_MAP_LOOKUP_AND_DELETE_ELEM`: Retrieves a value by key and deletes the entry in one step.
- `BPF_MAP_GET_NEXT_KEY`: Iterates through the keys in the map.
- `BPF_MAP_LOOKUP_BATCH`: Retrieves multiple entries in a single call.
- `BPF_MAP_UPDATE_BATCH`: Updates multiple entries at once.
- `BPF_MAP_DELETE_BATCH`: Deletes multiple entries in one operation.
- `BPF_MAP_FREEZE`: Converts the map into a read-only state.
- `BPF_OBJ_PIN`: Pins the map to the BPF filesystem so it persists beyond the process's lifetime.
- `BPF_OBJ_GET`: Retrieves a previously pinned map.

These operations allow efficient data sharing between eBPF programs and user-space applications. The `bpf()` syscall is used to perform these operations, providing a flexible interface for interacting with eBPF maps. Each operation serves a specific purpose. 

In this chapter, we have already explained `BPF_MAP_CREATE` in detail , so we will not cover it again. Instead, we will focus on the rest. We will show how to use them with a simple hash map and explain the code thoroughly.

Some map operations differ between user-space and kernel-space code. In user-space, you interact with eBPF maps using file descriptors and functions that often require an output parameter, Libbpf provides convenient wrappers for these commands which are defined in tools/lib/bpf/bpf.c. 
```c
int bpf_map_update_elem(int fd, const void *key, const void *value,
			__u64 flags)
{
	const size_t attr_sz = offsetofend(union bpf_attr, flags);
	union bpf_attr attr;
	int ret;

	memset(&attr, 0, attr_sz);
	attr.map_fd = fd;
	attr.key = ptr_to_u64(key);
	attr.value = ptr_to_u64(value);
	attr.flags = flags;

	ret = sys_bpf(BPF_MAP_UPDATE_ELEM, &attr, attr_sz);
	return libbpf_err_errno(ret);
}

int bpf_map_lookup_elem(int fd, const void *key, void *value)
{
	const size_t attr_sz = offsetofend(union bpf_attr, flags);
	union bpf_attr attr;
	int ret;

	memset(&attr, 0, attr_sz);
	attr.map_fd = fd;
	attr.key = ptr_to_u64(key);
	attr.value = ptr_to_u64(value);

	ret = sys_bpf(BPF_MAP_LOOKUP_ELEM, &attr, attr_sz);
	return libbpf_err_errno(ret);
}
[...]
```

whereas in kernel-space (within eBPF programs) perform equivalent operations using built-in helper functions which are defined in `kernel/bpf/helpers.c`.
```c
BPF_CALL_2(bpf_map_lookup_elem, struct bpf_map *, map, void *, key)
{
	WARN_ON_ONCE(!rcu_read_lock_held() && !rcu_read_lock_trace_held() &&
		     !rcu_read_lock_bh_held());
	return (unsigned long) map->ops->map_lookup_elem(map, key);
}

const struct bpf_func_proto bpf_map_lookup_elem_proto = {
	.func		= bpf_map_lookup_elem,
	.gpl_only	= false,
	.pkt_access	= true,
	.ret_type	= RET_PTR_TO_MAP_VALUE_OR_NULL,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_MAP_KEY,
};

BPF_CALL_4(bpf_map_update_elem, struct bpf_map *, map, void *, key,
	   void *, value, u64, flags)
{
	WARN_ON_ONCE(!rcu_read_lock_held() && !rcu_read_lock_trace_held() &&
		     !rcu_read_lock_bh_held());
	return map->ops->map_update_elem(map, key, value, flags);
}
```
Additionally, some operations—like batch operations and object pinning/getting—are implemented in the kernel but are intended to be invoked from user-space via system calls or libbpf rather than being used directly inside eBPF programs. We'll explain each operation in both contexts.

## 1. Map Update Element 

### User-Space code 
`BPF_MAP_UPDATE_ELEM` command inserts or updates a key-value pair in the map.
The function `bpf_map_update_elem` is a libbpf wrapper for `BPF_MAP_UPDATE_ELEM` command, it's part of the libbpf library, which provides a user-space interface for interacting with eBPF maps in the Linux kernel with prototype as follows:
```c
int bpf_map_update_elem(int fd, const void *key, const void *value, __u64 flags);
```
It takes a map file descriptor, pointers to the key and value, and a flag indicating how the update should be performed. The flag can be 
1. `BPF_NOEXIST` to insert only if the key does not exist.
2. `BPF_EXIST` to update only if the key already exists.
3. `BPF_ANY` to insert or update unconditionally.
On success, this call returns zero. On failure, it returns -1 and sets `errno` to indicate the cause of the error. For instance, if you use `BPF_NOEXIST` but the key already exists, it returns `EEXIST`. If you use `BPF_EXIST` but the key does not exist, it returns `ENOENT` which is `No such file or directory`.

{{< alert title="Note" >}}`BPF_NOEXIST` isn't supported for array type maps since all keys always exist.{{< /alert >}}

Here is an example that first tries to insert a new element using `BPF_NOEXIST` and then updates it using `BPF_EXIST`:

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
                            NULL);            // map_flags
    if (fd < 0) {
        fprintf(stderr, "Failed to create hash map: %s\n", strerror(errno));
    }
    return fd;
}

int main() {
    int fd = create_hash_map();
    if (fd >= 0) {
        printf("Hash map created successfully with fd: %d\n", fd);

        // Insert elements in the hash map
        int key = 5;
        long value = 100;
        if (bpf_map_update_elem(fd, &key, &value, BPF_ANY) == 0) {  // BPF_ANY means insert or update
            printf("Element inserted or updated successfully: key = %d, value = %ld\n", key, value);
        } else {
            fprintf(stderr, "Failed to insert or update element: %s\n", strerror(errno));
            close(fd);  // Close the map before returning
            return -1;
        }

        // Update an element in the hash map
        value = 200;
        if (bpf_map_update_elem(fd, &key, &value, BPF_EXIST) == 0) { 
            printf("Element inserted or updated successfully: key = %d, value = %ld\n", key, value);
        } else {
            fprintf(stderr, "Failed to insert or update element: %s\n", strerror(errno));
            close(fd);  // Close the map before returning
            return -1;
        }

        // Update an element that doesn't exist in the hash map
        key = 4;
        value = 300;
        if (bpf_map_update_elem(fd, &key, &value, BPF_EXIST) == 0) { 
            printf("Element inserted or updated successfully: key = %d, value = %ld\n", key, value);
        } else {
            fprintf(stderr, "Failed to insert or update element: %s\n", strerror(errno));
            close(fd);  // Close the map before returning
            return -1;
        }
        close(fd);
        return 0;
    }
    return -1;
}

```

To compile and run the program, use the following command: `gcc -o update-ebpf-map update-ebpf-map.c -lbpf`.
Then, execute the program with: `sudo ./update-ebpf-map`.
We first create a map and then insert `(5 -> 100)` using `BPF_ANY`, which either inserts or updates unconditionally. Since the map was empty, `(5 -> 100)` is inserted. Next, we update `(5 -> 100)` to `(5 -> 200)` using `BPF_EXIST`, ensuring that the key must exist beforehand. The operation succeeds, and the value associated with key `5` is now `200`.
Then, we try to insert `(4 -> 300)` using `BPF_EXIST`, which requires the key to already exist in the map. Since the key `4` does not exist in the map, the operation fails, and the error `ENOENT` is triggered, resulting in the message "Failed to insert or update element: No such file or directory."
The output from running the program (`sudo ./update-ebpf-map`) is as follows:

```sh
Hash map created successfully with fd: 3
Element inserted or updated successfully: key = 5, value = 100
Element inserted or updated successfully: key = 5, value = 200
Failed to insert or update element: No such file or directory
```

### Kernel-Space code

```c
int bpf_map_update_elem(void *map, const void *key, const void *value, __u64 flags);
```

## 2. Map Lookup Element

### User-Space code
`BPF_MAP_LOOKUP_ELEM` command is used to retrieve the value associated with a given key. The `bpf_map_lookup_elem` function is a libbpf wrapper for `BPF_MAP_LOOKUP_ELEM` command and its prototype is : `int bpf_map_lookup_elem(int fd, const void *key, void *value)` , so you provide the map’s file descriptor, a pointer to the key you want to look up, and a pointer to a buffer where the value will be stored if the key is found. If the operation succeeds, it returns zero, and the value is copied into the user-provided buffer. If the key does not exist, it returns -1 and sets `errno` to `ENOENT`.

Consider a scenario where you have inserted an entry `(key=10, value=100)` into the map. Looking it up would look like this:

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
                            NULL);            // map_flags
    if (fd < 0) {
        fprintf(stderr, "Failed to create hash map: %s\n", strerror(errno));
    }
    return fd;
}

int main() {
    int fd = create_hash_map();
    if (fd >= 0) {
        printf("Hash map created successfully with fd: %d\n", fd);
        
        // Insert a single entry: (10 -> 100)
        int key = 10;
        int value = 100;
        if (bpf_map_update_elem(fd, &key, &value, BPF_ANY) == 0) {
            printf("Element inserted or updated successfully: key = %d, value = %ld\n", key, value);
        } else {
            fprintf(stderr, "Failed to insert or update element: %s\n", strerror(errno));
            close(fd);
            return -1;
        }
    
        // Attempt to look up the value for key=10
        int lookup_key = 10;
        int lookup_val = 0;
        if (bpf_map_lookup_elem(fd, &lookup_key, &lookup_val) == 0) {
            printf("Found value %d for key %d\n", lookup_val, lookup_key);
        } else {
            fprintf(stderr, "Element doesn't exist: %s\n", strerror(errno));
            close(fd);
            return -1;
        }
        
        // Attempt to look up a value that doesn't exist 
        lookup_key = 11;
        lookup_val = 0;
        if (bpf_map_lookup_elem(fd, &lookup_key, &lookup_val) == 0) {
            printf("Found value %d for key %d\n", lookup_val, lookup_key);
        } else {
            fprintf(stderr, "Element doesn't exist: %s\n", strerror(errno));
            close(fd);
            return -1;
        }   
        close(fd);
        return 0;
    }
    return -1;
}
```

In this example, we first create a hash map, then insert `(10 -> 100)` into it. When we call `bpf_map_lookup_elem` with `lookup_key=10`, the kernel checks the map for this key. Since it exists, `lookup_val` is set to `100` and the function returns zero. If the key had not existed, `bpf_map_lookup_elem` would return `-1` and set `errno=ENOENT` and the output should look like:
```sh
Hash map created successfully with fd: 3
Element inserted or updated successfully: key = 10, value = 100
Found value 100 for key 10
Element doesn't exist: No such file or directory
```

This operation allows you to query the map and read the data it contains without modifying it. If the map is empty or does not contain the requested key, `bpf_map_lookup_elem` simply fails and sets an appropriate error code.

### Kernel-Space code

```c
void *bpf_map_lookup_elem(const void *map, const void *key);
```

## 3. Map Delete Element

### User-Space code

`BPF_MAP_DELETE_ELEM` command removes a key-value pair from the map.
The `bpf_map_delete_elem` function is a libbpf wrapper for `BPF_MAP_DELETE_ELEM` command and its prototype is : `int bpf_map_delete_elem(int fd, const void *key)` which takes a map file descriptor and a pointer to the key you want to remove. If the key is found and deleted, it returns zero. If the key does not exist, it returns -1 and sets `errno=ENOENT`.

Here is an example of deleting a key:

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
                            NULL);            // map_flags
    if (fd < 0) {
        fprintf(stderr, "Failed to create hash map: %s\n", strerror(errno));
    }
    return fd;
}

int main() {
    int fd = create_hash_map();
    if (fd >= 0) {
        printf("Hash map created successfully with fd: %d\n", fd);

        // Insert a key-value pair (20 -> 250)
        int key = 20;
        int value = 250;
        if (bpf_map_update_elem(fd, &key, &value, BPF_ANY) == 0) {
            printf("Element inserted or updated successfully: key = %d, value = %ld\n", key, value);
        } else {
            fprintf(stderr, "Failed to insert or update element: %s\n", strerror(errno));
            close(fd);
            return -1;
        }
        
        // Now delete the key-value pair for key=20
        if (bpf_map_delete_elem(fd, &key) == 0) {
            printf("Key %d deleted successfully\n", key);
        } else {
            fprintf(stderr, "Failed to delete element: %s\n", strerror(errno));
            close(fd);
            return 1;
        }

        // Confirm that the key no longer exists
        int lookup_val;
        if (bpf_map_lookup_elem(fd, &key, &lookup_val) == 0) {
            printf("Unexpectedly found key %d after deletion, value=%d\n", key, lookup_val);
        } else {
            if (errno == ENOENT) {
                printf("Confirmed that key %d no longer exists\n", key);
            } else {
                printf("Element still exists\n");
            }
        }
        close(fd);
        return 0;
    }
    return -1;
}
```

After inserting `(20 -> 250)` into the map, we call `bpf_map_delete_elem` to remove it. The call succeeds, returning zero. A subsequent lookup for `key=20` fails with `ENOENT`, confirming that the entry has been removed and the output:
```sh
Hash map created successfully with fd: 3
Element inserted or updated successfully: key = 20, value = 250
Key 20 deleted successfully
Confirmed that key 20 no longer exists
```

If you call `bpf_map_delete_elem` for a key that does not exist, the operation simply returns an error and sets `errno=ENOENT`, indicating that there was nothing to delete.

### Kernel-Space code

```c
int bpf_map_delete_elem(void *map, const void *key);
```

## 4. Map Lookup and Delete Element

### User-Space code

`BPF_MAP_LOOKUP_AND_DELETE_ELEM` command retrieves the value associated with the given key, just like `BPF_MAP_LOOKUP_ELEM` command, but it also removes the key-value pair from the map in a single operation The `bpf_map_lookup_and_delete_elem` function is a libbpf wrapper for `BPF_MAP_LOOKUP_AND_DELETE_ELEM` command and its prototype is: `int bpf_map_lookup_and_delete_elem(int fd, const void *key, void *value)` . If the key exists, the function returns zero, copies the value to the user-provided buffer, and deletes that entry from the map. If the key is not found, it returns -1 and sets `errno=ENOENT`. This operation is particularly useful for scenarios where you want to consume entries from a map, such as implementing a queue or stack-like structure, or simply ensuring that once you retrieve a value, it is removed without requiring a separate delete call.

First, consider inserting a key-value pair and then looking it up and deleting it at the same time:

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
                            NULL);            // map_flags
    if (fd < 0) {
        fprintf(stderr, "Failed to create hash map: %s\n", strerror(errno));
    }
    return fd;
}

int main() {
    int fd = create_hash_map();
    if (fd >= 0) {
        printf("Hash map created successfully with fd: %d\n", fd);

        // Insert a key-value pair (10 -> 100)
        int key = 10;
        int value = 100;
        if (bpf_map_update_elem(fd, &key, &value, BPF_ANY) == 0) {
            printf("Element inserted or updated successfully: key = %d, value = %ld\n", key, value);
        } else {
            fprintf(stderr, "Failed to insert or update element: %s\n", strerror(errno));
            close(fd);
            return -1;
        }

        // Now perform lookup-and-delete
        int lookup_val;
        if (bpf_map_lookup_and_delete_elem(fd, &key, &lookup_val) == 0) {
            printf("Lookup and delete succeeded, value=%d\n", lookup_val);
        } else {
            fprintf(stderr, "Failed to insert or update element: %s\n", strerror(errno));
            close(fd);
            return 1;
        }

        // Verify that the key is no longer in the map
        int verify_val;
        if (bpf_map_lookup_elem(fd, &key, &verify_val) == 0) {
            printf("Unexpectedly found key %d after deletion\n", key);
        } else if (errno == ENOENT) {
            printf("Confirmed that key %d no longer exists\n", key);
        } else {
            printf("Element still exists\n");
        }
        close(fd);
        return 0;
    }
    return -1;
}
```

The previous example inserts `(10 -> 100)` into a hash map, then the program calls `bpf_map_lookup_and_delete_elem` for `key=10`. The operation returns the value `100` and removes the entry from the map at the same time. A subsequent lookup confirms the key is gone. The output is similar to this:
```sh
Hash map created successfully with fd: 3
Element inserted or updated successfully: key = 10, value = 100
Lookup and delete succeeded, value=100
Confirmed that key 10 no longer exists
```

### Kernel-Space code

```c
void *bpf_map_lookup_and_delete_elem(const void *map, const void *key);
```

## 5. Get Next Key

### User-Space code

`BPF_MAP_GET_NEXT_KEY` command iterates through the keys in a map. If you pass a specific key, the function returns the next key in the map, or sets `errno=ENOENT` if there is no next key. If you call it with a non-existing key or a NULL pointer (in some usages), it can return the first key in the map. This allows you to iterate over all keys one by one, even if you do not know them in advance.. The `bpf_map_get_next_key` function is a libbpf wrapper for `BPF_MAP_GET_NEXT_KEY` command and its prototype is: `int bpf_map_get_next_key(int fd, const void *key, void *next_key)`.  
It's important to note that the order of keys returned by `bpf_map_get_next_key` is not guaranteed to be the same as the typical ordering found in most iterators in other programming languages. The keys in eBPF maps are stored in an internal, arbitrary order determined by the kernel. Therefore, the order in which keys are returned when iterating is not necessarily sequential (e.g., ascending or based on insertion order). If you need a specific order, such as sorted keys, you will need to handle that ordering manually in your application.

Here’s how you might iterate over all keys:

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
                            NULL);            // map_flags
    if (fd < 0) {
        fprintf(stderr, "Failed to create hash map: %s\n", strerror(errno));
    }
    return fd;
}

int main() {
    int fd = create_hash_map();
    if (fd >= 0) {
        printf("Hash map created successfully with fd: %d\n", fd);
    
        // Insert multiple keys for demonstration
        int keys[] = {10, 20, 30};
        int values[] = {100, 200, 300};
        for (int i = 0; i < 3; i++) {
            if (bpf_map_update_elem(fd, &keys[i], &values[i], BPF_ANY) == 0) {
                printf("Element inserted or updated successfully: key = %d, value = %ld\n", keys[i], values[i]);
            } else {
                fprintf(stderr, "Failed to insert or update element: %s\n", strerror(errno));
                close(fd);
                return -1;
            }
        }

        // We'll start by using a key that doesn't exist (e.g., start_key=-1) to get the first key.
        int start_key = -1;
        int next_key;
        if (bpf_map_get_next_key(fd, &start_key, &next_key) == 0) {
            printf("Next key: %d\n", next_key);
        } else {
            fprintf(stderr, "Error getting next key: %s\n", strerror(errno));
            close(fd);
            return -1;
        }

        // Move to the next key
        start_key = next_key;
        if (bpf_map_get_next_key(fd, &start_key, &next_key) == 0) {
            printf("Next key: %d\n", next_key);
        } else {
            fprintf(stderr, "Error getting next key: %s\n", strerror(errno));
            close(fd);
            return -1;
        } 

        // Move to the next key
        start_key = next_key;
        if (bpf_map_get_next_key(fd, &start_key, &next_key) == 0) {
            printf("Next key: %d\n", next_key);
        } else {
            fprintf(stderr, "Error getting next key: %s\n", strerror(errno));
            close(fd);
            return -1;
        } 
        close(fd);
        return 0;
    }
    return -1;
}
```

In this example, we insert `(10->100)`, `(20->200)`, `(30->300)` into the map. We start iteration with a key (-1) that we know does not exist. The kernel returns the first key in ascending order. We then print each key-value pair and call `bpf_map_get_next_key` to advance to the next key. When `ENOENT` is returned, we know we have reached the end of the map. This process allows scanning the map’s contents without knowing the keys upfront.

### Kernel-Space code

```c
int bpf_map_get_next_key(const void *map, const void *key, void *next_key);
```

## 6. Map Lookup Batch

### User-Space code

`BPF_MAP_LOOKUP_BATCH` command fetches multiple elements from the map in a single call. Instead of calling `BPF_MAP_LOOKUP_ELEM` command repeatedly for each key, you can use this operation to retrieve several keys and their associated values at once. This improves performance when dealing with large maps or when you need to read multiple entries efficiently.
The `bpf_map_lookup_batch` function is a libbpf wrapper for `BPF_MAP_LOOKUP_BATCH` command and it uses two special parameters: `in_batch` and `out_batch`, which help maintain the state between successive batch lookups. You begin by passing a `NULL` `in_batch` to start from the first set of entries. The kernel then returns a batch of `(key, value)` pairs and sets `out_batch` to indicate where to resume from. On subsequent calls, you pass `out_batch` as `in_batch` to continue retrieving the next batch of entries until all entries have been retrieved. This method is particularly efficient for maps with a large number of entries, as it reduces the overhead of making individual lookups for each element, thus speeding up the retrieval process.  
The helper function prototype is 
```c
int bpf_map_lookup_batch(int fd, void *in_batch, void *out_batch, void *keys,
                         void *values, __u32 *count, const struct bpf_map_batch_opts *opts);

```

- **fd**: The file descriptor for the eBPF map you're querying.
- **in_batch**: The address of the first element in the batch to read. You pass `NULL` for the first call to start from the beginning of the map. On subsequent calls, you pass the address of `out_batch` to continue from the last retrieved entry.
- **out_batch**: This is an output parameter that the kernel sets to the position of the last element retrieved. It indicates where to resume for the next batch lookup.
- **keys**: A pointer to a buffer where the kernel will store the keys retrieved.
- **values**: A pointer to a buffer where the kernel will store the corresponding values for the retrieved keys.
- **count**: On input, this specifies the number of elements you want to retrieve in the batch. On output, it will contain the actual number of elements retrieved.
- **opts**: An optional parameter for additional configuration (can be `NULL` if not needed).

Let's go through an example:

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
                            NULL);            // map_flags
    if (fd < 0) {
        fprintf(stderr, "Failed to create hash map: %s\n", strerror(errno));
    }
    return fd;
}

int main() {
    int fd = create_hash_map();
    if (fd >= 0) {
        printf("Hash map created successfully with fd: %d\n", fd);

        // Insert several entries for demonstration
        int keys[] = {10, 20, 30, 40, 50, 60, 70, 80, 90};
        int values[] = {100, 200, 300, 400, 500, 600, 700, 800, 900};
        for (int i = 0; i < 9; i++) {
            if (bpf_map_update_elem(fd, &keys[i], &values[i], BPF_ANY) == 0) {
                printf("Element inserted or updated successfully: key = %d, value = %ld\n", keys[i], values[i]);
            } else {
                fprintf(stderr, "Failed to insert or update element: %s\n", strerror(errno));
                close(fd);
                return -1;
            }
        }

        // Prepare to batch lookup
        int batch_keys[1024];
        int batch_vals[1024];
        __u32 batch_count = 2;  // Number of elements to retrieve in one go
        __u32 *in_batch = NULL;  // Start from the beginning
        __u32 out_batch;
        int err;

        do {
            err = bpf_map_lookup_batch(fd, in_batch, &out_batch,
                                       batch_keys, batch_vals, &batch_count, NULL);
            if (err == 0) {
                for (unsigned i = 0; i < batch_count; i++) {
                    printf("Batch element: key=%d, value=%d\n", batch_keys[i], batch_vals[i]);
                }

                // Prepare for next batch: continue from last position
                in_batch = &out_batch;  // Set `in_batch` to the position of the last element
            } else if (errno != ENOENT) {
                // An error other than ENOENT means a failure occurred.
                fprintf(stderr, "Lookup batch failed: %s\n", strerror(errno));
                break;
            }
        } while (err == 0);
        close(fd);
        return 0;
    }
    return -1;
}
```

The previous example first inserts nine key-value pairs into a hash map. Then, it calls `bpf_map_lookup_batch` repeatedly to retrieve elements in batches, until `ENOENT` indicates that all entries have been retrieved. Each successful batch call prints out a subset of the map entries. Since there are only nine entries, you will likely retrieve them in one or two batches, depending on the batch size. However, this method scales well for larger maps.
The batch size is set to `2` (in `batch_count`), meaning the program will attempt to retrieve two entries in each call to `bpf_map_lookup_batch`. If the map does not contain enough entries to fill the entire batch, `batch_count` is adjusted to reflect how many entries were actually returned. When `bpf_map_lookup_batch` eventually returns `ENOENT`, it indicates that all elements have been retrieved. The output could be like:

```sh
Hash map created successfully with fd: 3
Element inserted or updated successfully: key = 10, value = 100
Element inserted or updated successfully: key = 20, value = 200
Element inserted or updated successfully: key = 30, value = 300
Element inserted or updated successfully: key = 40, value = 400
Element inserted or updated successfully: key = 50, value = 500
Element inserted or updated successfully: key = 60, value = 600
Element inserted or updated successfully: key = 70, value = 700
Element inserted or updated successfully: key = 80, value = 800
Element inserted or updated successfully: key = 90, value = 900
Batch element: key=30, value=300
Batch element: key=20, value=400
Batch element: key=80, value=800
Batch element: key=70, value=900
Batch element: key=60, value=600
Batch element: key=40, value=700
Batch element: key=50, value=500
Batch element: key=90, value=600
```

### Kernel-Space code

There is no helper function for such operation.
## 7. Map Update Batch

### User-Space code

`BPF_MAP_UPDATE_BATCH` command allows you to insert or update multiple keys and values in a single call. Similar to `BPF_MAP_LOOKUP_BATCH` command, this can significantly reduce overhead compared to performing multiple `BPF_MAP_LOOKUP_ELEM` calls in a loop. The `bpf_map_update_batch` function is a libbpf wrapper for `BPF_MAP_UPDATE_BATCH` command and its prototype is:
```c
int bpf_map_update_batch(int fd, const void *keys, const void *values, __u32 *count,
			 const struct bpf_map_batch_opts *opts)
```
You provide arrays of keys and values, along with a count, and `bpf_map_update_batch` attempts to insert or update all of them at once. Just like `bpf_map_update_elem`, you can specify flags such as `BPF_ANY`, `BPF_NOEXIST`, or `BPF_EXIST` to control insertion and update behavior as we mentioned earlier.

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
                            NULL);            // map_flags
    if (fd < 0) {
        fprintf(stderr, "Failed to create hash map: %s\n", strerror(errno));
    }
    return fd;
}

int main() {
    int fd = create_hash_map();
    if (fd >= 0) {
        printf("Hash map created successfully with fd: %d\n", fd);

        // Prepare arrays of keys and values
        int bulk_keys[3] = {40, 50, 60};
        int bulk_values[3] = {400, 500, 600};
        __u32 bulk_count = 3;
    
        // Update multiple entries in one go
        if (bpf_map_update_batch(fd, bulk_keys, bulk_values, &bulk_count, BPF_ANY) == 0) {
            printf("Batch update succeeded\n");
        } else {
            fprintf(stderr, "Batch update failed: %s\n", strerror(errno));
            close(fd);
            return 1;
        }
    
        // Verify that the entries are now in the map
        for (int i = 0; i < 3; i++) {
            int val;
            if (bpf_map_lookup_elem(fd, &bulk_keys[i], &val) == 0) {
                printf("Key=%d, Value=%d\n", bulk_keys[i], val);
            } else {
                fprintf(stderr, "Key=%d not found after batch update: %s\n", bulk_keys[i], strerror(errno));
            }
        }
        close(fd);
        return 0;
    }
    return -1;
}
```

This example inserts `(40->400)`, `(50->500)`, and `(60->600)` into the map in a single `bpf_map_update_batch` call. Afterward, we verify that all three keys were successfully inserted. If any error occurs (e.g., map is full), some keys might be updated before the error is returned. You can inspect `errno` and `bulk_count` for partial success handling.
```sh
Hash map created successfully with fd: 3
Batch update succeeded
Key=40, Value=400
Key=50, Value=600
Key=60, Value=50

```

This bulk approach is especially beneficial when populating maps with a large set of keys during initialization or when updating multiple entries at once.

### Kernel-Space code

There is no helper function for such operation.

## 8. Map Delete Batch

### User-Space code

`BPF_MAP_DELETE_BATCH` command removes multiple entries from the map in a single call, much like `BPF_MAP_DELETE_ELEM` does for individual keys. You supply arrays of keys along with a count, and the kernel attempts to delete all those keys at once. This operation is more efficient than deleting entries one by one, especially for large sets of keys. The `bpf_map_delete_batch` function is a libbpf wrapper for `BPF_MAP_DELETE_BATCH` command and its prototype is:
```c
int bpf_map_delete_batch(int fd, const void *keys, __u32 *count,
			 const struct bpf_map_batch_opts *opts)
```
The **fd** parameter is the file descriptor for the map, and **keys** is a pointer to an array of keys to delete. The **count** parameter specifies the number of keys to delete and is updated with the actual number of deletions. The **opts** parameter is optional and allows additional configuration (usually passed as `NULL`). The function returns `0` if successful, or a negative error code if an error occurs, with **errno** providing more details.

For example, if your map currently contains `(10->100)`, `(20->200)`, and `(30->300)`, and you want to remove `(10, 20, 30)` all at once:

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
                            NULL);            // map_flags
    if (fd < 0) {
        fprintf(stderr, "Failed to create hash map: %s\n", strerror(errno));
    }
    return fd;
}

int main() {
    int fd = create_hash_map();
    if (fd >= 0) {
        printf("Hash map created successfully with fd: %d\n", fd);

        // Prepare arrays of keys and values
        int bulk_keys[3] = {40, 50, 60};
        int bulk_values[3] = {400, 500, 600};
        __u32 bulk_count = 3;
    
        // Update multiple entries in one go
        if (bpf_map_update_batch(fd, bulk_keys, bulk_values, &bulk_count, BPF_ANY) == 0) {
            printf("Batch update succeeded\n");
        } else {
            fprintf(stderr, "Batch update failed: %s\n", strerror(errno));
            close(fd);
            return 1;
        }

        // Now batch-delete them
        __u32 delete_count = 3;
        if (bpf_map_delete_batch(fd, bulk_keys, &delete_count, NULL) == 0) {
            printf("Batch delete succeeded\n");
        } else {
            fprintf(stderr, "Batch delete failed: %s\n", strerror(errno));
            close(fd);
            return 1;
        }
    
        // Confirm deletion
        for (int i = 0; i < 3; i++) {
            int val;
            if (bpf_map_lookup_elem(fd, &bulk_keys[i], &val) == 0) {
                printf("Unexpectedly found key %d after batch deletion\n", bulk_keys[i]);
            } else if (errno == ENOENT) {
                printf("Confirmed key %d is removed\n", bulk_keys[i]);
            } else {
                fprintf(stderr, "Lookup error: %s\n", strerror(errno));
            }
        }
    
        close(fd);
        return 0;
    }
    return -1;
}
```

If successful, all three keys are removed. If an error occurs (for example, if one key does not exist), `delete_count` may be set to the number of successfully deleted keys before the error. In that case, you can handle partial success accordingly.
This approach is ideal when you need to clear out a subset of keys without performing multiple individual deletions.

### Kernel-Space code

There is no helper function for such operation.

## 9. Map Freeze

### User-Space code

`BPF_MAP_FREEZE` command converts the specified map into a read-only state. After freezing a map, no further updates or deletions can be performed using `bpf()` syscalls, although eBPF programs themselves can still read and, in some cases, modify certain fields if allowed by the map type. Freezing is useful when you have finished constructing or populating a map and want to ensure its contents remain stable.
The `bpf_map_freeze` function is a libbpf wrapper for `BPF_MAP_FREEZE` command and its prototype is:
```c
int bpf_map_freeze(int fd)
```

To freeze a map:

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
                            NULL);            // map_flags
    if (fd < 0) {
        fprintf(stderr, "Failed to create hash map: %s\n", strerror(errno));
    }
    return fd;
}

int main() {
    int fd = create_hash_map();
    if (fd >= 0) {
        printf("Hash map created successfully with fd: %d\n", fd);


	    // Insert an entry (10->100)
	    int key = 10;
	    int value = 100;
	    if (bpf_map_update_elem(fd, &key, &value, BPF_ANY) == 0) {
            printf("Element inserted or updated successfully: key = %d, value = %ld\n", key, value);
        } else {
            fprintf(stderr, "Failed to insert or update element: %s\n", strerror(errno));
            return -1;
        }
	
	    // Freeze the map to prevent further updates
	    if (bpf_map_freeze(fd) == 0) {
	        printf("Map is now frozen and read-only\n");
	    } else {
	        perror("bpf_map_freeze");
	        return 1;
	    }
	
	    // Attempting to update after freezing should fail
	    int new_val = 200;
	    if (bpf_map_update_elem(fd, &key, &new_val, BPF_ANY) != 0) {
	        if (errno == EPERM) {
	            printf("Update failed, map is frozen\n");
	        } else {
	            perror("bpf_map_update_elem");
	        }
	    } else {
	        printf("Unexpected success, map should have been frozen\n");
	    }
	    close(fd);
	    return 0;
	}
	return -1;
}
```

After this call, attempts to update or delete elements through `bpf_map_update_elem` or `bpf_map_delete_elem` will fail with `EPERM`. This ensures that user-space cannot inadvertently modify the map’s contents, making it a suitable mechanism for finalizing configuration or ensuring data integrity.
```sh
Hash map created successfully with fd: 3
Element inserted or updated successfully: key = 10, value = 100
Map is now frozen and read-only
Update failed, map is frozen
```

### Kernel-Space code

There is no helper function for such operation.

## 10. Object Pin

### User-Space code
`BPF_OBJ_PIN` command allows you to pin a map (or other eBPF objects like programs) to a location in the eBPF filesystem (`/sys/fs/bpf` by default). Pinning makes the map accessible to other processes after the original process that created it terminates, thereby extending the map’s lifetime beyond that of a single application.
The `bpf_obj_pin_opts` function is a libbpf wrapper for `BPF_OBJ_PIN` command and its prototype is:
```c
int bpf_obj_pin_opts(int fd, const char *pathname, const struct bpf_obj_pin_opts *opts)
```
{{< alert title="Note" >}}The pathname argument must not contain a dot (".").{{< /alert >}}
For instance, to pin a map under `/sys/fs/bpf/my_map`:

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
                            NULL);            // map_flags
    if (fd < 0) {
        fprintf(stderr, "Failed to create hash map: %s\n", strerror(errno));
    }
    return fd;
}

int main() {
    int fd = create_hash_map();
    if (fd >= 0) {
        printf("Hash map created successfully with fd: %d\n", fd);


	    // Prepare arrays of keys and values
	    int bulk_keys[3] = {40, 50, 60};
	    int bulk_values[3] = {400, 500, 600};
	    __u32 bulk_count = 3;
	
	    // Update multiple entries in one go
	    if (bpf_map_update_batch(fd, bulk_keys, bulk_values, &bulk_count, BPF_ANY) == 0) {
	        printf("Batch update succeeded\n");
	    } else {
	        fprintf(stderr, "Batch update failed: %s\n", strerror(errno));
	        return 1;
	    }

	    // Pin the map to the BPF filesystem
	    const char *pin_path = "/sys/fs/bpf/my_map";
	    if (bpf_obj_pin(fd, pin_path) == 0) {
	        printf("Map pinned at %s\n", pin_path);
	    } else {
	        perror("bpf_obj_pin");
	        return 1;
	    }
	    close(fd);
	    return 0;
	}
	return -1;
}
```

Here, we create a map, insert `(20->200)`, and pin it to `/sys/fs/bpf/my_map`. After pinning, we can safely close the file descriptor without losing the map. The map remains accessible at the pin path, allowing other processes to open it later.
{{< alert title="Note" >}}Closing `fd` in the current process does not destroy the map. It persists at `/sys/fs/bpf/my_map` until unlinked or until the system reboots.{{< /alert >}}


### Kernel-Space code

There is no helper function for such operation.

## 11. Object Get

### User-Space code

`BPF_OBJ_GET` command retrieves a file descriptor for a previously pinned map, allowing a separate process to access and interact with that map. This facilitates sharing eBPF maps between multiple processes or restoring access to the map after the original creating process has exited.
The `bpf_obj_get` function is a libbpf wrapper for `BPF_OBJ_GET` command and its prototype is:
```c
int bpf_obj_get(const char *pathname)
```
By calling `bpf_obj_get(path)`, you open a reference to the pinned map from the filesystem path. Let's get the previous map `/sys/fs/bpf/my_map` 

```c
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <unistd.h>

int main() {
    const char *pin_path = "/sys/fs/bpf/my_map";

    // Open the pinned map
    int pinned_map_fd = bpf_obj_get(pin_path);
    if (pinned_map_fd < 0) {
        perror("bpf_obj_get");
        return 1;
    }
    printf("Opened pinned map from %s\n", pin_path);

    // Verify the map's content
    int key = 50;
    int val = 0;
    if (bpf_map_lookup_elem(pinned_map_fd, &key, &val) == 0) {
        printf("Retrieved value %d for key %d from pinned map\n", val, key);
    } else {
        perror("bpf_map_lookup_elem");
    }

    close(pinned_map_fd);
    return 0;
}
```

This program assumes that a map was previously pinned at `/sys/fs/bpf/my_map`. Calling `bpf_obj_get` opens a file descriptor to that map. We then retrieve `(50->500)` that was inserted in the previous example, confirming that the pinned map persists across processes.
```sh
Opened pinned map from /sys/fs/bpf/my_map
Retrieved value 500 for key 50 from pinned map
```
If successful, `pinned_map_fd` can be used just like any other map file descriptor. This is essential for long-running services or tools that need persistent state maintained across restarts, or for sharing data structures between different components of a system.

### Kernel-Space code

There is no helper function for such operation.

I know it can be challenging to wrap your head around the differences between eBPF user-space code and kernel-space eBPF programs. Bear with me—soon we'll see eBPF programs in action, including maps and map operations, and everything will start to click!

