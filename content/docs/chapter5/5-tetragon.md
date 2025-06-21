---
title: Tetragon
description: CNCF project using eBPF to monitor and enforce runtime security policies.
weight: 6
---

Tetragon is an open-source tool that uses eBPF to monitor and control Linux systems. It tracks events like process execution, network connections, and file access in real time. You can write custom rules to filter these events, and it runs with very little performance impact. Although it works great with Kubernetes and container setups, it can secure any Linux system that supports eBPF. Its kernel-level enforcement can, for example, kill a process if it violates a rule, adding a strong layer of security. Tetragon can be installed from their [website](https://tinyurl.com/eck5524z), consider download it to follow this part.

Tetragon works by using policies called TracingPolicies. These policies let you define exactly what kernel events to monitor and what actions to take when those events happen. You write rules in a policy that attach probes to kernel functions, filter events based on criteria like arguments or process IDs, and then enforce actions (for example, killing a process) if a rule is matched. This approach gives you fine-grained control over system security in real time. Let's take a glimpse of what Tetragon can do.

## TracingPolicy

A TracingPolicy is a YAML document that follows Kubernetes’ API conventions. Even if you’re running Tetragon on a CLI (non-Kubernetes) installation, the policy structure remains similar. At its simplest, a tracing policy must include:

`API Version and Kind`: This tells Tetragon which version of the API you’re using and what type of object you’re creating. For tracing policies, you typically use:

```yaml
    apiVersion: cilium.io/v1alpha1
    kind: TracingPolicy
```

`Metadata`: Metadata includes a unique name for your policy.
```yaml
    metadata:
      name: "example-policy"
 ```

### Spec Section

`Spec`: The spec contains all the configuration details about what you want to trace and how. It’s where you define:

- The hook point (e.g., a kernel function to monitor)
- Which arguments you want to capture
- Selectors (in-kernel filters) to determine when the policy should trigger, and
- The actions to execute when a match occurs.

The hook point is the entry point where Tetragon attaches its BPF program. You have several options: kprobes, tracepoints, uprobes and lsmhooks.

Let’s say you want to monitor `do_mkdirat` kernel function. You would specify:
```yaml
spec:
  kprobes:
  - call: "do_mkdirat"
    syscall: false
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "filename"
    - index: 2
      type: "int"
```

**What This Means:**

- You are instructing Tetragon to insert a kprobe into `do_mkdirat` kernel function and it's not a syscall.
- The policy tells the eBPF code to extract three arguments: the integer value (the file descriptor number), the filename structure (which include the file path) and integer value as mode.
 In some cases, you want to capture the return value from a function. To do so, set the `return` flag to true, define a `returnArg`, and specify its type. This is useful when you want to track how a function completes.

```yaml
spec:
  kprobes:
  - call: "do_mkdirat"
    syscall: false
    return: true
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "filename"
    - index: 2
      type: "int"
	returnArg:
	  index: 0
	  type: "int"
```

### Selectors

`Selectors` are the core of in-kernel filtering. They allow you to define conditions that must be met for the policy to apply and actions to be triggered. Within a selector, you can include one or more filters.

### Filter Types

Each probe can contain up to 5 selectors and each selector can contain one or more filter. Below is a table summarizing the available filters, their definitions, and the operators they support:

| Filter Name                | Definition                                                                                                           | Operators                                                                                                                                                                                                              |
| -------------------------- | -------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| matchArgs              | Filters on the value of function arguments.                                                                          | Equal, NotEqual, Prefix, Postfix, Mask, GreaterThan (GT), LessThan (LT), SPort, NotSPort, SPortPriv, NotSPortPriv, DPort, NotDPort, DPortPriv, NotDPortPriv, SAddr, NotSAddr, DAddr, NotDAddr, Protocol, Family, State |
| matchReturnArgs        | Filters based on the function’s return value.                                                                        | Equal, NotEqual, Prefix, Postfix                                                                                                                                                                                       |
| matchPIDs              | Filters on the host PID of the process.                                                                              | In, NotIn                                                                                                                                                                                                              |
| matchBinaries          | Filters on the binary path (or name) of the process invoking the event.                                              | In, NotIn, Prefix, NotPrefix, Postfix, NotPostfix                                                                                                                                                                      |
| matchNamespaces        | Filters based on Linux namespace values.                                                                             | In, NotIn                                                                                                                                                                                                              |
| matchCapabilities      | Filters based on Linux capabilities in the specified set (Effective, Inheritable, or Permitted).                     | In, NotIn                                                                                                                                                                                                              |
| matchNamespaceChanges  | Filters based on changes in Linux namespaces (e.g., when a process changes its namespace).                           | In                                                                                                                                                                                                                     |
| matchCapabilityChanges | Filters based on changes in Linux capabilities (e.g., when a process’s capabilities are altered).                    | In                                                                                                                                                                                                                     |
| matchActions           | Applies an action when the selector matches (executed directly in kernel BPF code or in userspace for some actions). | Not a traditional filter; supports action types such as: Sigkill, Signal, Override, FollowFD, UnfollowFD, CopyFD, GetUrl, DnsLookup, Post, NoPost, TrackSock, UntrackSock, NotifyEnforcer.                             |
| matchReturnActions     | Applies an action based on the return value matching the selector.                                                   | Similar to matchActions; supports action types (as above) that are executed on return events.                                                                                                                      |

`matchArgs`: Filter on a specific argument’s value (if filename = /etc/passwd)
```yaml
    selectors:
    - matchArgs:
      - index: 1
        operator: "Equal"
        values:
        - "/etc/shadow"
```

`matchBinaries`: Filters based on the binary path or name of the process invoking the function.
```yaml
    - matchBinaries:
      - operator: "In"
        values:
        - "/usr/bin/sudo"
        - "/usr/bin/su"
```

Imagine you want to monitor any process that tries to open the file `/etc/shadow` or `/etc/passwd`. You might set up a selector that uses matchArgs filter:

```yaml
spec:
  kprobes:
  - call: "sys_openat"
    syscall: true
    args:
    - index: 0
      type: int
    - index: 1
      type: "string"
    - index: 2
      type: "int"
    selectors:
    - matchArgs:
      - index: 1
        operator: "Equal"
        values:
        - "/etc/passwd"
        - "/etc/shadow"
```
First, filter on the second parameter (index=1), then match it with (/etc/passwd or /etc/shadow).

{{< alert title="Note" >}}Instead of writing the full name of syscalls such as `__x64_sys_openat` you can just use `sys_openat` and Tetragon will take care of the prefix of the syscall based on the architecture of you machine.{{< /alert >}}

### Actions 

`matchActions` and `matchReturnActions`: These attach actions to be executed when the selector matches. They also allow you to filter based on the value of return arguments (if needed).  
Actions are what your policy does when a selector matches. They allow you to enforce decisions right in the kernel. Some common actions include:  
`Sigkill` and `Signal`: immediately terminates the offending process.
```yaml
    matchActions: 
    - action: Sigkill
```

To send a specific signal (e.g., SIGKILL which is signal 9)
```yaml
    matchActions: 
    - action: Signal
      argSig: 
```

`Override`:  Modifies the return value of a function, which can cause the caller to receive an error code. This action uses the error injection framework.
```yaml
    - matchActions:
      - action: Override
        argError: -1
```

{{< alert title="Note" >}}Override function used for error injection. Due to security implications, override function is available only if the kernel was compiled with `CONFIG_BPF_KPROBE_OVERRIDE` option. There is a list of all function that support override and they are tagged with `ALLOW_ERROR_INJECTION` and they are located at `/sys/kernel/debug/error_injection/list`.{{< /alert >}}

`FollowFD`, `UnfollowFD` and `CopyFD`:  These actions help track file descriptor usage. For example, you can map a file descriptor to a file name during an open call, so that later calls (e.g., sys_write) that only have an FD can be correlated to a file path. The best example to explain FollowFD / UnfollowFD is from Tetragon documentation. This example is how to prevent write to a specific files for example `/etc/passwd`. `sys_write` only takes a file descriptor not a name and location. First we hook to `fd_install` kernel function.  
`fd_install` is a kernel function that's called when a file descriptor is being added to a process's file descriptor table. In simpler terms, when a process opens a file (or performs a similar operation that creates a file descriptor), `fd_install` is invoked to associate the new file descriptor (an integer) with the corresponding file object. `fd_install` has the following prototype:
```c
void fd_install(unsigned int fd, struct file *file);
```

{{< alert title="Note" >}}Tetragon is planing to remove `FollowFD`, `UnfollowFD` and `CopyFD` starting from Tetragon version 1.5 due to security concerns.{{< /alert >}}

```yaml
kprobes:
- call: "fd_install"
  syscall: false
  args:
  - index: 0
    type: int
  - index: 1
    type: "file"
  selectors:
  - matchArgs:
    - index: 1
      operator: "Equal"
      values:
      - "/etc/passwd"
    matchActions:
    - action: FollowFD
      argFd: 0
      argName: 1
- call: "sys_write"
  syscall: true
  args:
  - index: 0
    type: "fd"
  - index: 1
    type: "char_buf"
    sizeArgIndex: 3
  - index: 2
    type: "size_t"
  selectors:
  - matchArgs:
    - index: 0
      operator: "Equal"
      values:
      - "/etc/passwd"
    matchActions:
    - action: Sigkill
- call: "sys_close"
  syscall: true
  args:
  - index: 0
     type: "int"
  selectors:
  - matchActions:
    - action: UnfollowFD
      argFd: 0
      argName: 0
```

In the previous example, the second argument is defined as `file` type as the name of the kernel data structure `struct file`:
```yaml
  - index: 1
    type: "file"
```

`Post`: Sends an event up to user space. You can also ask for kernel and user stack traces to be included, and even limit how often these events fire.
```yaml
    selectors:
    - matchArgs:
      - index: 1
        operator: "Equal"
        values:
        - "/etc/passwd"
      matchActions:
      - action: Post
        rateLimit: 5m
        kernelStackTrace: true
        userStackTrace: true
```

`GetUrl` and `DnsLookup`: The GetUrl action triggers an HTTP GET request to a specified URL`argUrl`. The `DnsLookup` action initiates a DNS lookup for a specified fully qualified domain name (FQDN) `argFqdn`.
Both actions are used to notify external systems when a specific event occurs in the kernel such as (Thinkst canaries or webhooks).
```yaml
matchActions:
- action: GetUrl
  argUrl: http://example.com/trigger
```

```yaml
matchActions:
- action: DnsLookup
  argFqdn: canary.example.com
```


Below is a complete tracing policy example that monitors when `mkdir` attempts to create `test`. When it does, the policy sends a SIGKILL signal to the offending process.
```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "kill-mkdir-test"
spec:
  kprobes:
  - call: "do_mkdirat"
    syscall: false
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "filename"
    - index: 2
      type: "int"
    selectors:
    - matchArgs:
      - index: 1
        operator: "Equal"
        values:
        - "test"
      matchActions:
      - action: Sigkill
```

Running this policy using `sudo tetragon --tracing-policy mkdir.yaml`. Output can be monitored using `sudo tetra getevents -o compact`

```sh
process mac-Standard-PC-Q35-ICH9-2009 /usr/bin/mkdir ../tmp/test       
syscall mac-Standard-PC-Q35-ICH9-2009 /usr/bin/mkdir do_mkdirat                  
exit    mac-Standard-PC-Q35-ICH9-2009 /usr/bin/mkdir ../tmp/test SIGKILL 
```

Another example for blocking reading files from a specific directory using `file_open` hook in LSM:
```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "Block-screct-files"
spec:
  lsmhooks:
  - hook: "file_open" 
    args:
    - index: 0
      type: "file"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Prefix"
        values:
        - "/tmp/secret/"
      matchActions:
      - action: Sigkill
```

```sh
process mac-Standard-PC-Q35-ICH9-2009 /usr/bin/cat /tmp/secret/test1   
LSM     mac-Standard-PC-Q35-ICH9-2009 /usr/bin/cat file_open                    
exit    mac-Standard-PC-Q35-ICH9-2009 /usr/bin/cat /tmp/secret/test1 SIGKILL 
```

We can specify a specific binary to block. For example, to block only `cat` command:
```yaml
    selectors:
    - matchBinaries:
      - operator: "In"
        values:
        - "/usr/bin/cat"
      matchArgs:
      - index: 0
        operator: "Prefix"
        values:
        - "/tmp/secret/" 
```

Another example to block `wget` command from accessing port 443. We used `DPort` to define destination port:
```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "block-443-for-wget"
spec:
  kprobes:
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    - matchBinaries:
      - operator: "In"
        values:
        - "/usr/bin/wget"
      matchArgs:
      - index: 0
        operator: "DPort"
        values:
        - 443
      matchActions:
      - action: Sigkill
```

`wget` command is blocked while `curl` command is working!
```sh
process mac-Standard-PC-Q35-ICH9-2009 /usr/bin/wget https://8.8.8.8    
connect mac-Standard-PC-Q35-ICH9-2009 /usr/bin/wget tcp 192.168.122.215:60914 -> 8.8.8.8:443 
exit    mac-Standard-PC-Q35-ICH9-2009 /usr/bin/wget https://8.8.8.8 SIGKILL 
process mac-Standard-PC-Q35-ICH9-2009 /usr/bin/curl https://8.8.8.8    
exit    mac-Standard-PC-Q35-ICH9-2009 /usr/bin/curl https://8.8.8.8 0 
```

Example for monitoring `sudo` command using `__sys_setresuid` kernel function.  
`__sys_setresuid` is the kernel function that implements the `setresuid` system call. It changes a process’s user IDs—specifically, the real, effective, and saved user IDs—in one atomic operation and it's used to adjust process privileges.
```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "detect-sudo"
spec:
  kprobes:
  - call: "__sys_setresuid"
    syscall: false
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "int"
    - index: 2
      type: "int"
    selectors:
    - matchArgs:
      - index: 1
        operator: "Equal"
        values:
        - "0"
```

Tetragon can be configured to send [metrics](https://tinyurl.com/3p7nkrs4) to Prometheus to monitor activities observed by Tetragon. It has also [Elastic integration](https://tinyurl.com/4wafr2cb). Tetragon has policy library and many useful use cases in their [documentation](https://tinyurl.com/mpurdj5z). It's a powerful tool and even fun to try it.
