---
title: Landlock
description: User space sandboxing where apps define their own file access rules.
weight: 4
---

Landlock is a Linux Security Module (LSM) introduced in Linux kernel 5.13 based on eBPF that allows processes to restrict their own privileges in a fine-grained, stackable, and unprivileged manner. Unlike traditional Mandatory Access Control (MAC) systems such as SELinux and AppArmor, which require administrative setup, Landlock enables unprivileged processes to sandbox themselves. This makes it particularly useful for running potentially vulnerable applications while limiting their ability to perform unauthorized actions.

By defining specific access rules, processes can restrict themselves to only the necessary files and network operations, preventing unauthorized access or modification of sensitive data. This capability is particularly valuable in scenarios where applications handle untrusted input or where minimizing the impact of potential security breaches is critical.

A key advantage of Landlock is its layered security model. Rulesets in Landlock are stackable, meaning multiple rulesets can be enforced incrementally to tighten security restrictions over time. Once a Landlock ruleset is enforced, it cannot be relaxed or removed, ensuring that restrictions remain in place throughout the process's lifetime. Additionally, Landlock operates at the kernel object (e.g., file, process, socket) level rather than filtering syscalls, providing minimal overhead, a stable interface for future developments and race condition free.

To check if Landlock is up and running is by executing `sudo dmesg | grep landlock || journalctl -kb -g landlock`
```sh
[    0.043191] LSM: initializing lsm=lockdown,capability,landlock,yama,apparmor,tomoyo,bpf,ipe,ima,evm
[    0.043191] landlock: Up and running.
```

### How Landlock Works

1. **Ruleset Creation:**  
A Landlock ruleset defines what kinds of actions are handled (e.g., file read/write, TCP connect) and denies those actions by default unless they are explicitly allowed by the rules added to that ruleset. There are three types of rules in landlock defined in `include/uapi/linux/landlock.h` header file : `handled_access_fs`, `handled_access_net` and `scoped` as defined in the following data structure:
```c
struct landlock_ruleset_attr {
	/**
	 * @handled_access_fs: Bitmask of handled filesystem actions
	 * (cf. `Filesystem flags`_).
	 */
	__u64 handled_access_fs;
	/**
	 * @handled_access_net: Bitmask of handled network actions (cf. `Network
	 * flags`_).
	 */
	__u64 handled_access_net;
	/**
	 * @scoped: Bitmask of scopes (cf. `Scope flags`_)
	 * restricting a Landlock domain from accessing outside
	 * resources (e.g. IPCs).
	 */
	__u64 scoped;
};
```
`handled_access_fs` rules to sandbox a process to a set of actions on files and directories and they are as the following:
```java
#define LANDLOCK_ACCESS_FS_EXECUTE			    (1ULL << 0)
#define LANDLOCK_ACCESS_FS_WRITE_FILE			(1ULL << 1)
#define LANDLOCK_ACCESS_FS_READ_FILE			(1ULL << 2)
#define LANDLOCK_ACCESS_FS_READ_DIR			    (1ULL << 3)
#define LANDLOCK_ACCESS_FS_REMOVE_DIR			(1ULL << 4)
#define LANDLOCK_ACCESS_FS_REMOVE_FILE			(1ULL << 5)
#define LANDLOCK_ACCESS_FS_MAKE_CHAR			(1ULL << 6)
#define LANDLOCK_ACCESS_FS_MAKE_DIR			    (1ULL << 7)
#define LANDLOCK_ACCESS_FS_MAKE_REG		   	    (1ULL << 8)
#define LANDLOCK_ACCESS_FS_MAKE_SOCK			(1ULL << 9)
#define LANDLOCK_ACCESS_FS_MAKE_FIFO			(1ULL << 10)
#define LANDLOCK_ACCESS_FS_MAKE_BLOCK			(1ULL << 11)
#define LANDLOCK_ACCESS_FS_MAKE_SYM			    (1ULL << 12)
#define LANDLOCK_ACCESS_FS_REFER			    (1ULL << 13)
#define LANDLOCK_ACCESS_FS_TRUNCATE			    (1ULL << 14)
#define LANDLOCK_ACCESS_FS_IOCTL_DEV			(1ULL << 15)
```

They are explained in `include/uapi/linux/landlock.h` as the following:
```java
 * - %LANDLOCK_ACCESS_FS_EXECUTE: Execute a file.
 * - %LANDLOCK_ACCESS_FS_WRITE_FILE: Open a file with write access.
 * - %LANDLOCK_ACCESS_FS_READ_FILE: Open a file with read access.
 * - %LANDLOCK_ACCESS_FS_READ_DIR: Open a directory or list its content.
 * - %LANDLOCK_ACCESS_FS_REMOVE_DIR: Remove an empty directory or rename one.
 * - %LANDLOCK_ACCESS_FS_REMOVE_FILE: Unlink (or rename) a file.
 * - %LANDLOCK_ACCESS_FS_MAKE_CHAR: Create (or rename or link) a character device.
 * - %LANDLOCK_ACCESS_FS_MAKE_DIR: Create (or rename) a directory.
 * - %LANDLOCK_ACCESS_FS_MAKE_REG: Create (or rename or link) a regular file.
 * - %LANDLOCK_ACCESS_FS_MAKE_SOCK: Create (or rename or link) a UNIX domain socket.
 * - %LANDLOCK_ACCESS_FS_MAKE_FIFO: Create (or rename or link) a named pipe.
 * - %LANDLOCK_ACCESS_FS_MAKE_BLOCK: Create (or rename or link) a block device.
 * - %LANDLOCK_ACCESS_FS_MAKE_SYM: Create (or rename or link) a symbolic link.
 * - %LANDLOCK_ACCESS_FS_REFER: Link or rename a file from or to a different directory (i.e. reparent a file hierarchy).
 * - %LANDLOCK_ACCESS_FS_TRUNCATE: Truncate a file with:truncate(2), ftruncate(2), creat(2), or open(2) with O_TRUNC.
 * - %LANDLOCK_ACCESS_FS_IOCTL_DEV: Invoke :manpage:`ioctl(2)` commands on an opened character or block device.
```

`handled_access_net` rules to sandbox a process to a set of network actions and they are defined as the following:
```java
#define LANDLOCK_ACCESS_NET_BIND_TCP			(1ULL << 0)
#define LANDLOCK_ACCESS_NET_CONNECT_TCP			(1ULL << 1)
```

`handled_access_net` rules are explained as the following:
```c
* - %LANDLOCK_ACCESS_NET_BIND_TCP: Bind a TCP socket to a local port.
* - %LANDLOCK_ACCESS_NET_CONNECT_TCP: Connect an active TCP socket to
```

`scoped` rules to sandbox a process from a set of IPC (inter-process communication) actions or sending signals and they are defined as the following:
```java
#define LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET		    (1ULL << 0)
#define LANDLOCK_SCOPE_SIGNAL		                (1ULL << 1)
```

`scoped` rules are explained as the following:
```c
* - %LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET: Restrict a sandboxed process from connecting to an abstract UNIX socket created by a process outside the related Landlock domain (e.g. a parent domain or a non-sandboxed process).

* - %LANDLOCK_SCOPE_SIGNAL: Restrict a sandboxed process from sending a signal to another process outside the domain
```

Ruleset Creation is done using `landlock_create_ruleset()` syscall.

2. **Adding Rules:**  
Define access rights since the defaults actions is deny. Define access rights can be done using data structures which are `landlock_path_beneath_attr` and `landlock_net_port_attr`. For example, block access to entire file system except read files, read directories and execute on `/usr/bin/`.
`landlock_path_beneath_attr` data structure is defined in `include/uapi/linux/landlock.h` header file as the following:
```c
struct landlock_path_beneath_attr {
	/**
	 * @allowed_access: Bitmask of allowed actions for this file hierarchy
	 * (cf. `Filesystem flags`_).
	 */
	__u64 allowed_access;
	/**
	 * @parent_fd: File descriptor, preferably opened with ``O_PATH``,
	 * which identifies the parent directory of a file hierarchy, or just a
	 * file.
	 */
	__s32 parent_fd;
	/*
	 * This struct is packed to avoid trailing reserved members.
	 * Cf. security/landlock/syscalls.c:build_check_abi()
	 */
} __attribute__((packed));
```

`landlock_net_port_attr` data structure is defined in `include/uapi/linux/landlock.h` header file as the following:
```c
struct landlock_net_port_attr {
	/**
	 * @allowed_access: Bitmask of allowed network actions for a port
	 * (cf. `Network flags`_).
	 */
	__u64 allowed_access;
	/**
	 * @port: Network port in host endianness.
	 *
	 * It should be noted that port 0 passed to :manpage:`bind(2)` will bind
	 * to an available port from the ephemeral port range. This can be
	 * configured with the ``/proc/sys/net/ipv4/ip_local_port_range`` sysctl
	 * (also used for IPv6).
	 *
	 * A Landlock rule with port 0 and the ``LANDLOCK_ACCESS_NET_BIND_TCP``
	 * right means that requesting to bind on port 0 is allowed and it will
	 * automatically translate to binding on the related port range.
	 */
	__u64 port;
};
```

Adding rules can be done using `landlock_add_rule()` syscall.

3. **Restricting Self:**  
Once a ruleset is created and populated, a thread (with `no_new_privs` set, or with `CAP_SYS_ADMIN` in its namespace) can call `landlock_restrict_self()` syscall to enforce it on itself and all child processes. After enforcement, the process can still add more restrictions later, but cannot remove existing ones.

{{< alert title="Note" >}}Each time you call `landlock_restrict_self()` syscall will add a new layer, and you can stack up to 16 layers (rulesets). If layers exceed 16, it will return `E2BIG` (Argument list too long).{{< /alert >}}

### ABI Versions and Compatibility

When you call `landlock_create_ruleset()` with `attr = NULL` and `size = 0`, it returns the highest supported ABI. A recommended practice is to do a best-effort approach: detect the system’s ABI, then disable features that are not supported, so your program runs consistently on different kernels. 

- `ABI < 2`: Did not allow renaming/linking across directories.
- `ABI < 3`: File truncation could not be restricted.
- `ABI < 4`: No network restriction support.
- `ABI < 5`: Could not restrict `ioctl(2)` on devices.
- `ABI < 6`: No scope restrictions for signals or abstract Unix sockets.

It's recommended to detect Landlock ABI version to maintain compatibility across different kernel versions as stated in the kernel manual:
```c
int abi;

abi = landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
if (abi < 0) {
    /* Degrades gracefully if Landlock is not handled. */
    perror("The running kernel does not enable to use Landlock");
    return 0;
}
switch (abi) {
case 1:
    /* Removes LANDLOCK_ACCESS_FS_REFER for ABI < 2 */
    ruleset_attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_REFER;
    __attribute__((fallthrough));
case 2:
    /* Removes LANDLOCK_ACCESS_FS_TRUNCATE for ABI < 3 */
    ruleset_attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_TRUNCATE;
    __attribute__((fallthrough));
case 3:
    /* Removes network support for ABI < 4 */
    ruleset_attr.handled_access_net &=
        ~(LANDLOCK_ACCESS_NET_BIND_TCP |
          LANDLOCK_ACCESS_NET_CONNECT_TCP);
    __attribute__((fallthrough));
case 4:
    /* Removes LANDLOCK_ACCESS_FS_IOCTL_DEV for ABI < 5 */
    ruleset_attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_IOCTL_DEV;
    __attribute__((fallthrough));
case 5:
    /* Removes LANDLOCK_SCOPE_* for ABI < 6 */
    ruleset_attr.scoped &= ~(LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET |
                             LANDLOCK_SCOPE_SIGNAL);
}
```

Let's see a simple example to sandbox a process from communicating through TCP. 
```c
#define _GNU_SOURCE
#include <linux/landlock.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/syscall.h>

static inline int landlock_create_ruleset(const struct landlock_ruleset_attr *attr, size_t size, __u32 flags) {
    return syscall(__NR_landlock_create_ruleset, attr, size, flags);
}

static inline int landlock_restrict_self(int ruleset_fd) {
    return syscall(__NR_landlock_restrict_self, ruleset_fd, 0);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <binary> [args...]\n", argv[0]);
        return 1;
    }

    int abi = landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 4) {
        fprintf(stderr, "Landlock network restrictions are not supported (need ABI >= 4).\n");
        fprintf(stderr, "Running %s without Landlock.\n", argv[1]);
        execvp(argv[1], &argv[1]);
        perror("execvp");
        return 1;
    }

    struct landlock_ruleset_attr ruleset_attr = {
        .handled_access_net = LANDLOCK_ACCESS_NET_CONNECT_TCP | LANDLOCK_ACCESS_NET_BIND_TCP
    };

    int ruleset_fd = landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
    if (ruleset_fd < 0) {
        perror("landlock_create_ruleset");
        return 1;
    }

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        perror("prctl(PR_SET_NO_NEW_PRIVS)");
        close(ruleset_fd);
        return 1;
    }

    if (landlock_restrict_self(ruleset_fd)) {
        perror("landlock_restrict_self");
        close(ruleset_fd);
        return 1;
    }

    close(ruleset_fd);

    execvp(argv[1], &argv[1]);
    perror("execvp failed");
    return 1;
}
```

First, we define inline helper functions to provide a simplified interface for the `landlock_create_ruleset` and `landlock_restrict_self` system calls.
```c
static inline int landlock_create_ruleset(const struct landlock_ruleset_attr *attr, size_t size, __u32 flags) {
    return syscall(__NR_landlock_create_ruleset, attr, size, flags);
}

static inline int landlock_restrict_self(int ruleset_fd) {
    return syscall(__NR_landlock_restrict_self, ruleset_fd, 0);
}
```

Then, check Landlock ABI support (version >=4 supports network restrictions):
```c
    int abi = landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 4) {
        fprintf(stderr, "Landlock network restrictions are not supported (need ABI >= 4).\n");
        fprintf(stderr, "Running %s without Landlock.\n", argv[1]);
        execvp(argv[1], &argv[1]);
        perror("execvp");
        return 1;
    }
```

Then, define rules using `landlock_ruleset_attr` data structure:
```c
    struct landlock_ruleset_attr ruleset_attr = {
        .handled_access_net = LANDLOCK_ACCESS_NET_CONNECT_TCP | LANDLOCK_ACCESS_NET_BIND_TCP
    };
```

Next,  Ruleset creation using `landlock_create_ruleset()` syscall and get `ruleset_fd` as return value:
```c
    int ruleset_fd = landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
    if (ruleset_fd < 0) {
        perror("landlock_create_ruleset");
        return 1;
    }
```

Then, prevent the process from gaining new privileges using `prctl`:
```c
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        perror("prctl(PR_SET_NO_NEW_PRIVS)");
        close(ruleset_fd);
        return 1;
    }
```

Finally, enforce rules using `landlock_restrict_self()` syscall:
```c
    if (landlock_restrict_self(ruleset_fd)) {
        perror("landlock_restrict_self");
        close(ruleset_fd);
        return 1;
    }
```

Compile the code `gcc -Wall landlock_no_tcp.c -o landlock_no_tcp`, then, let's test it `./landlock_no_tcp ssh 192.168.1.2`
```sh
ssh: connect to host 192.168.1.2 port 22: Permission denied
```

We can see why this happened using `strace ./landlock_no_tcp ssh 192.168.1.2`:
```sh
[...]
socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 3
fcntl(3, F_SETFD, FD_CLOEXEC)           = 0
getsockname(3, {sa_family=AF_INET, sin_port=htons(0), sin_addr=inet_addr("0.0.0.0")}, [128 => 16]) = 0
setsockopt(3, SOL_IP, IP_TOS, [16], 4)  = 0
connect(3, {sa_family=AF_INET, sin_port=htons(22), sin_addr=inet_addr("192.168.1.2")}, 16) = -1 EACCES (Permission denied)
close(3)                                = 0
getpid()                                = 2245
write(2, "ssh: connect to host 192.168.1.2"..., 61ssh: connect to host 192.168.1.2 port 22: Permission denied
) = 61
munmap(0x7f9c722d3000, 135168)          = 0
exit_group(255)                         = ?
+++ exited with 255 +++
```

We can see what is going to happen if we use sudo `strace ./landlock_no_tcp sudo ssh 192.168.1.2`
```sh
[...]
read(3, "", 4096)                       = 0
close(3)                                = 0
geteuid()                               = 1000
prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)  = 1
openat(AT_FDCWD, "/usr/share/locale/locale.alias", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=2996, ...}) = 0
read(3, "# Locale name alias data base.\n#"..., 4096) = 2996
read(3, "", 4096)                       = 0
close(3)                                = 0
write(2, "sudo", 4sudo)                     = 4
write(2, ": ", 2: )                       = 2
write(2, "The \"no new privileges\" flag is "..., 78The "no new privileges" flag is set, which prevents sudo from running as root.) = 78
[...]
```

The output should look like the following:
```sh
sudo: The "no new privileges" flag is set, which prevents sudo from running as root.
sudo: If sudo is running in a container, you may need to adjust the container configuration to disable the flag.
```

Below another simplified example illustrating how to use Landlock to allow read-only access to `/usr`  and `/etc/ssl/certs` while permitting only TCP port 443 connections, and denying all other filesystem and TCP actions:

```c
#define _GNU_SOURCE
#include <linux/landlock.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

static inline int landlock_create_ruleset(const struct landlock_ruleset_attr *attr, size_t size, __u32 flags) {
    return syscall(__NR_landlock_create_ruleset, attr, size, flags);
}

static inline int landlock_add_rule(int ruleset_fd, enum landlock_rule_type rule_type, const void *rule_attr, __u32 flags) {
    return syscall(__NR_landlock_add_rule, ruleset_fd, rule_type, rule_attr, flags);
}

static inline int landlock_restrict_self(int ruleset_fd, __u32 flags) {
    return syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <binary-to-sandbox> [args...]\n", argv[0]);
        return 1;
    }

    int abi = landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 0) {
        fprintf(stderr, "Landlock not available. Running %s without restrictions.\n", argv[1]);
        execvp(argv[1], &argv[1]);
        perror("execvp");
        return 1;
    }

    struct landlock_ruleset_attr ruleset_attr = {
        .handled_access_fs =
            LANDLOCK_ACCESS_FS_EXECUTE |
            LANDLOCK_ACCESS_FS_READ_FILE |
            LANDLOCK_ACCESS_FS_READ_DIR,

        .handled_access_net = LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP,
    };

    int ruleset_fd = landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
    if (ruleset_fd < 0) {
        perror("landlock_create_ruleset");
        return 1;
    }

    struct landlock_path_beneath_attr usr_attr = {
        .allowed_access = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_EXECUTE
    };
    usr_attr.parent_fd = open("/usr", O_PATH | O_CLOEXEC);
    if (usr_attr.parent_fd < 0) {
        perror("open /usr");
        close(ruleset_fd);
        return 1;
    }
    if (landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &usr_attr, 0) < 0) {
        perror("landlock_add_rule (/usr)");
        close(usr_attr.parent_fd);
        close(ruleset_fd);
        return 1;
    }
    close(usr_attr.parent_fd);

    struct landlock_path_beneath_attr ssl_attr = {
        .allowed_access = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR
    };
    ssl_attr.parent_fd = open("/etc/ssl/certs", O_PATH | O_CLOEXEC);
    if (ssl_attr.parent_fd < 0) {
        perror("open /etc/ssl/certs");
        close(ruleset_fd);
        return 1;
    }
    if (landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &ssl_attr, 0) < 0) {
        perror("landlock_add_rule (/etc/ssl/certs)");
        close(ssl_attr.parent_fd);
        close(ruleset_fd);
        return 1;
    }
    close(ssl_attr.parent_fd);

    if (abi >= 4) { 
        struct landlock_net_port_attr net_attr = {
            .allowed_access = LANDLOCK_ACCESS_NET_CONNECT_TCP,
            .port = 443
        };
        if (landlock_add_rule(ruleset_fd, LANDLOCK_RULE_NET_PORT, &net_attr, 0) < 0) {
            perror("landlock_add_rule (HTTPS only)");
            close(ruleset_fd);
            return 1;
        }
    }

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        perror("prctl(PR_SET_NO_NEW_PRIVS)");
        close(ruleset_fd);
        return 1;
    }

    if (landlock_restrict_self(ruleset_fd, 0)) {
        perror("landlock_restrict_self");
        close(ruleset_fd);
        return 1;
    }

    close(ruleset_fd);

    execvp(argv[1], &argv[1]);
    perror("execvp failed");
    return 1;
}
```

Here we defined rules for file access and network access then ruleset creation :
```c
    struct landlock_ruleset_attr ruleset_attr = {
        .handled_access_fs =
            LANDLOCK_ACCESS_FS_EXECUTE |
            LANDLOCK_ACCESS_FS_READ_FILE |
            LANDLOCK_ACCESS_FS_READ_DIR,

        .handled_access_net = LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP,
    };
    
    int ruleset_fd = landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
    if (ruleset_fd < 0) {
        perror("landlock_create_ruleset");
        return 1;
    }
```

Then, allow read-only and execute rights to `/usr`:
```c
    struct landlock_path_beneath_attr usr_attr = {
        .allowed_access = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_EXECUTE
    };
    usr_attr.parent_fd = open("/usr", O_PATH | O_CLOEXEC);
    if (usr_attr.parent_fd < 0) {
        perror("open /usr");
        close(ruleset_fd);
        return 1;
    }
    if (landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &usr_attr, 0) < 0) {
        perror("landlock_add_rule (/usr)");
        close(usr_attr.parent_fd);
        close(ruleset_fd);
        return 1;
    }
    close(usr_attr.parent_fd);
```

Then, allow read-only access to `/etc/ssl/certs`:
```c
    struct landlock_path_beneath_attr ssl_attr = {
        .allowed_access = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR
    };
    ssl_attr.parent_fd = open("/etc/ssl/certs", O_PATH | O_CLOEXEC);
    if (ssl_attr.parent_fd < 0) {
        perror("open /etc/ssl/certs");
        close(ruleset_fd);
        return 1;
    }
    if (landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &ssl_attr, 0) < 0) {
        perror("landlock_add_rule (/etc/ssl/certs)");
        close(ssl_attr.parent_fd);
        close(ruleset_fd);
        return 1;
    }
    close(ssl_attr.parent_fd);
```

Next, ensure network control is supported by the kernel then allow only TCP port 443:
```c
    if (abi >= 4) {
        struct landlock_net_port_attr net_attr = {
            .allowed_access = LANDLOCK_ACCESS_NET_CONNECT_TCP,
            .port = 443
        };
        if (landlock_add_rule(ruleset_fd, LANDLOCK_RULE_NET_PORT, &net_attr, 0) < 0) {
            perror("landlock_add_rule (HTTPS only)");
            close(ruleset_fd);
            return 1;
        }
    }
```

Running `./landlock_tcp_bin curl https://8.8.8.8` TCP port 443:
```sh
<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">
<TITLE>302 Moved</TITLE></HEAD><BODY>
<H1>302 Moved</H1>
The document has moved
<A HREF="https://dns.google/">here</A>.
</BODY></HTML>
```

Running `./landlock_tcp_bin curl http://1.1.1.1` TCP port 80:
```sh
curl: (7) Failed to connect to 1.1.1.1 port 80 after 0 ms: Could not connect to server
```

Running `./landlock_tcp_bin ls /etc`
```sh
ls: cannot open directory '/etc': Permission denied
```

Let's move on to some tools that can help with advanced monitoring and control or a kind of next-level firewalling.
