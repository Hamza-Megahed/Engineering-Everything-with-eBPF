---
title: Introduction
description: Plain language snapshot of eBPF as tiny programs running safely in the Linux kernel.
weight: 2
---

**eBPF** (Extended Berkeley Packet Filter) is a revolutionary in-kernel virtual machine that allows developers to execute custom programs directly within the Linux kernel. Unlike traditional approaches, which require recompiling or modifying the kernel, eBPF enables the dynamic injection of code, providing a safe and efficient way to extend kernel functionality without rebooting the system.

eBPF programs are typically written in a restricted subset of C, compiled into bytecode, and then loaded into the kernel using the `bpf()` system call (which will be explained in more detail later). Once loaded, these programs can be attached to various hooks or events within the kernel, such as system calls, network packets, and tracepoints. The execution of eBPF programs is governed by strict safety checks to prevent them from crashing the kernel or accessing unauthorized memory areas.

In simpler terms, think of eBPF as a sandboxed virtual machine inside the kernel that can observe and modify system behavior safely and efficiently. This technology has opened up new possibilities for performance monitoring, networking enhancements, and security enforcement.

{{< alert title="Note" >}}eBPF is not a virtual machine in the traditional sense but rather a mechanism for executing special-purpose bytecode within the kernel.{{< /alert >}}


### Key Capabilities of eBPF

1. **Tracing**: eBPF provides powerful tracing capabilities that allow developers to observe and analyze the behavior of the kernel and user-space applications. By attaching eBPF programs to tracepoints, kprobes (kernel probes), and uprobes (user-space probes), you can gather detailed insights into system performance and diagnose issues in real-time (which will be explained later).
    
    - **Example Use Case**: Using eBPF you can trace file open operations to see which files are being accessed by a process by attacheing an eBPF program to the `open()` system call tracepoint and prints the filename each time a file is opened. In cybersecurity, it helps detect unauthorized file access, enabling early threat detection and compliance monitoring.
    
2. **Networking**: eBPF enables advanced networking features by allowing custom packet filtering, modification, and routing logic to run within the kernel. This eliminates the need to copy packets to user space, reducing latency and improving performance.
    
    - **Example Use Case**: The XDP (eXpress Data Path) framework uses eBPF to perform high-speed packet processing at the network interface card (NIC) level. This is particularly useful for applications like DDoS mitigation and load balancing.
        
3. **Security**: eBPF enhances system security by allowing real-time monitoring and enforcement of security policies. With eBPF, you can detect and respond to security events, such as unauthorized system calls or suspicious network activity.
    
    - **Example Use Case**: Seccomp can be used to enforce security policies by restricting the system calls a process is allowed to make. In containerized environments or isolated applications, seccomp helps ensure that only necessary and authorized system calls are permitted, preventing potential security breaches by blocking access to sensitive kernel functionality.
        
4. **Observability**: eBPF provides deep observability into system behavior by allowing the collection of detailed telemetry data. Unlike traditional logging and metrics, eBPF-based observability can capture low-level events without requiring changes to application code.
    
    - **Example Use Case**: Tools like `bcc` (BPF Compiler Collection) and `bpftrace` allow you to profile CPU usage, memory access, and I/O operations in real-time, helping to identify performance bottlenecks and optimize system performance. In cybersecurity, this can be used to monitor for anomalous system behavior, such as unusual CPU spikes or memory access patterns, which could indicate a malware infection or unauthorized activities.
    

Don't worry if some of these concepts seem challenging right now; we’ll break them down with clear examples throughout the book. Now, let’s dive into the history of eBPF.
