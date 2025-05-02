---
title: Tail call
description: One eBPF program can jump straight into another without returning which lets you chain logic and sidestep the per-program instruction limit while adding almost no overhead.
weight: 5
---

Tail calls in eBPF let you chain together multiple BPF programs, effectively bypassing the instruction limit imposed on individual programs which is around 4096 instructions before kernel 5.2 and now the limit is one million instructions. Tail calls can also be used to break up the code logic into multiple parts to enable modular design. Tail call transfers control from one eBPF program to another without returning to the caller. 1. The verifier ensures that tail calls do not lead to unbounded recursion and that the jump is safe. It also reduces the effective stack size available (e.g., from 512 bytes to 256 bytes) when tail calls are used with BPF-to-BPF function calls.

#### How Tail Calls Work

1. eBPF uses a special map type called `BPF_MAP_TYPE_PROG_ARRAY` that holds file descriptors of other BPF programs. The tail call uses an index (or key) into this map to know which program to jump to.  
2. Within an eBPF program, you can use the helper function `bpf_tail_call(ctx, prog_array, key)` to transfer execution to another program. If the call is successful, the current program’s execution ends and the new program starts from its entry point.

Let's explore an example of XDP code. The idea is to have a main XDP program that inspects incoming packets and, based on the TCP destination port, uses a tail call to jump to the appropriate program—one for port 8080 and one for port 22.
```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 2);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} prog_array SEC(".maps");

char _license[] SEC("license") = "GPL";

SEC("xdp")
int main_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr *iph;
    struct tcphdr *tcph;

    if (data + sizeof(*eth) > data_end)
        return XDP_ABORTED;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    iph = data + sizeof(*eth);
    if ((void *)iph + sizeof(*iph) > data_end)
        return XDP_ABORTED;

    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    tcph = (void *)iph + (iph->ihl * 4);
    if ((void *)tcph + sizeof(*tcph) > data_end)
        return XDP_ABORTED;

    int dport = bpf_ntohs(tcph->dest);

    if (dport == 8080) {
        int key = 0;
        bpf_tail_call(ctx, &prog_array, key);
    } else if (dport == 22) {
        int key = 1;
        bpf_tail_call(ctx, &prog_array, key);
    }

    return XDP_PASS;
}

SEC("xdp")
int port8080_prog(struct xdp_md *ctx)
{
    bpf_printk("Packet to port 8080 processed\n");
    return XDP_PASS;
}

SEC("xdp")
int port22_prog(struct xdp_md *ctx)
{
    bpf_printk("Packet to port 22 processed\n");
    return XDP_PASS;
}
```

User-space code:
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include "tail_call.skel.h"

#ifndef libbpf_is_err
#define libbpf_is_err(ptr) ((unsigned long)(ptr) > (unsigned long)-1000L)
#endif

int main(int argc, char **argv)
{
    struct tail_call *skel;
    struct bpf_link *link = NULL;
    int err, key, prog_fd;
    int ifindex;
    const char *ifname;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }
    ifname = argv[1];

    skel = tail_call__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    err = tail_call__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    key = 0;
    prog_fd = bpf_program__fd(skel->progs.port8080_prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Invalid FD for port8080_prog\n");
        goto cleanup;
    }
    err = bpf_map__update_elem(skel->maps.prog_array,
                               &key, sizeof(key),
                               &prog_fd, sizeof(prog_fd),
                               0);
    if (err) {
        fprintf(stderr, "Failed to update prog_array for port8080_prog: %d\n", err);
        goto cleanup;
    }

    key = 1;
    prog_fd = bpf_program__fd(skel->progs.port22_prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Invalid FD for port22_prog\n");
        goto cleanup;
    }
    err = bpf_map__update_elem(skel->maps.prog_array,
                               &key, sizeof(key),
                               &prog_fd, sizeof(prog_fd),
                               0);
    if (err) {
        fprintf(stderr, "Failed to update prog_array for port22_prog: %d\n", err);
        goto cleanup;
    }

    ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        perror("if_nametoindex");
        goto cleanup;
    }

    link = bpf_program__attach_xdp(skel->progs.main_prog, ifindex);
    if (libbpf_is_err(link)) {
        err = libbpf_get_error(link);
        fprintf(stderr, "Failed to attach XDP program on %s (ifindex: %d): %d\n",
                ifname, ifindex, err);
        link = NULL;
        goto cleanup;
    }

    printf("XDP program loaded and tail calls configured on interface %s (ifindex: %d).\n",
           ifname, ifindex);
    printf("Press Ctrl+C to exit...\n");

    while (1)
        sleep(1);

cleanup:
    if (link)
        bpf_link__destroy(link);
    tail_call__destroy(skel);
    return err < 0 ? -err : 0;
}
```

<p style="text-align: center;">
  <img src="/images/docs/chapter6/tail-call.png" alt="Centered image" />
</p>

Compile the code 
```sh
clang -g -O2 -target bpf -c tail_call.c -o tail_call.o
sudo bpftool gen skeleton tail_call.o > tail_call.skel.h
clang -o loader loader.c -lbpf
```

Run the loader using `sudo ./loader enp1s0` . Open trace buffer `sudo cat /sys/kernel/debug/tracing/trace_pipe`:
```sh
<idle>-0             [003] ..s2.  8853.538349: bpf_trace_printk: Packet to port 8080 processed
<idle>-0             [003] .Ns2.  8853.539270: bpf_trace_printk: Packet to port 8080 processed
<idle>-0             [003] .Ns2.  8853.539279: bpf_trace_printk: Packet to port 8080 processed
gnome-shell-2539     [003] ..s1.  8853.541321: bpf_trace_printk: Packet to port 8080 processed
gnome-shell-2539     [003] ..s1.  8853.541334: bpf_trace_printk: Packet to port 8080 processed
<idle>-0             [003] ..s2.  8860.777125: bpf_trace_printk: Packet to port 22 processed
<idle>-0             [003] ..s2.  8860.777420: bpf_trace_printk: Packet to port 22 processed
<idle>-0             [003] ..s2.  8860.777611: bpf_trace_printk: Packet to port 22 processed
llvmpipe-1-2569      [003] ..s1.  8860.783551: bpf_trace_printk: Packet to port 22 processed
```
