---
title: Lightweight Tunnels
description: LWT IN OUT and XMIT hooks in the routing stack where eBPF can add or strip headers perform NAT or steer packets into overlays with minimal extra latency.
weight: 3
---

Lightweight Tunnels (LWT) in the Linux kernel provides a way to handle network tunneling defined in `/net/core/lwtunnel.c`. Rather than being standalone protocols like TCP or UDP, these encapsulation types are identifiers used to select a specific method of wrapping packets for tunneling. For example, MPLS encapsulation wraps packets with an MPLS label stack, while SEG6 encapsulation uses an IPv6 Segment Routing header. The code below shows how these encapsulation types are mapped to human‐readable form:

```c
switch (encap_type) {
	case LWTUNNEL_ENCAP_MPLS:
		return "MPLS";
	case LWTUNNEL_ENCAP_ILA:
		return "ILA";
	case LWTUNNEL_ENCAP_SEG6:
		return "SEG6";
	case LWTUNNEL_ENCAP_BPF:
		return "BPF";
	case LWTUNNEL_ENCAP_SEG6_LOCAL:
		return "SEG6LOCAL";
	case LWTUNNEL_ENCAP_RPL:
		return "RPL";
	case LWTUNNEL_ENCAP_IOAM6:
		return "IOAM6";
	case LWTUNNEL_ENCAP_XFRM:
		return NULL;
	case LWTUNNEL_ENCAP_IP6:
	case LWTUNNEL_ENCAP_IP:
	case LWTUNNEL_ENCAP_NONE:
	case __LWTUNNEL_ENCAP_MAX:
		WARN_ON(1);
		break;
	}
	return NULL;
}
```
There are four types of programs in eBPF to handle Lightweight Tunnels. Among them, `BPF_PROG_TYPE_LWT_IN` and `BPF_PROG_TYPE_LWT_OUT` are the most important.
`BPF_PROG_TYPE_LWT_IN` can be attached to incoming path of Lightweight Tunnel and uses `lwt_in` as section definition while `BPF_PROG_TYPE_LWT_OUT` can be attached the outgoing path of Lightweight Tunnel and used `lwt_out` as section definition. Both applications can add more control to the route by allowing or dropping of traffic and also inspect the traffic on a specific route but they are not allowed to modify. Information on the full capabilities of these LWT eBPF program types is limited, making them hard to fully explore.

{{< alert title="Note" >}}Both LWT "in" and "out" programs run at a stage where the packet data has already been processed by the routing stack and the kernel has already stripped the Layer 2 (Ethernet) header. This means that the packet data passed to your eBPF program starts directly with the IP header.{{< /alert >}}

We can build a simple `BPF_PROG_TYPE_LWT_OUT` program for testing without the need to make Lightweight Tunnel. The idea of this program is to block outgoing 8080 connection from 10.0.0.2 to 10.0.0.3.

```c
#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/in.h>

char _license[] SEC("license") = "GPL";

SEC("lwt_out")
int drop_egress_port_8080(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct iphdr *iph = data;
    if ((void *)iph + sizeof(*iph) > data_end)
        return BPF_OK;

    if (iph->protocol != IPPROTO_TCP)
        return BPF_OK;

    int ip_header_length = iph->ihl * 4;

    struct tcphdr *tcph = data + ip_header_length;
    if ((void *)tcph + sizeof(*tcph) > data_end)
        return BPF_OK;
    
    if (bpf_ntohs(tcph->dest) == 8080) {
        bpf_printk("Dropping egress packet to port 8080\n");
        return BPF_DROP;
    }

    return BPF_OK;
}

```

Here we utilize another technique to access packet fields without manually calculating offsets for each field. For example, we defined `struct iphdr ip;` from `linux/ip.h` header which allows us to directly access protocol fields within IP header. `iphdr` structure has the following definition:

```c
struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	ihl:4,
		version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	__u8	version:4,
  		ihl:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	__u8	tos;
	__be16	tot_len;
	__be16	id;
	__be16	frag_off;
	__u8	ttl;
	__u8	protocol;
	__sum16	check;
	__struct_group(/* no tag */, addrs, /* no attrs */,
		__be32	saddr;
		__be32	daddr;
	);
};
```
This enables us to check if the packet is TCP using `if (ip.protocol != IPPROTO_TCP)`. If the packet is TCP, it passes the check with `BPF_OK` and proceeds to the next check. 
`tcphdr`structure has the following definition in `linux/tcp.h`:

```c
struct tcphdr {
	__be16	source;
	__be16	dest;
	__be32	seq;
	__be32	ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16	res1:4,
		doff:4,
		fin:1,
		syn:1,
		rst:1,
		psh:1,
		ack:1,
		urg:1,
		ece:1,
		cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16	doff:4,
		res1:4,
		cwr:1,
		ece:1,
		urg:1,
		ack:1,
		psh:1,
		rst:1,
		syn:1,
		fin:1;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif
	__be16	window;
	__sum16	check;
	__be16	urg_ptr;
};
```

The final check is validating if the destination port is 8080 then it will drop the packet and print out message using `bpf_printk`. 

{{< alert title="Note" >}}The eBPF verifier requires explicit boundary checks to ensure that any access to packet data is safe. Without these checks, the verifier will reject your program, as it can't guarantee that your memory accesses remain within the valid packet boundaries.{{< /alert >}}

Compile the eBPF program and attach it to your interface or tunnel using something similar to the following:
```sh
sudo ip route add 10.0.0.3/32 encap bpf out obj drop_egress_8080.o section lwt_out dev tun0
```
Next, setup a web server on the remote machine
```sh
python3 -m http.server 8080
```
Then, from the eBPF machine run
```sh
curl http://10.0.0.3:8080/index.html
```
You should notice that the connection is dropped and messages in `/sys/kernel/debug/tracing/trace_pipe`
```sh
          <idle>-0       [003] b.s21  6747.667466: bpf_trace_printk: Dropping egress packet to port 8080
          <idle>-0       [003] b.s21  6748.729064: bpf_trace_printk: Dropping egress packet to port 8080
          <idle>-0       [003] b.s21  6749.753690: bpf_trace_printk: Dropping egress packet to port 8080
          <idle>-0       [003] b.s21  6750.777898: bpf_trace_printk: Dropping egress packet to port 8080
            curl-3437    [001] b..11  8589.106765: bpf_trace_printk: Dropping egress packet to port 8080
          <idle>-0       [001] b.s31  8590.112358: bpf_trace_printk: Dropping egress packet to port 8080
```

This program for sure can be used to inspecting or monitoring, all you need to do is to replace `BPF_DROP` with `BPF_OK`. Now let's look at `BPF_PROG_TYPE_LWT_IN` programs which can be attached to incoming path of Lightweight Tunnel. Let's use the previous example and make some changes. Modifying the code to block ingress traffic originated from 10.0.0.3 on port 8080

```c
#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/in.h>

#define TARGET_IP 0x0A000003  // 10.0.0.3 in hexadecimal

char _license[] SEC("license") = "GPL";

SEC("lwt_in")
int drop_ingress_port_8080(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct iphdr *iph = data;
    if ((void *)iph + sizeof(*iph) > data_end)
        return BPF_OK;
    if (iph->protocol != IPPROTO_TCP)
        return BPF_OK;

    int ip_header_length = iph->ihl * 4;

    struct tcphdr *tcph = data + ip_header_length;
    if ((void *)tcph + sizeof(*tcph) > data_end)
        return BPF_OK;
        
    if (iph->saddr == bpf_htonl(TARGET_IP)) {

        if (bpf_ntohs(tcph->dest) == 8080) {
            bpf_printk("Dropping ingress packet to port 8080 for IP 10.0.0.3\n");
            return BPF_DROP;
        }
    }

    return BPF_OK;
}
```

Compile it then attach it using `sudo ip route replace table local local 10.0.0.2/32 encap bpf headroom 14 in obj drop_ingress_8080.o section lwt_in dev tun0`. Start a web server on eBPF machine , then from the other machine with IP address 10.0.0.3 run `curl http://10.0.0.2:8080` and you should notice that the connection is dropped and messages in `/sys/kernel/debug/tracing/trace_pipe`
```sh
    [000] b.s21    81.669152: bpf_trace_printk: Dropping ingress packet to port 8080 for IP 10.0.0.3
    [000] b.s21    82.694440: bpf_trace_printk: Dropping ingress packet to port 8080 for IP 10.0.0.3
    [000] b.s21    84.741651: bpf_trace_printk: Dropping ingress packet to port 8080 for IP 10.0.0.3
    [000] b.s21    88.773985: bpf_trace_printk: Dropping ingress packet to port 8080 for IP 10.0.0.3
```

I hope these two examples were easy and straightforward, and that LWT is now clearer. Next, we'll explore the Traffic Control subsystem, which can direct and manage traffic effectively.
