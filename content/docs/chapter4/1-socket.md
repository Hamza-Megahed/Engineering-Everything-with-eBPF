---
title: Socket Filter
description: Classic filtering on a socket before data reaches user space.
weight: 2
---

We saw socket filter program type definition in previous chapter, a `SOCKET_FILTER` type program executes whenever a packet arrives at the socket it is attached to give you access to examine all packets passed through the socket and can't give you control to modify packets and believe me, it's easier than you think, all you have to do is to look at the the entire packet structure as we will see. Socket filter eBPF programs are classified under the program type `BPF_PROG_TYPE_SOCKET_FILTER`.

The socket buffer (or `sk_buff`) is the primary structure used within the Linux kernel to represent network packets. It stores not only the packet data itself but also various metadata such as header pointers, packet lengths, protocol information, and state flags. `sk_buff` is defined in `include/linux/skbuff.h` and it has four major pointers:
1. head: A pointer to the beginning of the allocated memory buffer for the packet.
2. data: A pointer to the beginning of the valid packet data within the buffer.
3. tail: A pointer that marks the end of the valid data currently stored in the buffer.
4. end: A pointer to the end of the allocated memory region.

These four pointers provide the framework for managing the packet data within a single contiguous memory allocation. The sk_buff's allocated memory region divided into several logical segments that these pointers describe:
1. Headroom: Space before the packet data for prepending headers.
2. Data: The actual packet contents (headers and payload).
3. Tailroom: Space after the packet data for appending headers or trailers.
4. skb_shared_info: Metadata structure for reference counting, fragments, and other shared data.

<p style="text-align: center;">
  <img src="/images/docs/chapter4/socket-sk_buff.png" alt="Centered image" />
</p>

`__sk_buff` data structure is a simplified version of `sk_buff` structure that’s exposed to eBPF programs. It provides a subset of information about a network packet that eBPF programs can use to inspect, filter, or even modify packets without needing access to all the internals of the full `sk_buff`.

`__sk_buff` used as context for eBPF programs such as in socket filter programs. `__sk_buff` is defined in `include/uapi/linux/bpf.h` as:
```c
struct __sk_buff {
	__u32 len;
	__u32 pkt_type;
	__u32 mark;
	__u32 queue_mapping;
	__u32 protocol;
	__u32 vlan_present;
	__u32 vlan_tci;
	__u32 vlan_proto;
	__u32 priority;
	__u32 ingress_ifindex;
	__u32 ifindex;
	__u32 tc_index;
	__u32 cb[5];
	__u32 hash;
	__u32 tc_classid;
	__u32 data;
	__u32 data_end;
	__u32 napi_id;
	__u32 family;
	__u32 remote_ip4;
	__u32 local_ip4;
	__u32 remote_ip6[4];
	__u32 local_ip6[4];
	__u32 remote_port;
	__u32 local_port;
	__u32 data_meta;
	__bpf_md_ptr(struct bpf_flow_keys *, flow_keys);
	__u64 tstamp;
	__u32 wire_len;
	__u32 gso_segs;
	__bpf_md_ptr(struct bpf_sock *, sk);
	__u32 gso_size;
	__u8  tstamp_type;
	__u32 :24;
	__u64 hwtstamp;
};
```

Therefore, to detect an ICMP echo request packet (as in the following example), you need to perform the following checks: first, verify that it's an IPv4 packet. If it is, then confirm that the protocol is ICMP. Finally, check if the ICMP type is an echo request or an echo reply all of that is just by reading `__sk_buff` using `bpf_skb_load_bytes` . `bpf_skb_load_bytes` is a helper function which can be used to load `data` from a packet and it has the following prototype:
```c
`static long (* const bpf_skb_load_bytes)(const void *skb, __u32 offset, void *to, __u32 len) = (void *) 26;`
```
`bpf_skb_load_bytes` takes a pointer to `sk_buff` , offset which means which part of the packet you want to load or extract, a pointer to a location where you want to store the loaded or extracted data and finally, the length you want to extract.

```c
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define ETH_TYPE     12 // EtherType
#define ETH_HLEN     14 // ETH header length 
#define ICMP_LEN     34 // ICMP header start point
#define ETH_P_IP     0x0800 // Internet Protocol packet
#define IPPROTO_ICMP 1 // Echo request

char _license[] SEC("license") = "GPL";

SEC("socket")
int icmp_filter_prog(struct __sk_buff *skb)
{
    __u16 eth_proto = 0;

    if (bpf_skb_load_bytes(skb, ETH_TYPE, &eth_proto, sizeof(eth_proto)) < 0)
        return 0;

    eth_proto = bpf_ntohs(eth_proto);
    if (eth_proto != ETH_P_IP) {
        return 0;
    }

    __u8 ip_version = 0;
    if (bpf_skb_load_bytes(skb, ETH_HLEN, &ip_version, sizeof(ip_version)) < 0)
        return 0;

    ip_version = ip_version >> 4;
    if (ip_version != 4) {
        return 0;
    }

    __u8 ip_proto = 0;
    if (bpf_skb_load_bytes(skb, ETH_HLEN + 9, &ip_proto, sizeof(ip_proto)) < 0)
        return 0;
    if (ip_proto != IPPROTO_ICMP) {
        return 0;
    }

    __u8 icmp_type = 0;
    if (bpf_skb_load_bytes(skb, ICMP_LEN, &icmp_type, sizeof(icmp_type)) < 0)
        return 0;

    if (icmp_type != 8) {
        return 0;
    }

    return skb->len;
}
```

We need to keep the following diagram in front of us to understand this code:
<p style="text-align: center;">
  <img src="/images/docs/chapter4/socket-example1-1.png" alt="Centered image" />
</p>

```c
#define ETH_TYPE     12 // EtherType
#define ETH_HLEN     14 // ETH header length 
#define ICMP_LEN     34 // ICMP header start point
#define ETH_P_IP     0x0800 // Internet Protocol packet
#define IPPROTO_ICMP 1 // Echo request

char _license[] SEC("license") = "GPL";

SEC("socket")
int icmp_filter_prog(struct __sk_buff *skb)
{
    int offset = 0;
    __u16 eth_proto = 0;

    if (bpf_skb_load_bytes(skb, ETH_TYPE, &eth_proto, sizeof(eth_proto)) < 0)
        return 0;

    eth_proto = bpf_ntohs(eth_proto);
    if (eth_proto != ETH_P_IP) {
        return 0;
    }
```

First, we defined Ethernet type , Ethernet header length which is the start point of IP header, ICMP header length (Ethernet header length + IP header length). The program is defined as socket as you can see in SEC, then `__sk_buff` as context.
The first thing to is extract Ethernet type to determine of the packet is IP packet or not, all we need to do is get the following place in Ethernet header
<p style="text-align: center;">
  <img src="/images/docs/chapter4/socket-example1-2.png" alt="Centered image" />
</p>

`bpf_skb_load_bytes` helper function will do that `bpf_skb_load_bytes(skb, ETH_TYPE, &eth_proto, sizeof(eth_proto))`, it will extract EtherType for us and save the output in `eth_proto`. We define `eth_proto` as `__u16` which is unsigned 16-bit integer and that's why `bpf_skb_load_bytes` will extract in that case 2 bytes because we specified the length we need as `sizeof(eth_proto)`.
Then we used `bpf_ntohs` macro which used to convert multi-byte values like EtherType, IP addresses, and port numbers from network byte order (big-endian) to host byte order, then we we perform out check if the packet is IP packet by comparing the retrieved value with 0x0800 which represent IP EtherType, as defined in the `/include/uapi/linux/if_ether.h` kernel source code. If the value does not match, the code will drop the packet from the socket.

The same concept goes with IP version part:
```c
    __u8 ip_version = 0;
    if (bpf_skb_load_bytes(skb, ETH_HLEN, &ip_version, sizeof(ip_version)) < 0)
        return 0;

    ip_version = ip_version >> 4;
    if (ip_version != 4) {
        return 0;
    }
```
<p style="text-align: center;">
  <img src="/images/docs/chapter4/socket-example1-3.png" alt="Centered image" />
</p>

We need to extract the first 1 byte (`__u8`) of the IP header. The top nibble (the first 4 bits) is the version of IP `ip_version = ip_version >> 4` followed by checking if the version is 4 or drop the packet from the socket. Then we need to move to Protocol field in IP header to check if the packet is ICMP by comparing the retrieved value with 1 which represents ICMP as defined in `/include/uapi/linux/in.h` kernel source code. If the value does not match, the code will drop the packet from the socket.
{{< alert title="Note" >}}We assumed that IP header has fixed size 20 byes just for the sake of simplifying, but in reality you should check IP header size from Ver/IHL first.{{< /alert >}}

<p style="text-align: center;">
  <img src="/images/docs/chapter4/socket-example1-4.png" alt="Centered image" />
</p>

Then the last part is moving to the first byte of ICMP header and check if the packet is echo request or drop the packet from the socket. Finally, `return skb->len` indicated that the packet should be accepted and passed along to user space or to further processing. Let's move to the user-space code.

```c
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "icmp_socket_filter.skel.h"

int main(void)
{
    struct icmp_socket_filter *skel = NULL;
    int sock_fd = -1, prog_fd = -1, err;

    skel = icmp_socket_filter__open();
    if (!skel) {
        fprintf(stderr, "Failed to open skeleton\n");
        return 1;
    }

    err = icmp_socket_filter__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load skeleton: %d\n", err);
        goto cleanup;
    }

    prog_fd = bpf_program__fd(skel->progs.icmp_filter_prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to get program FD\n");
        goto cleanup;
    }

    sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_fd < 0) {
        fprintf(stderr, "Error creating raw socket: %d\n", errno);
        goto cleanup;
    }

    err = setsockopt(sock_fd, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd));
    if (err) {
        fprintf(stderr, "setsockopt(SO_ATTACH_BPF) failed: %d\n", errno);
        goto cleanup;
    }

    printf("Only ICMP Echo Requests (ping) will be seen by this raw socket.\n");

    while (1) {
        unsigned char buf[2048];
        ssize_t n = read(sock_fd, buf, sizeof(buf));
        if (n < 0) {
            perror("read");
            break;
        }
        printf("Received %zd bytes (ICMP echo request) on this socket\n", n);
    }

cleanup:
    if (sock_fd >= 0)
        close(sock_fd);
    icmp_socket_filter__destroy(skel);
    return 0;
}
```

We made a few modifications to the user-space file , instead of attaching the eBPF program directly, we first,retrieve the file descriptor of the loaded eBPF program as shown below:
```c
    prog_fd = bpf_program__fd(skel->progs.icmp_filter_prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to get program FD\n");
        goto cleanup;
    }
```

The next step is creating a socket as shown in the following:
```c
    sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_fd < 0) {
        fprintf(stderr, "Error creating raw socket: %d\n", errno);
        goto cleanup;
    }
```

Finally, attach the file descriptor of the loaded eBPF program to the created socket as in the following:
```c
err = setsockopt(sock_fd, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd));
    if (err) {
        fprintf(stderr, "setsockopt(SO_ATTACH_BPF) failed: %d\n", errno);
        goto cleanup;
    }
```

Compile the eBPF program, then generate skeleton file. After that, compile the loader. Start the program and ping from the same machine or from an external machine. You should see output similar to the following:
```sh
Only ICMP Echo Requests (ping) will be seen by this raw socket.
Received 98 bytes (ICMP echo request) on this socket
Received 98 bytes (ICMP echo request) on this socket
Received 98 bytes (ICMP echo request) on this socket
Received 98 bytes (ICMP echo request) on this socket
Received 98 bytes (ICMP echo request) on this socket
```

Let's demonstrate another simple example and yet has important benefits which is extracting a keyword from HTTP request by storing only 64 bytes from the request's TCP payload in a buffer and searching that buffer. The buffer size significantly reduced so we don't need to address IP fragmentation. By performing some checks as we did in the previous example until we get to the TCP payload and search in it by a magic word.
```c
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define ETH_TYPE     12
#define ETH_HLEN     14
#define ETH_P_IP     0x0800  // IPv4 EtherType
#define IPPROTO_TCP  6
#define TCP_LEN      34 // TCP header start point

#define HTTP_PORT    8080
#define HTTP_PAYLOAD_READ_LEN 64

static __always_inline int search_substring(const char *tcp_buff, int tcp_buff_len,
                                            const char *magic_word,   int magic_word_len)
{
    if (magic_word_len == 0 || tcp_buff_len == 0 || magic_word_len > tcp_buff_len)
        return 0;

    for (int i = 0; i <= tcp_buff_len - magic_word_len; i++) {
        int j;
        for (j = 0; j < magic_word_len; j++) {
            if (tcp_buff[i + j] != magic_word[j])
                break;
        }
        if (j == magic_word_len) {
            return 1;
        }
    }
    return 0;
}


char _license[] SEC("license") = "GPL";
SEC("socket")
int http_filter_prog(struct __sk_buff *skb)
{
	const char magic_word[] = "l33t";
    int offset = 0;
    __u16 eth_proto = 0;

    if (bpf_skb_load_bytes(skb, ETH_TYPE, &eth_proto, sizeof(eth_proto)) < 0)
        return 0;

    eth_proto = bpf_ntohs(eth_proto);
    if (eth_proto != ETH_P_IP) {
        return 0;
    }

    __u8 ip_version = 0;
    if (bpf_skb_load_bytes(skb, ETH_HLEN, &ip_version, sizeof(ip_version)) < 0)
        return 0;

    ip_version = ip_version >> 4;
    if (ip_version != 4) {
        return 0;
    }
    
    __u8 ip_proto = 0;
    if (bpf_skb_load_bytes(skb, ETH_HLEN + 9, &ip_proto, sizeof(ip_proto)) < 0)
        return 0;
    if (ip_proto != IPPROTO_TCP) {
        return 0;
    }

    __u8 tcp_hdr_len = 0;
    if (bpf_skb_load_bytes(skb, TCP_LEN + 12, &tcp_hdr_len, 1) < 0)
        return 0;
    tcp_hdr_len >>= 4;
    tcp_hdr_len *= 4;

    __u16 dport = 0;
    if (bpf_skb_load_bytes(skb, TCP_LEN + 2, &dport, sizeof(dport)) < 0)
        return 0;
    dport = bpf_ntohs(dport);
    if (dport != HTTP_PORT) {
        return 0;
    }

    offset += tcp_hdr_len;
    char http_buf[HTTP_PAYLOAD_READ_LEN] = {0};
    if (bpf_skb_load_bytes(skb, TCP_LEN + tcp_hdr_len, &http_buf, sizeof(http_buf)) < 0)
        return skb->len;

    bpf_printk("packet \n%s",http_buf );

    if (search_substring(http_buf, HTTP_PAYLOAD_READ_LEN, magic_word, sizeof(magic_word) - 1)) {
        bpf_printk("ALERT: Magic Word Found in the HTTP request payload\n");
    }
    return skb->len;
}
```

Keep the following diagram in front of you to understand this code:
<p style="text-align: center;">
  <img src="/images/docs/chapter4/socket-example2-1.png" alt="Centered image" />
</p>

A simple search function is added to search for "l33t" in TCP payload, it can be sent via GET request such as `/?id=l33t`. The function, `search_substring`, perfroms a basic substring search algorithm. Due to its `__always_inline` attribute, this function offers performance benefits. The function takes the payload buffer, its length, the search term, and its length as input. It returns 1 if the search term is found within the payload, and 0 otherwise. This allows for simple pattern-based filtering of network traffic within our the eBPF program.
```c
static __always_inline int search_substring(const char *tcp_buff, int tcp_buff_len,
                                            const char *magic_word,   int magic_word_len)
{
    if (magic_word_len == 0 || tcp_buff_len == 0 || magic_word_len > tcp_buff_len)
        return 0;

    for (int i = 0; i <= tcp_buff_len - magic_word_len; i++) {
        int j;
        for (j = 0; j < magic_word_len; j++) {
            if (tcp_buff[i + j] != magic_word[j])
                break;
        }
        if (j == magic_word_len) {
            return 1;
        }
    }
    return 0;
}
```

Calculating TCP header size is important because we need to know where TCP payload data begins as the size of TCP header is not fixed as in the most cases of IP header due to TCP options.
```c
    __u8 tcp_hdr_len = 0;
    if (bpf_skb_load_bytes(skb, TCP_LEN + 12, &tcp_hdr_len, 1) < 0)
        return 0;
    tcp_hdr_len >>= 4;
    tcp_hdr_len *= 4;
```
{{< alert title="Note" >}}IP header has options too but in most cases the IP header size is 20 bytes, parsing IHL in IP header will give the exact size of IP header size.{{< /alert >}}

Let's move to user-space code

```c
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>


static const char *BPF_OBJ_FILE = "http_extract.o";

int main(void)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog;
    int sock_fd = -1, prog_fd = -1, err;

    obj = bpf_object__open_file(BPF_OBJ_FILE, NULL);
    if (!obj) {
        fprintf(stderr, "Error opening BPF object file\n");
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Error loading BPF object: %d\n", err);
        bpf_object__close(obj);
        return 1;
    }

    prog = bpf_object__find_program_by_name(obj, "http_filter_prog");
    if (!prog) {
        fprintf(stderr, "Error finding BPF program by name.\n");
        bpf_object__close(obj);
        return 1;
    }

    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Error getting program FD.\n");
        bpf_object__close(obj);
        return 1;
    }

    sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_fd < 0) {
        fprintf(stderr, "Error creating raw socket: %d\n", errno);
        bpf_object__close(obj);
        return 1;
    }

    err = setsockopt(sock_fd, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd));
    if (err) {
        fprintf(stderr, "setsockopt(SO_ATTACH_BPF) failed: %d\n", errno);
        close(sock_fd);
        bpf_object__close(obj);
        return 1;
    }

    printf("BPF socket filter attached. It will detect HTTP methods on port 80.\n");

    while (1) {
        unsigned char buf[2048];
        ssize_t n = read(sock_fd, buf, sizeof(buf));
        if (n < 0) {
            perror("read");
            break;
        }

        printf("Received %zd bytes on this socket\n", n);
    }

    close(sock_fd);
    bpf_object__close(obj);
    return 0;
}
```

The first 4 bits of `Offset/Flags` field in TCP header contains the size of the TCP header ` tcp_hdr_len >>= 4` then multiplies the value by 4 to convert the header length from 32-bit words to bytes. Compile and start the program then start HTTP server on your machine on port 8080 or change `HTTP_PORT` from the code, you can use python 
```sh
python3 -m http.server 8080
```
Then curl from another box 
```sh
curl http://192.168.1.2:8080/index.html?id=l33t
```
And you will get similar results because we entered the magic word which is `l33t` in our request.
```sh
GET /index.html?id=l33t HTTP/1.1
Host: 192.168.1.2:8080
    sshd-session-1423    [000] ..s11 28817.447546: bpf_trace_printk: ALERT: Magic Word Found in the HTTP request payload
```
This program's ability to inspect network traffic is crucial for intrusion detection and web application firewalls. Its functionality enables security tools to identify suspicious patterns or malicious content as it passes through the network, allowing for proactive threat detection with minimal performance overhead.
