---
title: Bpfilter
description: A work-in-progress kernel module that translates iptables and nftables rules into eBPF bytecode so the firewall runs through the BPF verifier instead of legacy netfilter tables.
weight: 7
---

bpfilter is a eBPF-based packet filtering currently maintained by meta, designed to replace or complement traditional packet filtering systems such as netfilter/iptables. It leverages the power of eBPF programs to implement filtering directly in the kernel. bpfilter is part of a broader shift towards eBPF-driven networking, moving away from older, monolithic approaches with minimal overhead.

bpfilter consists of two parts: daemon and front-ends. Font-end such as `bfcli` which receives firewall rules from administrators and send them to the daemon (`bpfilter`). `bpfilter` daemon parses the ruleset whether provided directly as a string or loaded from a file and then translates these high-level rules into eBPF bytecode that can be executed in the kernel.

bpfilter attaches the generated eBPF programs to specific kernel hooks such as XDP, TC (Traffic Control), or netfilter hooks (like NF_PRE_ROUTING, NF_LOCAL_IN, etc.). Each hook corresponds to a different stage in the packet processing pipeline, allowing bpfilter to intercept packets as early or as late as necessary.
<p style="text-align: center;">
  <img src="/images/docs/chapter5/bpfilter-Architecture.png" alt="Centered image" />
</p>

## Install bpfilter
Follow the following instructions to install bpfilter on ubuntu 24.04/ debian 13.
Install dependencies:
```sh
sudo apt install bison clang-format clang-tidy cmake doxygen flex furo git lcov libbpf-dev libcmocka-dev libbenchmark-dev libgit2-dev libnl-3-dev python3-breathe python3-pip python3-sphinx pkgconf
```

Download bpfilter:
```sh
git clone https://github.com/facebook/bpfilter.git
```

Make bpfilter:
```sh
cd bpfilter/
export SOURCES_DIR=$(pwd)
export BUILD_DIR=$SOURCES_DIR/build
cmake -S $SOURCES_DIR -B $BUILD_DIR
make -C $BUILD_DIR
```
{{< alert title="Note" >}}bpfilter can use custom version `iptables` and `nftables` and supply your rules in either `iptables` syntax or `nftables` syntax such dropping incoming ICMP with `iptables` using `--bpf` flag as the following:  
`sudo ./iptables --bpf -D INPUT -p icmp -j DROP`

{{< /alert >}}


Follow the following instructions to install the custom `iptables` and `nftables` on ubuntu 24.04
Install dependencies:
```sh
sudo apt install autoconf libtool libmnl-dev libnftnl-dev libgmp-dev libedit-dev
```

Make the custom `iptables` and `nftables`:
```sh
make -C $BUILD_DIR nftables iptables
```

## bpfilter rules

A bpfilter ruleset is defined using chains and rules with the following structure:

```
chain $HOOK policy $POLICY
    rule
        $MATCHER
        $VERDICT
    [...]
[...]
```

```
chain $HOOK policy $POLICY
```

**$HOOK:** The kernel hook where the chain is attached. The following list is from bpfilter documentation:

```
BF_HOOK_XDP: XDP hook.
BF_HOOK_TC_INGRESS: ingress TC hook.
BF_HOOK_NF_PRE_ROUTING: similar to nftables and iptables prerouting hook.
BF_HOOK_NF_LOCAL_IN: similar to nftables and iptables input hook.
BF_HOOK_CGROUP_INGRESS: ingress cgroup hook.
BF_HOOK_CGROUP_EGRESS: egress cgroup hook.
BF_HOOK_NF_FORWARD: similar to nftables and iptables forward hook.
BF_HOOK_NF_LOCAL_OUT: similar to nftables and iptables output hook.
BF_HOOK_NF_POST_ROUTING: similar to nftables and iptables postrouting hook.
BF_HOOK_TC_EGRESS: egress TC hook.
```

**$POLICY:** The default action (typically ACCEPT or DROP) applied to packets that do not match any rule in the chain.  
**Rule**: Each rule under the chain consists of one or more `matchers` followed by a `verdict`.  
**$MATCHER:** A condition (or multiple conditions) that compares parts of the packet. For example, checking the protocol or matching an IP address.  
 **$VERDICT:** The action to take if the matchers are true. Common verdicts are:
- `ACCEPT`: Let the packet continue through the network stack.
- `DROP`: Discard the packet.
- `CONTINUE`: Continue to the next rule (often used in conjunction with packet counting).

The following tables are from the bpfilter documentation and they contain detailed information about the various matchers used in bpfilter for filtering network traffic. Each table lists the matcher name (the field of the packet), its corresponding type in bpfilter (for example, `udp.sport` or `tcp.sport`), the operator used for comparison (such as `eq`, `not`, or `range`), the payload (the value or range to compare against), and additional notes that explain usage constraints or default behaviors.

### Meta matchers

| Matches          | Type            | Operator | Payload       | Notes                                                                                                                                                             |
| ---------------- | --------------- | -------- | ------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Interface index  | `meta.ifindex`  | eq       | `$IFINDEX`    | For chains attached to an ingress hook, `$IFINDEX` is the input interface index. For chains attached to an egress hook, `$IFINDEX` is the output interface index. |
| L3 protocol      | `meta.l3_proto` | eq       | `$PROTOCOL`   | `ipv4` and `ipv6` are supported.                                                                                                                                  |
| L4 protocol      | `meta.l4_proto` | eq       | `$PROTOCOL`   | `icmp`, `icmpv6`, `tcp`, `udp` are supported.                                                                                                                     |
| Source port      | `meta.sport`    | eq       | `$PORT`       | `$PORT` is a valid port value, as a decimal integer.                                                                                                              |
| Source port      | `meta.sport`    | not      | `$PORT`       | `$PORT` is a valid port value, as a decimal integer.  *(Same payload and note as above)*                                                                          |
| Source port      | `meta.sport`    | range    | `$START-$END` | `$START` and `$END` are valid port values, as decimal integers.                                                                                                   |
| Destination port | `meta.dport`    | eq       | `$PORT`       | `$PORT` is a valid port value, as a decimal integer.                                                                                                              |
| Destination port | `meta.dport`    | not      | `$PORT`       | `$PORT` is a valid port value, as a decimal integer.  *(Same payload and note as above)*                                                                          |
| Destination port | `meta.dport`    | range    | `$START-$END` | `$START` and `$END` are valid port values, as decimal integers.                                                                                                   |


### IPv4 matchers

| Matches             | Type         | Operator | Payload         | Notes                                                                       |
|---------------------|--------------|----------|-----------------|-----------------------------------------------------------------------------|
| Source address      | `ip4.saddr`  | eq       | `$IP/$MASK`     | `/$MASK` is optional, `/32` is used by default.                             |
| Source address      | `ip4.saddr`  | not      | `$IP/$MASK`     | `/$MASK` is optional, `/32` is used by default.                             |
| Source address      | `ip4.saddr`  | in       | `{$IP[,...]}`   | Only support `/32` mask.                                                    |
| Destination address | `ip4.daddr`  | eq       | `$IP/$MASK`     | `/$MASK` is optional, `/32` is used by default.                             |
| Destination address | `ip4.daddr`  | not      | `$IP/$MASK`     | `/$MASK` is optional, `/32` is used by default.                             |
| Destination address | `ip4.daddr`  | in       | `{$IP[,...]}`   | Only support `/32` mask.                                                    |
| Protocol            | `ip4.proto`  | eq       | `$PROTOCOL`     | Only `icmp` is supported for now, more protocols will be added.             |

### IPv6 matchers

| Matches              | Type         | Operator | Payload       | Notes                                                       |
|----------------------|--------------|----------|---------------|-------------------------------------------------------------|
| Source address       | `ip6.saddr`  | eq       | `$IP/$PREFIX` | `/$PREFIX` is optional, `/128` is used by default.           |
| Source address       | `ip6.saddr`  | not      | `$IP/$PREFIX` | `/$PREFIX` is optional, `/128` is used by default.           |
| Destination address  | `ip6.daddr`  | eq       | `$IP/$PREFIX` | `/$PREFIX` is optional, `/128` is used by default.           |
| Destination address  | `ip6.daddr`  | not      | `$IP/$PREFIX` | `/$PREFIX` is optional, `/128` is used by default.           |

### TCP matchers

| Matches          | Type         | Operator | Payload        | Notes                                                                                                                      |
|------------------|--------------|----------|----------------|----------------------------------------------------------------------------------------------------------------------------|
| Source port      | `tcp.sport`  | eq       | `$PORT`        | `$PORT` is a valid port value, as a decimal integer.                                                                       |
| Source port      | `tcp.sport`  | not      | `$PORT`        | `$PORT` is a valid port value, as a decimal integer.                                                                       |
| Source port      | `tcp.sport`  | range    | `$START-$END`  | `$START` and `$END` are valid port values, as decimal integers.                                                            |
| Destination port | `tcp.dport`  | eq       | `$PORT`        | `$PORT` is a valid port value, as a decimal integer.                                                                       |
| Destination port | `tcp.dport`  | not      | `$PORT`        | `$PORT` is a valid port value, as a decimal integer.                                                                       |
| Destination port | `tcp.dport`  | range    | `$START-$END`  | `$START` and `$END` are valid port values, as decimal integers.                                                            |
| Flags            | `tcp.flags`  | eq       | `$FLAGS`       | `$FLAGS` is a comma-separated list of capitalized TCP flags (`FIN`, `RST`, `ACK`, `ECE`, `SYN`, `PSH`, `URG`, `CWR`).       |
| Flags            | `tcp.flags`  | not      | `$FLAGS`       | `$FLAGS` is a comma-separated list of capitalized TCP flags (`FIN`, `RST`, `ACK`, `ECE`, `SYN`, `PSH`, `URG`, `CWR`).       |
| Flags            | `tcp.flags`  | any      | `$FLAGS`       | `$FLAGS` is a comma-separated list of capitalized TCP flags (`FIN`, `RST`, `ACK`, `ECE`, `SYN`, `PSH`, `URG`, `CWR`).       |
| Flags            | `tcp.flags`  | all      | `$FLAGS`       | `$FLAGS` is a comma-separated list of capitalized TCP flags (`FIN`, `RST`, `ACK`, `ECE`, `SYN`, `PSH`, `URG`, `CWR`).       |

### UDP matchers

| Matches          | Type        | Operator | Payload       | Notes                                                           |
| ---------------- | ----------- | -------- | ------------- | --------------------------------------------------------------- |
| Source port      | `udp.sport` | eq       | `$PORT`       | `$PORT` is a valid port value, as a decimal integer.            |
| Source port      | `udp.sport` | not      | `$PORT`       | `$PORT` is a valid port value, as a decimal integer.            |
| Source port      | `udp.sport` | range    | `$START-$END` | `$START` and `$END` are valid port values, as decimal integers. |
| Destination port | `udp.dport` | eq       | `$PORT`       | `$PORT` is a valid port value, as a decimal integer.            |
| Destination port | `udp.dport` | not      | `$PORT`       | `$PORT` is a valid port value, as a decimal integer.            |
| Destination port | `udp.dport` | range    | `$START-$END` | `$START` and `$END` are valid port values, as decimal integers. |

## Examples

Let's explore some examples and how to write bpfilter rules. First, start the daemon:
```sh
sudo build/output/sbin/bpfilter
info   : no serialized context found on disk, a new context will be created
info   : waiting for requests...
```

{{< alert title="Note" >}}Flag `--transient` marks the bpfilter ruleset as temporary, meaning it will be removed on daemon restart.{{< /alert >}}

You can use either iptables or nftables as the following:
```sh
sudo build/tools/install/sbin/./iptables --bpf {Rule}
or 
sudo build/tools/install/sbin/./nft --bpf {Rule}
```

As the previous example which blocks ICMP with bpfilter but using custom `iptables` as front-end:
```sh
sudo build/tools/install/sbin/./iptables --bpf -D INPUT -p icmp -j DROP
```

Let's write rules with `bfcli`. Let's start with create a simple rule by creating a chain on the TC ingress hook for interface index 2 with a default ACCEPT policy, and it adds a rule to drop any packets where the IPv4 protocol is ICMP:
```sh
sudo build/output/sbin/./bfcli ruleset set --str "chain BF_HOOK_TC_INGRESS{ifindex=2} policy ACCEPT rule ip4.proto eq icmp DROP"
```

You can use XDP instead on the previous rule. It's all dependent on where in the kernel you want to apply your filter:
```sh
"chain BF_HOOK_XDP{ifindex=2} policy ACCEPT rule ip4.proto eq icmp DROP"
```

Flushing bpfilter is by using:
```sh
sudo build/output/sbin/./bfcli ruleset flush
```

Blocking egress traffic to 192.168.1.24 port 22 on TC egress hook
```sh
"chain BF_HOOK_TC_EGRESS{ifindex=2} policy ACCEPT rule ip4.daddr eq 192.168.1.24 tcp.dport eq 22 DROP"
```

Dropping packets that have both SYN and FIN flags set that’s not normally seen in legitimate traffic as it used by attackers as part of system discovery:
```sh
"chain BF_HOOK_TC_INGRESS{ifindex=2} policy ACCEPT rule tcp.flags all SYN,FIN DROP"
```
