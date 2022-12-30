# Tonel

A Multi-Stream UDP over TCP Tunneler for Lightning-Fast Network Layer 3 Transmission with TUN Interface.

# Table of Contents

- [Overview](#overview)
- [Usage](#usage)
  - [Client](#client)
  - [Server](#server)
- [MTU overhead](#mtu-overhead)
  - [MTU calculation for WireGuard](#mtu-calculation-for-wireguard)
- [Compatibility](#compatibility)
- [Comparison to udp2raw](#comparison-to-udp2raw)

# Overview

Tonel is a tool that allows for the transmission of UDP packets through multiple TCP connections. It is designed to maximize performance and minimize the amount of processing and encapsulation required for this purpose.

Tonel is a tool that is often used in situations where UDP is restricted or slowed down, but TCP is permitted. Its TCP stack is designed to work through many stateful and stateless L3/L4 firewalls and NAT devices. One advantage of using Tonel is that it avoids common issues that can degrade performance when using UDP over TCP, such as retransmissions and flow control. Despite appearing as a TCP connection to firewalls and NAT devices, Tonel still maintains the underlying UDP characteristics, including out-of-order delivery.

# Usage

IPs, ports and domains are just for example. Both IPv4 and IPv6 are supported.
For globally listen on IPv4, use `0.0.0.0`, and for IPv6, use `[::]`.

The following example will route the following diagram:

```text
UDP traffic <==> Tonel Client (tonelc) <==> <Tonel TCP traffic> <==> Tonel Server (tonels) <==> UDP traffic
                 listen: 127.0.0.1:1111                              listen: 127.0.0.1:2222
                 remote: 127.0.0.1:2222                              remote: 127.0.0.1:3333
```

Make sure you consult the Tonel by providing `-h` option to each binaries to show you the usage.

## Client

First, install the Tonel client:

```bash
cargo install tonel --bin tonels

# If you want faster memory allocator, you can use jemalloc (alloc-jem) or mimalloc (alloc-mi) feature like below:
cargo install tonel --bin tonels --features='default,alloc-mi'
```

Now, start Tonel to listen on UDP port 1111 and forward udp packet over TCP to `127.0.0.1:2222`
Tonel server destination. We assume your network interface is `eth0`.

```bash
RUST_LOG=info tonelc --local 127.0.0.1:1111 --remote 127.0.0.1:2222 --auto-rule eth0
```

## Server

First, install the Tonel server:

```bash
cargo install tonel --bin tonels
# If you want faster memory allocator, you can use jemalloc (alloc-jem) or mimalloc (alloc-mi) feature like below:
cargo install tonel --bin tonelc --features='default,alloc-mi'
```

Now, start Tonel to listen on TCP port 2222 and forward udp packet to `127.0.0.1:3333`
remote destination. We assume your network interface is `eth0`.

```bash
RUST_LOG=info tonels --local 2222 --remote 127.0.0.1:3333 --auto-rule eth0
```

# MTU overhead

Tonel's goal is to minimize tunneling overhead. As an example, the overhead compared to a standard UDP packet using IPv4 is as follows:

**Standard UDP packet:** `20 byte IP header + 8 byte UDP header = 28 bytes`

**Tonel TCP packet:** `20 byte IP header + 20 byte TCP header = 40 bytes`

**UDP apps in both side of Tonel must tune their MTU and reduce it by `12 bytes` on IPv4 or `32 bytes` on IPv6, at least.**

## MTU calculation for WireGuard

If you are using Tonel to tunnel UDP packets from [WireGuard®](https://www.wireguard.com), here are some guidelines for determining the appropriate MTU for your WireGuard interface.

```
WireGuard MTU = Interface MTU - IPv4 header (20 bytes) - TCP header (20 bytes) - WireGuard overhead (32 bytes)
```

or

```
WireGuard MTU = Interface MTU - IPv6 header (40 bytes) - TCP header (20 bytes) - WireGuard overhead (32 bytes)
```

For instance, if you are using an Ethernet interface with an MTU of 1500 bytes, the WireGuard interface MTU should be set as follows:

IPv4: `1500 - 20 - 20 - 32 = 1428 bytes`
IPv6: `1500 - 40 - 20 - 32 = 1408 bytes`

The resulting Tonel TCP data packet will have a size of 1500 bytes, which does not exceed the interface MTU of 1500.

It is a good practice to reduce the MTU further to avoid packet loss, and to apply the same MTU on both ends.

# Compatibility

Currently, Tonel only works on Linux operating systems. There are plans to make it cross-platform in the future. Contributions are welcome.

# Comparison to udp2raw

|                                                 |     Tonel     |      udp2raw      |
| ----------------------------------------------- | :-----------: | :---------------: |
| UDP over Fake TCP                               |      ✅       |        ✅         |
| UDP over ICMP                                   |      ❌       |        ✅         |
| UDP over UDP                                    |      ❌       |        ✅         |
| Arbitrary TCP handshake content                 |      ✅       |        ❌         |
| Multi-threaded and concurrency                  |      ✅       |        ❌         |
| Throughput                                      |   Excellent   |       Good        |
| Layer 3 mode                                    | TUN interface | Raw sockets + BPF |
| Tunneling MTU overhead                          |   12 bytes    |     44 bytes      |
| Seprate TCP connections for each UDP connection | Client/Server |    Server only    |
| Anti-replay                                     |      ❌       |        ✅         |
| Encryption                                      |      ✅       |        ✅         |
| IPv6                                            |      ✅       |        ✅         |

# License

See LICENSE for details.
