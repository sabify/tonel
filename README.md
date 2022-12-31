# Tonel

A Multi-Stream UDP over TCP Tunneler for Lightning-Fast Network Layer 3 Transmission with TUN Interface.

# Table of Contents

- [Overview](#overview)
  - [Features](#features)
- [Usage](#usage)
  - [Client](#client)
  - [Server](#server)
- [MTU overhead](#mtu-overhead)
  - [MTU calculation for WireGuard](#mtu-calculation-for-wireguard)
- [Compatibility](#compatibility)
- [Comparing Tonel to udp2raw](#comparing-tonel-to-udp2raw)
- [Client Command Line Options](#client-command-line-options)
- [Server Command Line Options](#server-command-line-options)
- [License](#license)

# Overview

Tonel is a tool that allows for the transmission of UDP packets through multiple TCP connections. It is designed to maximize performance and minimize the amount of processing and encapsulation required for this purpose.

Tonel is a tool that is often used in situations where UDP is restricted or slowed down, but TCP is permitted. Its TCP stack is designed to work through many stateful and stateless L3/L4 firewalls and NAT devices. One advantage of using Tonel is that it avoids common issues that can degrade performance when using UDP over TCP, such as retransmissions and flow control. Despite appearing as a TCP connection to firewalls and NAT devices, Tonel still maintains the underlying UDP characteristics, including out-of-order delivery.

## Features

- Tonel is fast!
- Tonel has almost zero allocations.
- You can adjust the number of TCP and UDP connections in the Tonel client for each client connection.
- You can adjust the number of UDP connections in the Tonel server for each Tonel client connection.
- You can encrypt TCP connections.
- You can configure the handshake packet for TCP connections in Tonel.

# Usage

IPs, ports and domains are just for example. Both IPv4 and IPv6 are supported.
For globally listen on IPv4, use `0.0.0.0`, and for IPv6, use `[::]`.

Here's an example configuration:

```text
UDP traffic <==> Tonel Client <==> <Tonel TCP traffic> <==> Tonel Server <==> UDP traffic
                      |                                          |
                      |                                          |
            listen: 127.0.0.1:1111                     listen: 127.0.0.1:2222
            remote: 127.0.0.1:2222                     remote: 127.0.0.1:3333
```

Note: Be sure to consult the Tonel documentation by providing the -h switch to each binary to see the full usage instructions.

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

**Standard UDP packet:** `20 byte IP header + 8 byte UDP header = 28 bytes`\
**Tonel TCP packet:** `20 byte IP header + 20 byte TCP header = 40 bytes`

**Note:** UDP apps on both sides of Tonel must tune their MTU and reduce it by at least 12 bytes on IPv4 or 32 bytes on IPv6.

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

IPv4: `1500 - 20 - 20 - 32 = 1428 bytes`\
IPv6: `1500 - 40 - 20 - 32 = 1408 bytes`

The resulting Tonel TCP data packet will have a size of 1500 bytes, which does not exceed the interface MTU of 1500.

It is a good practice to reduce the MTU further to avoid packet loss, and to apply the same MTU on both ends.

# Compatibility

Currently, Tonel only works on Linux operating systems. There are plans to make it cross-platform in the future. Contributions are welcome.

# Comparing Tonel to udp2raw

|                                          |     Tonel     |      udp2raw      |
| ---------------------------------------- | :-----------: | :---------------: |
| UDP over Fake TCP                        |      ✅       |        ✅         |
| Multi-Stream TCP and UDP per each client |      ✅       |        ❌         |
| Arbitrary TCP handshake content          |      ✅       |        ❌         |
| Multi-threaded and concurrency           |      ✅       |        ❌         |
| Throughput                               |   Excellent   |       Good        |
| Layer 3 mode                             | TUN interface | Raw sockets + BPF |
| Tunneling MTU overhead                   |   12 bytes    |     44 bytes      |
| Encryption                               |      ✅       |        ✅         |
| IPv6                                     |      ✅       |        ✅         |

# Client Command Line Options

```text
Usage: tonelc [OPTIONS] --local <IP:PORT> --remote <IP or HOST NAME:PORT>

Options:
  -l, --local <IP:PORT>                Sets the IP and port where Tonel Client listens for incoming UDP datagrams, IPv6 address need to be specified as: "[IPv6]:PORT"
  -r, --remote <IP or HOST NAME:PORT>  Sets the address or host name and port where Tonel Client connects to Tonel Server, IPv6 address need to be specified as: "[IPv6]:PORT"
      --tun <tunX>                     Sets the Tun interface name, if absent, pick the next available name [default: ]
      --tun-local <IP>                 Sets the Tun interface IPv4 local address (O/S's end) [default: 192.168.200.1]
      --tun-peer <IP>                  Sets the Tun interface IPv4 destination (peer) address (Tonel Client's end).
                                       You will need to setup SNAT/MASQUERADE rules on your Internet facing interface
                                       in order for Tonel Client to connect to Tonel Server [default: 192.168.200.2]
  -4, --ipv4-only                      Only use IPv4 address when connecting to remote
      --tun-local6 <IP>                Sets the Tun interface IPv6 local address (O/S's end) [default: fcc8::1]
      --tun-peer6 <IP>                 Sets the Tun interface IPv6 destination (peer) address (Tonel Client's end).
                                       You will need to setup SNAT/MASQUERADE rules on your Internet facing interface
                                       in order for Tonel Client to connect to Tonel Server [default: fcc8::2]
      --handshake-packet <PATH>        Specify a file, which, after TCP handshake, its content will be sent as
                                       the first data packet to the server.
                                       Note: ensure this file's size does not exceed the MTU of the outgoing interface.
                                       The content is always sent out in a single packet and will not be further segmented
      --tcp-connections <number>       Number of TCP connections per each client. [default: 1]
      --udp-connections <number>       Number of UDP connections per each client. [default: 1]
      --encryption <encryption>        Specify an encryption algorithm for using in TCP connections.
                                       Server and client should use the same encryption.
                                       Currently XOR is only supported and the format should be 'xor:key'.
      --auto-rule <interface-name>     Automatically adds required iptables and sysctl rules.
                                       The argument needs the name of an active network interface
                                       that the firewall will route the traffic over it. (e.g. eth0)
  -h, --help                           Print help information
  -V, --version                        Print version information
```

# Server Command Line Options

```text
Usage: tonels [OPTIONS] --local <PORT> --remote <IP or HOST NAME:PORT>

Options:
  -l, --local <PORT>                   Sets the port where Tonel Server listens for incoming Tonel Client TCP connections
  -r, --remote <IP or HOST NAME:PORT>  Sets the address or host name and port where Tonel Server forwards UDP packets to,
                                       IPv6 address need to be specified as: "[IPv6]:PORT"
      --tun <tunX>                     Sets the Tun interface name, if absent, pick the next available name [default: ]
      --tun-local <IP>                 Sets the Tun interface local address (O/S's end) [default: 192.168.201.1]
      --tun-peer <IP>                  Sets the Tun interface destination (peer) address (Tonel Server's end).
                                       You will need to setup DNAT rules to this address in order for Tonel Server to
                                       accept TCP traffic from Tonel Client [default: 192.168.201.2]
  -4, --ipv4-only                      Do not assign IPv6 addresses to Tun interface
      --tun-local6 <IP>                Sets the Tun interface IPv6 local address (O/S's end) [default: fcc9::1]
      --tun-peer6 <IP>                 Sets the Tun interface IPv6 destination (peer) address (Tonel Client's end).
                                       You will need to setup SNAT/MASQUERADE rules on your Internet facing interface
                                       in order for Tonel Client to connect to Tonel Server [default: fcc9::2]
      --handshake-packet <PATH>        Specify a file, which, after TCP handshake, its content will be sent as
                                       the first data packet to the client.
                                       Note: ensure this file's size does not exceed the MTU of the outgoing interface.
                                       The content is always sent out in a single packet and will not be further segmented
      --encryption <encryption>        Specify an encryption algorithm for using in TCP connections.
                                       Server and client should use the same encryption.
                                       Currently XOR is only supported and the format should be 'xor:key'.
      --udp-connections <number>       Number of UDP connections per each TCP connection. [default: 1]
      --auto-rule <interface-name>     Automatically adds required iptables and sysctl rules.
                                       The argument needs the name of an active network interface
                                       that the firewall will route the traffic over it. (e.g. eth0)
  -h, --help                           Print help information
  -V, --version                        Print version information
```

# License

See LICENSE for details.
