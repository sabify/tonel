use cfg_if::cfg_if;
use clap::{crate_version, Arg, ArgAction, Command};
use log::{debug, error, info};
use std::fs;
use std::io;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::broadcast;
use tokio::time;
use tokio_tun::TunBuilder;
use tokio_util::sync::CancellationToken;
use tonel::tcp::packet::MAX_PACKET_LEN;
use tonel::tcp::Stack;
use tonel::utils::{assign_ipv6_address, new_udp_reuseport};
use tonel::Encryption;

use tonel::UDP_SOCK_READ_DEADLINE;

cfg_if! {
    if #[cfg(all(feature = "alloc-jem", not(target_env = "msvc")))] {
        use jemallocator::Jemalloc;
        #[global_allocator]
        static GLOBAL: Jemalloc = Jemalloc;
    } else if #[cfg(all(feature = "alloc-mi", unix))] {
        use mimalloc::MiMalloc;
        #[global_allocator]
        static GLOBAL: MiMalloc = MiMalloc;
    }
}

#[tokio::main]
async fn main() -> io::Result<()> {
    pretty_env_logger::init();

    let num_cpus = num_cpus::get();
    info!("{} cores available", num_cpus);

    let matches = Command::new("Tonel Server")
        .version(crate_version!())
        .author("Saber Haj Rabiee")
        .arg(
            Arg::new("local")
                .short('l')
                .long("local")
                .required(true)
                .value_name("PORT")
                .help("Sets the port where Tonel Server listens for incoming Tonel Client TCP connections")
        )
        .arg(
            Arg::new("remote")
                .short('r')
                .long("remote")
                .required(true)
                .value_name("IP or HOST NAME:PORT")
                .help("Sets the address or host name and port where Tonel Server forwards UDP packets to, \n\
                    IPv6 address need to be specified as: \"[IPv6]:PORT\"")
        )
        .arg(
            Arg::new("tun")
                .long("tun")
                .required(false)
                .value_name("tunX")
                .help("Sets the Tun interface name, if absent, pick the next available name")
                .default_value("")
        )
        .arg(
            Arg::new("tun_local")
                .long("tun-local")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface local address (O/S's end)")
                .default_value("192.168.201.1")
        )
        .arg(
            Arg::new("tun_peer")
                .long("tun-peer")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface destination (peer) address (Tonel Server's end). \n\
                       You will need to setup DNAT rules to this address in order for Tonel Server \n\
                       to accept TCP traffic from Tonel Client")
                .default_value("192.168.201.2")
        )
        .arg(
            Arg::new("ipv4_only")
                .long("ipv4-only")
                .short('4')
                .required(false)
                .help("Do not assign IPv6 addresses to Tun interface")
                .action(ArgAction::SetTrue)
                .conflicts_with_all(["tun_local6", "tun_peer6"]),
        )
        .arg(
            Arg::new("tun_local6")
                .long("tun-local6")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface IPv6 local address (O/S's end)")
                .default_value("fcc9::1")
        )
        .arg(
            Arg::new("tun_peer6")
                .long("tun-peer6")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface IPv6 destination (peer) address (Tonel Client's end). \n\
                       You will need to setup SNAT/MASQUERADE rules on your Internet facing interface \n\
                       in order for Tonel Client to connect to Tonel Server")
                .default_value("fcc9::2")
        )
        .arg(
            Arg::new("handshake_packet")
                .long("handshake-packet")
                .required(false)
                .value_name("PATH")
                .help("Specify a file, which, after TCP handshake, its content will be sent as the \n\
                      first data packet to the client.\n\
                      Note: ensure this file's size does not exceed the MTU of the outgoing interface. \n\
                      The content is always sent out in a single packet and will not be further segmented")
        )
        .arg(
            Arg::new("encryption")
                .long("encryption")
                .required(false)
                .value_name("encryption")
                .help("Specify an encryption algorithm for using in TCP connections. \n\
                       Server and client should use the same encryption. \n\
                       Currently XOR is only supported and the format should be 'xor:key'.")
        )
        .arg(
            Arg::new("udp_connections")
                .long("udp-connections")
                .required(false)
                .value_name("number")
                .help("Number of UDP connections per each TCP connections.")
                .default_value(num_cpus.to_string())
        )
        .arg(
            Arg::new("auto_rule")
                .long("auto-rule")
                .required(false)
                .value_name("interface-name")
                .help("Automatically adds required iptables and sysctl rules.\n\
                The argument needs the name of an active network interface \n\
                that the firewall will route the traffic over it. (e.g. eth0)")
        )
        .get_matches();

    let local_port: u16 = matches
        .get_one::<String>("local")
        .unwrap()
        .parse()
        .expect("bad local port");

    let remote_addr = tokio::net::lookup_host(matches.get_one::<String>("remote").unwrap())
        .await
        .expect("bad remote address or host")
        .next()
        .expect("unable to resolve remote host name");
    info!("Remote address is: {}", remote_addr);

    let tun_local: Ipv4Addr = matches
        .get_one::<String>("tun_local")
        .unwrap()
        .parse()
        .expect("bad local address for Tun interface");
    let tun_peer: Ipv4Addr = matches
        .get_one::<String>("tun_peer")
        .unwrap()
        .parse()
        .expect("bad peer address for Tun interface");

    let udp_socks_amount: usize = matches
        .get_one::<String>("udp_connections")
        .unwrap()
        .parse()
        .expect("Unspecified number of UDP connections per each client");
    if udp_socks_amount == 0 {
        panic!("UDP connections should be greater than or equal to 1");
    }

    let encryption = matches
        .get_one::<String>("encryption")
        .map(Encryption::from);
    debug!("Encryption in use: {:?}", encryption);
    let encryption = Arc::new(encryption);

    let ipv4_only = matches.get_flag("ipv4_only");

    let (tun_local6, tun_peer6) = if ipv4_only {
        (None, None)
    } else {
        (
            matches
                .get_one::<String>("tun_local6")
                .map(|v| v.parse().expect("bad local address for Tun interface")),
            matches
                .get_one::<String>("tun_peer6")
                .map(|v| v.parse().expect("bad peer address for Tun interface")),
        )
    };

    let tun_name = matches.get_one::<String>("tun").unwrap();
    let handshake_packet: Option<Vec<u8>> = matches
        .get_one::<String>("handshake_packet")
        .map(fs::read)
        .transpose()?;
    let handshake_packet = Arc::new(handshake_packet);

    let tun = TunBuilder::new()
        .name(tun_name) // if name is empty, then it is set by kernel.
        .tap(false) // false (default): TUN, true: TAP.
        .packet_info(false) // false: IFF_NO_PI, default is true.
        .up() // or set it up manually using `sudo ip link set <tun-name> up`.
        .address(tun_local)
        .destination(tun_peer)
        .try_build_mq(num_cpus)
        .unwrap();

    if let (Some(tun_local6), Some(tun_peer6)) = (tun_local6, tun_peer6) {
        assign_ipv6_address(tun[0].name(), tun_local6, tun_peer6);
    }

    let auto_rule = matches.get_one::<String>("auto_rule");

    if let Some(dev_name) = auto_rule {
        let ipv4_forward_value = std::process::Command::new("sysctl")
            .arg("net.ipv4.ip_forward")
            .output()
            .expect("sysctl net.ipv4.ip_forward could not be executed.");

        if !ipv4_forward_value.status.success() {
            panic!(
                "sysctl net.ipv4.ip_forward could not be executed successfully: {}.",
                ipv4_forward_value.status
            );
        }

        let status = std::process::Command::new("sysctl")
            .arg("-w")
            .arg("net.ipv4.ip_forward=1")
            .output()
            .expect("sysctl -w net.ipv4.ip_forward=1 could not be executed.")
            .status;

        if !status.success() {
            panic!("sysctl -w net.ipv4.ip_forward=1 could not be executed successfully: {status}.");
        }

        info!("sysctl -w net.ipv4.ip_forward=1 has been set.");

        let ipv4_forward_value: String = String::from_utf8(ipv4_forward_value.stdout)
            .unwrap()
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();

        let ipv6_forward_value: Option<String> = if !ipv4_only {
            let ipv6_forward_value = std::process::Command::new("sysctl")
                .arg("net.ipv6.conf.all.forwarding")
                .output()
                .expect("sysctl net.ipv6.conf.all.forwarding could not be executed.");

            if !ipv6_forward_value.status.success() {
                panic!(
                    "sysctl net.ipv6.conf.all.forwarding could not be executed successfully: {}.",
                    ipv6_forward_value.status
                );
            }

            let status = std::process::Command::new("sysctl")
                .arg("-w")
                .arg("net.ipv6.conf.all.forwarding=1")
                .output()
                .expect("sysctl -w net.ipv6.conf.all.forwarding=1 could not be executed.")
                .status;

            if !status.success() {
                panic!("sysctl -w net.ipv6.conf.all.forwarding=1 could not be executed successfully: {status}.");
            }

            info!("sysctl -w net.ipv6.conf.all.forwarding=1 has been set.");
            Some(
                String::from_utf8(ipv6_forward_value.stdout)
                    .unwrap()
                    .chars()
                    .filter(|c| !c.is_whitespace())
                    .collect(),
            )
        } else {
            None
        };

        let iptables_add_rule = format!(
            "-t nat -I PREROUTING -p tcp -i {dev_name} --dport {} -j DNAT --to-destination {}",
            local_port, tun_peer,
        );
        let ip6tables_add_rule = if !ipv4_only {
            Some(format!(
                "-t nat -I PREROUTING -p tcp -i {dev_name} --dport {} -j DNAT --to-destination {}",
                local_port,
                tun_peer6.unwrap(),
            ))
        } else {
            None
        };

        let iptables_del_rule = format!(
            "-t nat -D PREROUTING -p tcp -i {dev_name} --dport {} -j DNAT --to-destination {}",
            local_port, tun_peer,
        );
        let ip6tables_del_rule = if !ipv4_only {
            Some(format!(
                "-t nat -D PREROUTING -p tcp -i {dev_name} --dport {} -j DNAT --to-destination {}",
                local_port,
                tun_peer6.unwrap(),
            ))
        } else {
            None
        };

        let status = std::process::Command::new("iptables")
            .args(iptables_add_rule.split(' '))
            .output()
            .expect("iptables could not be executed.")
            .status;

        if !status.success() {
            panic!("{iptables_add_rule} could not be executed successfully: {status}.");
        }

        info!("iptables has been configured.");

        if !ipv4_only {
            let status = std::process::Command::new("ip6tables")
                .args(ip6tables_add_rule.as_ref().unwrap().split(' '))
                .output()
                .expect("ip6tables could not be executed.")
                .status;

            if !status.success() {
                panic!(
                    "{} could not be executed successfully: {status}.",
                    ip6tables_add_rule.as_ref().unwrap()
                );
            }

            info!("ip6tables has been configured.");
        }

        ctrlc::set_handler(move || {
            let status = std::process::Command::new("sysctl")
                .arg("-w")
                .arg(&ipv4_forward_value)
                .output()
                .unwrap_or_else(|err| {
                    panic!(
                        "sysctl -w '{:?}' could not be executed: {err}.",
                        ipv4_forward_value
                    )
                })
                .status;
            if !status.success() {
                panic!(
                    "sysctl -w '{:?}' could not be executed successfully: {status}.",
                    ipv4_forward_value
                );
            }

            info!("sysctl ipv4 forwarding value reverted back to original value.");

            if !ipv4_only {
                let status = std::process::Command::new("sysctl")
                    .arg("-w")
                    .arg(ipv6_forward_value.as_ref().as_ref().unwrap())
                    .output()
                    .unwrap_or_else(|err| {
                        panic!(
                            "sysctl -w '{:?}' could not be executed: {err}.",
                            ipv6_forward_value
                        )
                    })
                    .status;
                if !status.success() {
                    panic!(
                        "sysctl -w '{:?}' could not be executed successfully: {status}.",
                        ipv6_forward_value
                    );
                }

                info!("sysctl ipv6 forwarding value reverted back to original value.");
            }

            let status = std::process::Command::new("iptables")
                .args(iptables_del_rule.split(' '))
                .output()
                .expect("iptables could not be executed.")
                .status;

            if !status.success() {
                panic!("{iptables_del_rule} could not be executed successfully: {status}.");
            }

            info!("Respective iptables rules removed.");

            if !ipv4_only {
                let status = std::process::Command::new("ip6tables")
                    .args(ip6tables_del_rule.as_ref().unwrap().split(' '))
                    .output()
                    .expect("ip6tables could not be executed.")
                    .status;

                if !status.success() {
                    panic!(
                        "{} could not be executed successfully: {status}.",
                        ip6tables_del_rule.as_ref().unwrap()
                    );
                }

                info!("Respective ip6tables rules removed.");
            }

            std::process::exit(0);
        })
        .expect("Error setting Ctrl-C handler");
    } else {
        info!(
            "Make sure ip forwarding is enabled, run the following commands: \n\
            sysctl -w net.ipv4.ip_forward=1 \n\
            sysctl -w net.ipv6.conf.all.forwarding=1"
        );

        if ipv4_only {
            info!(
            "Make sure your firewall routes packets, replace the dev_name with \n\
            your active network interface (like eth0) and run the following commands for iptables: \n\
            iptables -t nat -I PREROUTING -p tcp -i dev_name --dport {} -j DNAT --to-destination {}",
            local_port,
            tun_peer,
        );
        } else {
            info!(
                "Make sure your firewall routes packets, replace the dev_name with \n\
                your active network interface (like eth0) and run the following commands for iptables: \n\
                iptables -t nat -I PREROUTING -p tcp -i dev_name --dport {} -j DNAT --to-destination {}\n\
                ip6tables -t nat -I PREROUTING -p tcp -i dev_name --dport {} -j DNAT --to-destination {}",
                local_port,
                tun_peer,
                local_port,
                tun_peer6.unwrap(),
            );
        }
    }

    info!("Created TUN device {}", tun[0].name());

    //thread::sleep(time::Duration::from_secs(5));
    let mut stack = Stack::new(tun, tun_local, tun_local6);
    stack.listen(local_port);
    info!("Listening on {}", local_port);

    'main_loop: loop {
        let tcp_sock = Arc::new(stack.accept().await);
        info!("New connection: {}", tcp_sock);

        let mut buf_tcp = [0u8; MAX_PACKET_LEN];

        let mut should_receive_handshake_packet = false;
        let handshake_packet = handshake_packet.clone();
        if handshake_packet.is_some() {
            should_receive_handshake_packet = true;
        }

        let udp_sock = UdpSocket::bind(if remote_addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })
        .await;

        let udp_sock = match udp_sock {
            Ok(udp_sock) => udp_sock,
            Err(err) => {
                error!("No more UDP address is available: {err}");
                continue;
            }
        };

        let local_addr = udp_sock.local_addr().unwrap();
        drop(udp_sock);

        let cancellation = CancellationToken::new();
        let (packet_received_tx, _packet_received_rx) = broadcast::channel(1);
        let udp_socks: Vec<_> = {
            let mut socks = Vec::with_capacity(udp_socks_amount);
            for _ in 0..udp_socks_amount {
                let udp_sock = match new_udp_reuseport(local_addr) {
                    Ok(udp_sock) => udp_sock,
                    Err(err) => {
                        error!("Craeting new udp socket error: {err}");
                        continue 'main_loop;
                    }
                };
                if let Err(err) = udp_sock.connect(remote_addr).await {
                    error!("UDP couldn't connect to {remote_addr}: {err}, closing connection");
                    continue 'main_loop;
                }
                socks.push(Arc::new(udp_sock));
            }
            socks
        };

        for udp_sock in &udp_socks {
            let tcp_sock = tcp_sock.clone();
            let cancellation = cancellation.clone();
            let encryption = encryption.clone();
            let mut packet_received_rx = packet_received_tx.subscribe();
            let packet_received_tx = packet_received_tx.clone();
            let udp_sock = udp_sock.clone();
            tokio::spawn(async move {
                let mut buf_udp = [0u8; MAX_PACKET_LEN];
                let mut buf = [0u8; MAX_PACKET_LEN];
                loop {
                    let read_timeout = time::sleep(UDP_SOCK_READ_DEADLINE);
                    tokio::select! {
                        biased;
                        _ = cancellation.cancelled() => {
                            debug!("Closing connection requested for {local_addr}, closing connection");
                            break;
                        },
                        res = udp_sock.recv(&mut buf_udp) => {
                            match res {
                                Ok(size) => {
                                    if let Some(ref enc) = *encryption {
                                        enc.encrypt(&mut buf_udp[..size]);
                                    }
                                    if tcp_sock.send(&mut buf, &buf_udp[..size]).await.is_none() {
                                        debug!("Unable to send TCP packet to {remote_addr}, closing connection");
                                        break;
                                    }
                                },
                                Err(err) => {
                                    debug!("UDP connection closed on {remote_addr}: {err}, closing connection");
                                    break;
                                }
                            };
                        },
                        _ = packet_received_rx.recv() => {
                            continue;
                        },
                        _ = read_timeout => {
                            debug!("No traffic seen in the last {:?}, closing connection {local_addr}", UDP_SOCK_READ_DEADLINE);
                            break;
                        },
                    };
                    _ = packet_received_tx.send(());
                }
                cancellation.cancel();
            });
        }
        let tcp_sock = tcp_sock.clone();
        let encryption = encryption.clone();
        let cancellation = cancellation.clone();
        tokio::spawn(async move {
            let mut udp_sock_index = 0;
            let mut buf = [0u8; MAX_PACKET_LEN];

            loop {
                tokio::select! {
                    biased;
                    _ = cancellation.cancelled() => {
                        debug!("Closing connection requested for {local_addr}, closing connection");
                        break;
                    },
                    res = tcp_sock.recv(&mut buf_tcp) => {
                        match res {
                            Some(size) => {
                                if should_receive_handshake_packet {
                                    should_receive_handshake_packet = false;
                                    if let Some(ref p) = *handshake_packet {
                                        if tcp_sock.send(&mut buf, p).await.is_none() {
                                            error!("Failed to send handshake packet to remote, closing connection.");
                                            break;
                                        }
                                        debug!("Sent handshake packet to: {}", tcp_sock);
                                    }
                                    continue;
                                }
                                udp_sock_index = (udp_sock_index + 1) % udp_socks_amount;
                                let udp_sock = udp_socks[udp_sock_index].clone();
                                if let Some(ref enc) = *encryption {
                                    enc.decrypt(&mut buf_tcp[..size]);
                                }
                                if let Err(e) = udp_sock.send(&buf_tcp[..size]).await {
                                    debug!("Unable to send UDP packet to {local_addr}: {e}, closing connection");
                                    break;
                                }
                            },
                            None => {
                                debug!("TCP connection closed on {local_addr}");
                                break;
                            },
                        };
                    },
                };
                _ = packet_received_tx.send(());
            }
            cancellation.cancel();
            info!("Connention {local_addr} closed");
        });
    }
}
