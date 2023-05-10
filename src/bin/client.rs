use cfg_if::cfg_if;
use clap::ArgMatches;
use clap::{crate_version, Arg, ArgAction, Command};
use log::{debug, error, info, trace};
use std::fs;
use std::io;
#[cfg(any(
    target_os = "openbsd",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    target_os = "macos",
    target_os = "ios"
))]
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::broadcast;
use tokio::task::JoinSet;
use tokio::time;
use tokio_util::sync::CancellationToken;
use tonel::tcp::packet::MAX_PACKET_LEN;
use tonel::tcp::{Socket, Stack};
use tonel::utils::{assign_ipv6_address, new_udp_reuseport};
use tonel::Encryption;
use tun::Device;

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

fn main() {
    #[cfg(not(target_os = "macos"))]
    let tun_value_name = "tunX|fd";
    #[cfg(target_os = "macos")]
    let tun_value_name = "utunX|fd";
    let matches = Command::new("Tonel Client")
        .version(crate_version!())
        .author("Saber Haj Rabiee")
        .arg(
            Arg::new("local")
                .short('l')
                .long("local")
                .required(true)
                .value_name("IP:PORT")
                .help("Sets the IP and port where Tonel Client listens for incoming UDP datagrams, \n\
                    IPv6 address need to be specified as: \"[IPv6]:PORT\"")
        )
        .arg(
            Arg::new("remote")
                .short('r')
                .long("remote")
                .required(true)
                .value_name("IP or HOST NAME:PORT")
                .help("Sets the address or host name and port where Tonel Client connects to Tonel Server, \n\
                    IPv6 address need to be specified as: \"[IPv6]:PORT\"")
        )
        .arg(
            Arg::new("tun_local")
                .long("tun-local")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface IPv4 local address (O/S's end)")
                .default_value("192.168.200.1")
        )
        .arg(
            Arg::new("tun_peer")
                .long("tun-peer")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface IPv4 destination (peer) address (Tonel Client's end). \n\
                       You will need to setup SNAT/MASQUERADE rules on your Internet facing interface \n\
                       in order for Tonel Client to connect to Tonel Server")
                .default_value("192.168.200.2")
        )
        .arg(
            Arg::new("ipv4_only")
                .long("ipv4-only")
                .short('4')
                .required(false)
                .help("Only use IPv4 address when connecting to remote")
                .action(ArgAction::SetTrue)
                .conflicts_with_all(["tun_local6", "tun_peer6"]),
        )
        .arg(
            Arg::new("tun_local6")
                .long("tun-local6")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface IPv6 local address (O/S's end)")
                .default_value("fcc8::1")
        )
        .arg(
            Arg::new("tun_peer6")
                .long("tun-peer6")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface IPv6 destination (peer) address (Tonel Client's end). \n\
                       You will need to setup SNAT/MASQUERADE rules on your Internet facing interface \n\
                       in order for Tonel Client to connect to Tonel Server")
                .default_value("fcc8::2")
        )
        .arg(
            Arg::new("handshake_packet")
                .long("handshake-packet")
                .required(false)
                .value_name("PATH")
                .help("Specify a file, which, after TCP handshake, its content will be sent as the \n\
                      first data packet to the server.\n\
                      Note: ensure this file's size does not exceed the MTU of the outgoing interface. \n\
                      The content is always sent out in a single packet and will not be further segmented")
        )
        .arg(
            Arg::new("tcp_connections")
                .long("tcp-connections")
                .required(false)
                .value_name("number")
                .help("The number of TCP connections per each client.")
                .default_value("1")
        )
        .arg(
            Arg::new("udp_connections")
                .long("udp-connections")
                .required(false)
                .value_name("number")
                .help("The number of UDP connections per each client.")
                .default_value("1")
                )
        .arg(
            Arg::new("tun_queues")
                .long("tun-queues")
                .required(false)
                .value_name("number")
                .help("The number of queues for TUN interface. Default is \n\
                       set to 1. The platform should support multiple queues feature.")
                .default_value("1")
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
            Arg::new("auto_rule")
                .long("auto-rule")
                .required(false)
                .value_name("interface-name")
                .help("Automatically adds and removes required firewall and sysctl rules.\n\
                       The argument needs the name of an active network interface \n\
                       that the firewall will route the traffic over it. (e.g. eth0)")
        )
        .arg(
            Arg::new("daemonize")
                .long("daemonize")
                .short('d')
                .required(false)
                .action(ArgAction::SetTrue)
                .help("Start the process as a daemon.")
        )
        .arg(
            Arg::new("log_output")
                .long("log-output")
                .value_name("path")
                .required(false)
                .help("Log output path. Default is stderr.")
        )
        .arg(
            Arg::new("log_level")
                .long("log-level")
                .required(false)
                .value_name("level")
                .default_value("info")
                .help("Log output level. It could be one of the following:\n\
                    off, error, warn, info, debug, trace.")
        )
        .arg(
            Arg::new("timeout")
                .long("timeout")
                .required(false)
                .value_name("timeout")
                .help("Set timeout for connections in seconds. Default is disabled.")
        )
        .arg(
        Arg::new("tun")
            .long("tun")
            .required(false)
            .value_name(tun_value_name)
            .help(
                "Sets the Tun interface name and if it is absent, the OS \n\
                   will pick the next available name. \n\
                   You can also create your TUN device and \n\
                   pass the int32 file descriptor to this switch.",
            ),
    ).get_matches();

    let mut log_builder = env_logger::Builder::new();
    log_builder.filter(
        None,
        matches
            .get_one::<String>("log_level")
            .unwrap()
            .parse()
            .unwrap(),
    );

    log_builder.init();

    let daemonize = matches.get_flag("daemonize");
    if daemonize {
        let mut daemon = daemonize::Daemonize::new().working_directory("/tmp");

        if let Some(path) = matches.get_one::<String>("log_output") {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(path)
                .expect("log output path does not exist.");

            daemon = daemon.stderr(file);
        }
        daemon.start().unwrap_or_else(|e| {
            eprintln!("failed to daemonize: {e}");
            std::process::exit(1);
        });
    }

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(main_async(matches))
        .unwrap();
}

async fn main_async(matches: ArgMatches) -> io::Result<()> {
    let local_addr: Arc<SocketAddr> = Arc::new(
        matches
            .get_one::<String>("local")
            .unwrap()
            .parse()
            .expect("bad local address"),
    );

    let ipv4_only = matches.get_flag("ipv4_only");

    let remote_addr = tokio::net::lookup_host(matches.get_one::<String>("remote").unwrap())
        .await
        .expect("bad remote address or host")
        .find(|addr| !ipv4_only || addr.is_ipv4())
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

    let (tun_local6, tun_peer6) = if ipv4_only {
        (None, None)
    } else {
        (
            matches.get_one::<String>("tun_local6").map(|v| {
                v.parse::<Ipv6Addr>()
                    .expect("bad local address for Tun interface")
            }),
            matches.get_one::<String>("tun_peer6").map(|v| {
                v.parse::<Ipv6Addr>()
                    .expect("bad peer address for Tun interface")
            }),
        )
    };

    let tcp_socks_amount: usize = matches
        .get_one::<String>("tcp_connections")
        .unwrap()
        .parse()
        .expect("Unspecified number of TCP connections per each client");
    if tcp_socks_amount == 0 {
        panic!("TCP connections should be greater than or equal to 1");
    }

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

    let handshake_packet: Arc<Option<Vec<u8>>> = Arc::new(
        matches
            .get_one::<String>("handshake_packet")
            .map(fs::read)
            .transpose()?,
    );

    let mut tun_config = tun::Configuration::default();
    tun_config
        .netmask("255.255.255.0")
        .address(tun_local)
        .destination(tun_peer)
        .up()
        .queues(
            matches
                .get_one::<String>("tun_queues")
                .unwrap()
                .parse()
                .unwrap(),
        );
    if let Some(name) = matches.get_one::<String>("tun") {
        if let Ok(fd) = name.parse::<i32>() {
            tun_config.raw_fd(fd);
        } else {
            tun_config.name(name);
        }
    }

    let tun = tun::create(&tun_config).unwrap();

    if tun_local6.is_some() {
        #[cfg(any(
            target_os = "openbsd",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "dragonfly",
            target_os = "macos",
        ))]
        assign_ipv6_address(tun.name(), tun_local6.unwrap());
        #[cfg(any(target_os = "linux", target_os = "android"))]
        assign_ipv6_address(tun.name(), tun_local6.unwrap(), tun_peer6.unwrap());
    }

    let exit_fn: Box<dyn Fn() + 'static + Send> = if let Some(dev_name) =
        matches.get_one::<String>("auto_rule")
    {
        cfg_if! {
            if #[cfg(target_os = "linux")] {
                auto_rule(
                    dev_name,
                    ipv4_only,
                    remote_addr,
                )
            } else if
                #[cfg(target_os = "macos")] {
                auto_rule(
                    tun.name(),
                    dev_name,
                    tun_peer,
                    tun_peer6,
                )
            }
        }
    } else {
        info!(
            "Make sure ip forwarding is enabled, run the following commands or equivalent in your OS: \n\
            sysctl -w net.ipv4.ip_forward=1 \n\
            sysctl -w net.ipv6.conf.all.forwarding=1"
        );

        if ipv4_only {
            info!(
                "Make sure your firewall routes packets, replace the dev_name with \n\
                your active network interface (like eth0) and run the following commands for iptables \n\
                or equivalent in your OS: \n\
                iptables -t nat -I POSTROUTING -o dev_name -p tcp --dport {} -j MASQUERADE",
                remote_addr.port(),
            );
        } else {
            info!(
                "Make sure your firewall routes packets, replace the dev_name with \n\
                your active network interface (like eth0) and run the following commands for iptables \n\
                or equivalent in your OS: \n\
                iptables -t nat -I POSTROUTING -o dev_name -p tcp --dport {} -j MASQUERADE\n\
                ip6tables -t nat -I POSTROUTING -o dev_name -p tcp --dport {} -j MASQUERADE",
                remote_addr.port(),
                remote_addr.port(),
            );
        }

        Box::new(|| {})
    };

    ctrlc::set_handler(move || {
        exit_fn();
        std::process::exit(0);
    })
    .expect("Error setting Ctrl-C handler");

    info!("Created TUN device {}", tun.name());

    let timeout = matches
        .get_one::<String>("timeout")
        .map(|f| f.parse::<u64>().unwrap());

    let stack = Arc::new(Stack::new(tun, tun_peer, tun_peer6, timeout));

    let local_addr = local_addr.clone();
    let mut buf_r = [0u8; MAX_PACKET_LEN];
    let udp_sock = new_udp_reuseport(*local_addr).unwrap();

    'main_loop: loop {
        let (size, addr) = udp_sock.recv_from(&mut buf_r).await.unwrap();

        info!("New UDP client from {}", addr);
        let stack = stack.clone();
        let local_addr = local_addr.clone();
        let handshake_packet = handshake_packet.clone();
        let encryption = encryption.clone();

        let udp_socks: Arc<Vec<_>> = {
            let mut socks = Vec::with_capacity(udp_socks_amount);
            for _ in 0..udp_socks_amount {
                let udp_sock = match new_udp_reuseport(*local_addr) {
                    Ok(udp_sock) => udp_sock,
                    Err(err) => {
                        error!("Craeting new udp socket error: {err}");
                        continue 'main_loop;
                    }
                };
                if let Err(err) = udp_sock.connect(addr).await {
                    error!("Unable to connect to {addr} over udp: {err}");
                    continue 'main_loop;
                }

                socks.push(Arc::new(udp_sock));
            }
            Arc::new(socks)
        };

        let cancellation = CancellationToken::new();
        let (packet_received_tx, _) = broadcast::channel(1);

        let first_packet = Some(buf_r[..size].into());
        let mut tcp_connect = TcpConnect {
            udp_socks: udp_socks.clone(),
            encryption: encryption.clone(),
            packet_received_tx: packet_received_tx.clone(),
            handshake_packet: handshake_packet.clone(),
            cancellation: cancellation.clone(),
            first_packet,
        };

        let tcp_socks: Arc<Vec<_>> = {
            let mut socks = Vec::with_capacity(tcp_socks_amount);
            let mut set = JoinSet::new();
            let mut first_connection = true;
            let mut first_port = 0u16;
            for i in 0..tcp_socks_amount {
                debug!("Creating tcp stream {i} to {remote_addr} for {addr}.");
                let stack = stack.clone();
                let tcp_connect_clone = tcp_connect.clone();
                if first_connection {
                    let mut buf = [0u8; MAX_PACKET_LEN];
                    let res = stack.connect(&mut buf, remote_addr, 0).await;
                    let tcp_sock = if let Some((tcp_sock, port)) = res {
                        first_port = port;
                        Arc::new(tcp_sock)
                    } else {
                        error!("Unable to connect a tcp sock to remote {remote_addr} for {addr}");
                        continue 'main_loop;
                    };
                    {
                        let tcp_sock = tcp_sock.clone();
                        tokio::spawn(async move {
                            tcp_connect_clone.handle(&mut buf, tcp_sock).await;
                        });
                    }
                    socks.push(tcp_sock);
                    first_connection = false;
                    continue;
                }
                set.spawn(async move {
                    let mut buf = [0u8; MAX_PACKET_LEN];
                    let (tcp_sock, _) = stack
                        .connect(&mut buf, remote_addr, first_port as u32)
                        .await?;
                    let tcp_sock = Arc::new(tcp_sock);
                    {
                        let tcp_sock = tcp_sock.clone();
                        tokio::spawn(async move {
                            tcp_connect_clone.handle(&mut buf, tcp_sock).await;
                        });
                    }
                    Some(tcp_sock)
                });
                tcp_connect.first_packet = None;
            }
            while let Some(tcp_sock) = set.join_next().await {
                let tcp_sock = match tcp_sock {
                    Ok(tcp_sock) => match tcp_sock {
                        Some(tcp_sock) => tcp_sock,
                        None => {
                            error!(
                                "Unable to connect a tcp sock to remote {remote_addr} for {addr}"
                            );
                            cancellation.cancel();
                            continue 'main_loop;
                        }
                    },
                    Err(err) => {
                        error!(
                                "Unable to join a tcp sock connection to remote {remote_addr} for {addr}: {err}"
                            );
                        cancellation.cancel();
                        continue 'main_loop;
                    }
                };
                socks.push(tcp_sock);
            }
            Arc::new(socks)
        };

        for (_, udp_sock) in udp_socks.iter().enumerate() {
            let udp_sock = udp_sock.clone();
            let mut packet_received_rx = packet_received_tx.subscribe();
            let packet_received_tx = packet_received_tx.clone();
            let cancellation = cancellation.clone();
            let encryption = encryption.clone();
            let tcp_socks = tcp_socks.clone();
            tokio::spawn(async move {
                let mut buf_udp = [0u8; MAX_PACKET_LEN];
                let mut buf = [0u8; MAX_PACKET_LEN];
                let mut tcp_sock_index = 0usize;
                loop {
                    let read_timeout = time::sleep(UDP_SOCK_READ_DEADLINE);
                    tokio::select! {
                        biased;
                        _ = cancellation.cancelled() => {
                            debug!("Closing connection requested on {:?}, closing connection UDP", udp_sock);
                            break;
                        },
                        res = udp_sock.recv(&mut buf_udp) => {
                            match res {
                                Ok(size) => {
                                    if let Some(ref enc) = *encryption {
                                        enc.encrypt(&mut buf_udp[..size]);
                                    }
                                    tcp_sock_index = (tcp_sock_index + 1) % tcp_socks.len();
                                    if tcp_socks[tcp_sock_index].send(&mut buf, &buf_udp[..size]).await.is_none() {
                                        debug!("Unable to send TCP traffic on {:?}, closing connection", udp_sock);
                                        break;
                                    }
                                },
                                Err(e) => {
                                    debug!("UDP connection closed on {:?}: {e}, closing connection", udp_sock);
                                    break;
                                }
                            };
                        },
                        _ = packet_received_rx.recv() => {
                            continue;
                        },
                        _ = read_timeout => {
                            debug!("No traffic seen in the last {:?} on {:?}, closing connection", UDP_SOCK_READ_DEADLINE, udp_sock);
                            break;
                        },
                    };
                    _ = packet_received_tx.send(());
                }
                cancellation.cancel();
                info!("Connention {:?} closed", udp_sock);
            });
        }
    }
}

#[derive(Clone)]
struct TcpConnect {
    udp_socks: Arc<Vec<Arc<UdpSocket>>>,
    encryption: Arc<Option<Encryption>>,
    packet_received_tx: broadcast::Sender<()>,
    handshake_packet: Arc<Option<Vec<u8>>>,
    cancellation: CancellationToken,
    first_packet: Option<Vec<u8>>,
}

impl TcpConnect {
    async fn handle(&self, buf: &mut [u8], tcp_sock: Arc<Socket>) {
        let mut should_receive_handshake_packet = false;
        if let Some(ref packet) = *self.handshake_packet {
            should_receive_handshake_packet = true;
            if tcp_sock.send(buf, packet).await.is_none() {
                error!("Failed to send handshake packet to remote, closing connection.");
                self.cancellation.cancel();
                return;
            }
            debug!("Sent handshake packet to: {tcp_sock}");
        }

        let mut udp_sock_index = 0usize;
        loop {
            tokio::select! {
                biased;
                _ = self.cancellation.cancelled() => {
                    debug!("Closing connection requested on {tcp_sock}, closing connection");
                    break;
                }
                res = tcp_sock.recv(buf) => {
                    match res {
                        Some(size) => {
                            if should_receive_handshake_packet {
                                should_receive_handshake_packet = false;
                                trace!("Received handshake packet to: {tcp_sock}");

                                if let Some(ref packet) = self.first_packet {
                                    trace!("Sending first packet to: {tcp_sock}");
                                    if tcp_sock.send(buf, packet).await.is_none() {
                                        error!("Failed to send first packet to remote, closing connection.");
                                        break;
                                    }
                                }
                                continue;
                            }
                            if let Some(ref enc) = *self.encryption {
                                enc.decrypt(&mut buf[..size]);
                            }
                            udp_sock_index = (udp_sock_index + 1) % self.udp_socks.len();
                            if let Err(e) = self.udp_socks[udp_sock_index].send(&buf[..size]).await {
                                debug!("Unable to send UDP packet on {tcp_sock}: {e}, closing connection");
                                break;
                            }
                        },
                        None => {
                            break;
                        },
                    }
                },
            };
            _ = self.packet_received_tx.send(());
        }
        self.cancellation.cancel();
    }
}

#[cfg(target_os = "linux")]
fn auto_rule(
    dev_name: &str,
    ipv4_only: bool,
    remote_addr: SocketAddr,
) -> Box<dyn Fn() + 'static + Send> {
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

    let ipv4_forward_value: String = String::from_utf8(ipv4_forward_value.stdout)
        .unwrap()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();

    // let ipv4_forward_value = OsString::from(ipv4_forward_value);
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
        "-t nat -I POSTROUTING -o {dev_name} -p tcp --dport {} -j MASQUERADE",
        remote_addr.port()
    );
    let ip6tables_add_rule = format!(
        "-t nat -I POSTROUTING -o {dev_name} -p tcp --dport {} -j MASQUERADE",
        remote_addr.port()
    );

    let iptables_del_rule = format!(
        "-t nat -D POSTROUTING -o {dev_name} -p tcp --dport {} -j MASQUERADE",
        remote_addr.port()
    );
    let ip6tables_del_rule = format!(
        "-t nat -D POSTROUTING -o {dev_name} -p tcp --dport {} -j MASQUERADE",
        remote_addr.port()
    );

    let status = std::process::Command::new("iptables")
        .args(iptables_add_rule.split(' '))
        .output()
        .expect("iptables could not be executed.")
        .status;

    if !status.success() {
        panic!("{iptables_add_rule} could not be executed successfully: {status}.");
    }

    if !ipv4_only {
        let status = std::process::Command::new("ip6tables")
            .args(ip6tables_add_rule.split(' '))
            .output()
            .expect("ip6tables could not be executed.")
            .status;

        if !status.success() {
            panic!("{ip6tables_add_rule} could not be executed successfully: {status}.");
        }
    }
    Box::new(move || {
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

        if !ipv4_only {
            let status = std::process::Command::new("sysctl")
                .arg("-w")
                .arg(ipv6_forward_value.as_ref().unwrap())
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
                .args(ip6tables_del_rule.split(' '))
                .output()
                .expect("ip6tables could not be executed.")
                .status;

            if !status.success() {
                panic!("{ip6tables_del_rule} could not be executed successfully: {status}.");
            }

            info!("Respective ip6tables rules removed.");
        }
    })
}

#[cfg(target_os = "macos")]
fn auto_rule(
    dev_name: &str,
    int_name: &str,
    peer: Ipv4Addr,
    peer6: Option<Ipv6Addr>,
) -> Box<dyn Fn() + 'static + Send> {
    use std::process::Stdio;

    use tonel::utils::{add_routes, delete_routes};

    let ipv4_forward_value = std::process::Command::new("sysctl")
        .arg("net.inet.ip.forwarding")
        .output()
        .expect("sysctl net.inet.ip.forwarding could not be executed.");

    if !ipv4_forward_value.status.success() {
        panic!(
            "sysctl net.inet.ip.forwarding could not be executed successfully: {}.",
            ipv4_forward_value.status
        );
    }

    let status = std::process::Command::new("sysctl")
        .arg("net.inet.ip.forwarding=1")
        .output()
        .expect("sysctl net.inet.ip.forwarding=1 could not be executed.")
        .status;

    if !status.success() {
        panic!("sysctl net.inet.ip.forwarding=1 could not be executed successfully: {status}.");
    }

    let ipv4_forward_value: String = String::from_utf8(ipv4_forward_value.stdout)
        .unwrap()
        .replace(": ", "=")
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();

    // let ipv4_forward_value = OsString::from(ipv4_forward_value);
    let ipv6_forward_value: Option<String> = if peer6.is_some() {
        let ipv6_forward_value = std::process::Command::new("sysctl")
            .arg("net.inet6.ip6.forwarding")
            .output()
            .expect("sysctl net.inet6.ip6.forwarding could not be executed.");

        if !ipv6_forward_value.status.success() {
            panic!(
                "sysctl net.inet6.ip6.forwarding could not be executed successfully: {}.",
                ipv6_forward_value.status
            );
        }

        let status = std::process::Command::new("sysctl")
            .arg("-w")
            .arg("net.inet6.ip6.forwarding=1")
            .output()
            .expect("sysctl -w net.inet6.ip6.forwarding=1 could not be executed.")
            .status;

        if !status.success() {
            panic!(
                "sysctl net.inet6.ip6.forwarding=1 could not be executed successfully: {status}."
            );
        }

        Some(
            String::from_utf8(ipv6_forward_value.stdout)
                .unwrap()
                .replace(": ", "=")
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect(),
        )
    } else {
        None
    };

    let mut pfctl = std::process::Command::new("pfctl")
        .arg("-e")
        .arg("-a")
        .arg("com.apple/tonel")
        .arg("-f")
        .arg("-")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::piped())
        .spawn()
        .expect("Failed to spawn pfctl process.");

    let mut nat_rules = format!("nat on {int_name} from {peer}/24 to any -> ({int_name})\n");
    if let Some(peer6) = peer6 {
        nat_rules += format!("nat on {int_name} from {peer6}/64 to any -> ({int_name})\n").as_str();
    }
    pfctl
        .stdin
        .take()
        .expect("Failed to open stdin for pfctl command.")
        .write_all(nat_rules.as_bytes())
        .expect("Failed to write pfctl rules");

    pfctl.wait().expect("Failed to add pfctl rules.");

    add_routes(dev_name, peer, peer6);

    Box::new(move || {
        let status = std::process::Command::new("sysctl")
            .arg(&ipv4_forward_value)
            .output()
            .unwrap_or_else(|err| {
                panic!(
                    "sysctl '{:?}' could not be executed: {err}.",
                    ipv4_forward_value
                )
            })
            .status;
        if !status.success() {
            panic!(
                "sysctl '{:?}' could not be executed successfully: {status}.",
                ipv4_forward_value
            );
        }

        let _ = std::process::Command::new("pfctl")
            .arg("-a")
            .arg("com.apple/tonel")
            .arg("-f")
            .arg("-")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .status();

        if peer6.is_some() {
            let status = std::process::Command::new("sysctl")
                .arg(ipv6_forward_value.as_ref().unwrap())
                .output()
                .unwrap_or_else(|err| {
                    panic!(
                        "sysctl '{:?}' could not be executed: {err}.",
                        ipv6_forward_value
                    )
                })
                .status;
            if !status.success() {
                panic!(
                    "sysctl '{:?}' could not be executed successfully: {status}.",
                    ipv6_forward_value
                );
            }

            delete_routes(peer, peer6);
        }
    })
}
