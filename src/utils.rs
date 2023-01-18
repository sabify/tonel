#[cfg(any(target_os = "linux", target_os = "android"))]
use neli::{
    consts::{
        nl::{NlmF, NlmFFlags},
        rtnl::{Ifa, IfaFFlags, RtAddrFamily, Rtm},
        socket::NlFamily,
    },
    nl::{NlPayload, Nlmsghdr},
    rtnl::{Ifaddrmsg, Rtattr},
    socket::NlSocketHandle,
    types::RtBuffer,
};

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::net::UdpSocket;

pub fn new_udp_reuseport(local_addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let udp_sock = socket2::Socket::new(
        if local_addr.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        },
        socket2::Type::DGRAM,
        None,
    )?;
    udp_sock.set_reuse_port(true)?;
    udp_sock.set_reuse_address(true)?;
    // from tokio-rs/mio/blob/master/src/sys/unix/net.rs
    udp_sock.set_cloexec(true)?;
    udp_sock.set_nonblocking(true)?;
    udp_sock.bind(&socket2::SockAddr::from(local_addr))?;
    let udp_sock: std::net::UdpSocket = udp_sock.into();
    udp_sock.try_into()
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn assign_ipv6_address(device_name: &str, local: Ipv6Addr, peer: Ipv6Addr) {
    {
        let index = nix::net::if_::if_nametoindex(device_name).unwrap();

        let mut rtnl = NlSocketHandle::connect(NlFamily::Route, None, &[]).unwrap();
        let mut rtattrs = RtBuffer::new();
        rtattrs.push(Rtattr::new(None, Ifa::Local, &local.octets()[..]).unwrap());
        rtattrs.push(Rtattr::new(None, Ifa::Address, &peer.octets()[..]).unwrap());

        let ifaddrmsg = Ifaddrmsg {
            ifa_family: RtAddrFamily::Inet6,
            ifa_prefixlen: 64,
            ifa_flags: IfaFFlags::empty(),
            ifa_scope: 0,
            ifa_index: index as i32,
            rtattrs,
        };
        let nl_header = Nlmsghdr::new(
            None,
            Rtm::Newaddr,
            NlmFFlags::new(&[NlmF::Request]),
            None,
            None,
            NlPayload::Payload(ifaddrmsg),
        );
        rtnl.send(nl_header).unwrap();
    }
}

#[cfg(any(
    target_os = "openbsd",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    target_os = "macos",
))]
pub fn assign_ipv6_address(dev_name: &str, local: Ipv6Addr) {
    {
        std::process::Command::new("ifconfig")
            .arg(dev_name)
            .arg("inet6")
            .arg(format!("{local}/64"))
            .status()
            .unwrap_or_else(|e| panic!("ifconfig set IPv6 local address failed {e}"));
    }
}

#[cfg(any(
    target_os = "openbsd",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    target_os = "macos",
))]
pub fn add_routes(dev_name: &str, peer: Ipv4Addr, peer6: Option<Ipv6Addr>) {
    let interface_keyword = "-interface";
    #[cfg(target_os = "openbsd")]
    let interface_keyword = "-iface";
    let _ = std::process::Command::new("route")
        .arg("-q")
        .arg("-n")
        .arg("add")
        .arg("-inet")
        .arg(format!("{peer}/24"))
        .arg(interface_keyword)
        .arg(dev_name)
        .output();

    if let Some(peer6) = peer6 {
        let _ = std::process::Command::new("route")
            .arg("-q")
            .arg("-n")
            .arg("add")
            .arg("-inet6")
            .arg(format!("{peer6}/64"))
            .arg(interface_keyword)
            .arg(dev_name)
            .output();
    }
}

#[cfg(any(
    target_os = "openbsd",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    target_os = "macos",
))]
pub fn delete_routes(peer: Ipv4Addr, peer6: Option<Ipv6Addr>) {
    let _ = std::process::Command::new("route")
        .arg("-q")
        .arg("-n")
        .arg("delete")
        .arg("-inet")
        .arg(format!("{peer}/24"))
        .output();

    if let Some(peer6) = peer6 {
        let _ = std::process::Command::new("route")
            .arg("-q")
            .arg("-n")
            .arg("delete")
            .arg("-inet6")
            .arg(format!("{peer6}/64"))
            .output();
    }
}
