use crate::iface::Local;
use anyhow::{Context, Result};
use pnet::datalink::DataLinkSender;
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::icmpv6::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmpv6::{self, Icmpv6Code, Icmpv6Packet, Icmpv6Types, MutableIcmpv6Packet};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv6::MutableIpv6Packet;
use pnet::packet::MutablePacket;
use pnet::util::MacAddr;
use std::net::Ipv6Addr;

const ETH_HDR: usize = 14;
const IP6_HDR: usize = 40;
const ICMP_LEN: usize = 16; // 8 bytes of echo header + 8 of payload
const FRAME: usize = ETH_HDR + IP6_HDR + ICMP_LEN;

/// The link-local scope "all-nodes" multicast address.
const ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
/// Destination MAC derived from ff02::1 per RFC 2464: 33:33 + the last 4 bytes.
const ALL_NODES_MAC: MacAddr = MacAddr(0x33, 0x33, 0x00, 0x00, 0x00, 0x01);
/// Echo identifier; it only needs to be stable within one run.
const ECHO_IDENT: u16 = 0x1_5ca;

/// Fires ICMPv6 Echo Requests at ff02::1.
///
/// Every device with an IPv6 stack answers with its link-local address,
/// revealing the MAC **regardless of the IPv4 it has configured**. That is what
/// lets us list the whole broadcast domain without guessing a single IPv4
/// subnet.
pub fn ping_all_nodes(tx: &mut Box<dyn DataLinkSender>, local: &Local, count: usize) -> Result<usize> {
    let Some(src) = local.link_local else {
        return Ok(0);
    };

    let mut sent = 0;
    for seq in 0..count {
        let mut buf = [0u8; FRAME];
        build(&mut buf, local, src, seq as u16);
        match tx.send_to(&buf, None) {
            Some(Ok(())) => sent += 1,
            Some(Err(e)) => return Err(e).context("failed to send ICMPv6 to ff02::1"),
            None => anyhow::bail!("send buffer too small for ICMPv6"),
        }
        std::thread::sleep(std::time::Duration::from_millis(120));
    }
    Ok(sent)
}

fn build(buf: &mut [u8; FRAME], local: &Local, src: Ipv6Addr, seq: u16) {
    {
        let mut eth = MutableEthernetPacket::new(&mut buf[..]).expect("frame is sized");
        eth.set_destination(ALL_NODES_MAC);
        eth.set_source(local.mac);
        eth.set_ethertype(EtherTypes::Ipv6);

        let mut ip6 = MutableIpv6Packet::new(eth.payload_mut()).expect("ipv6 header");
        ip6.set_version(6);
        ip6.set_traffic_class(0);
        ip6.set_flow_label(0);
        ip6.set_payload_length(ICMP_LEN as u16);
        ip6.set_next_header(IpNextHeaderProtocols::Icmpv6);
        // 255 is mandatory for NDP and conventional here: it guarantees no
        // router forwards the packet off the link.
        ip6.set_hop_limit(255);
        ip6.set_source(src);
        ip6.set_destination(ALL_NODES);

        let mut echo = MutableEchoRequestPacket::new(ip6.payload_mut()).expect("echo request");
        echo.set_icmpv6_type(Icmpv6Types::EchoRequest);
        echo.set_icmpv6_code(Icmpv6Code(0));
        echo.set_identifier(ECHO_IDENT);
        echo.set_sequence_number(seq);
        echo.set_payload(b"ipscan\0\0");
    }

    // The ICMPv6 checksum covers a pseudo-header with source and destination,
    // so it can only be computed once the IPv6 header is already filled in.
    let off = ETH_HDR + IP6_HDR;
    let cks = {
        let p = Icmpv6Packet::new(&buf[off..]).expect("icmpv6 assembled");
        icmpv6::checksum(&p, &src, &ALL_NODES)
    };
    let mut icmp = MutableIcmpv6Packet::new(&mut buf[off..]).expect("icmpv6 mutable");
    icmp.set_checksum(cks);
}
