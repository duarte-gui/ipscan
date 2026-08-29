use crate::dhcp::{self, DhcpObservation};
use crate::rawsock::RawSocket;
use pnet::packet::arp::{ArpOperations, ArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use pnet::util::MacAddr;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::Sender;

/// How a (MAC, IP) pair came to our attention. This sets the confidence: an
/// ArpReply is direct proof, while an Ipv4Source is merely observed traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub enum Source {
    /// Answered an ARP request, ours or someone else's.
    ArpReply,
    /// Sent an ARP request, revealing its own IP in the sender field.
    ArpRequest,
    /// Gratuitous ARP: sender IP == target IP, typical at boot or on IP change.
    Gratuitous,
    /// Source address of any captured IPv4 packet.
    Ipv4Source,
    /// Seen inside a DHCP packet.
    Dhcp,
    /// Answered the ICMPv6 to ff02::1, or showed up in an NS/NA.
    Ndp,
}

impl Source {
    pub fn label(&self) -> &'static str {
        match self {
            Source::ArpReply => "arp-reply",
            Source::ArpRequest => "arp-request",
            Source::Gratuitous => "gratuitous-arp",
            Source::Ipv4Source => "ipv4-traffic",
            Source::Dhcp => "dhcp",
            Source::Ndp => "ipv6-ndp",
        }
    }
}

/// Frames the kernel dropped because the queue was full. If this is non-zero
/// the result is incomplete — and the user needs to be told.
pub static KERNEL_DROPS: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
pub enum Event {
    /// A MAC was tied to an IPv4 address.
    V4 { mac: MacAddr, ip: Ipv4Addr, src: Source },
    /// A MAC was seen with an IPv6 address (usually link-local).
    V6 { mac: MacAddr, ip: Ipv6Addr },
    /// A DHCP observation (request, ack, ...).
    Dhcp(Box<DhcpObservation>),
}

/// Receive loop. Runs on its own thread and pushes parsed events out. It never
/// takes the program down: a malformed frame is simply skipped.
pub fn rx_loop(
    mut rx: RawSocket,
    tx: Sender<Event>,
    stop: &'static AtomicBool,
    local_mac: MacAddr,
) {
    // The kernel resets the counter on every read, so we accumulate it here.
    let mut since_stats = 0u32;

    while !stop.load(Ordering::Relaxed) {
        since_stats += 1;
        if since_stats >= 2048 {
            since_stats = 0;
            let (_, drops) = rx.stats();
            if drops > 0 {
                KERNEL_DROPS.fetch_add(drops as u64, Ordering::Relaxed);
            }
        }

        let frame = match rx.recv() {
            Some(f) => f,
            // The timeout fires constantly; that is how we check the stop flag.
            None => continue,
        };
        let eth = match EthernetPacket::new(frame) {
            Some(e) => e,
            None => continue,
        };
        // Skip what we sent ourselves, or we would show up as a "host".
        if eth.get_source() == local_mac {
            continue;
        }
        match eth.get_ethertype() {
            EtherTypes::Arp => handle_arp(&eth, &tx),
            EtherTypes::Ipv4 => handle_ipv4(&eth, &tx),
            EtherTypes::Ipv6 => handle_ipv6(&eth, &tx),
            _ => {}
        }
    }

    let (_, drops) = rx.stats();
    if drops > 0 {
        KERNEL_DROPS.fetch_add(drops as u64, Ordering::Relaxed);
    }
}

fn handle_arp(eth: &EthernetPacket, tx: &Sender<Event>) {
    let arp = match ArpPacket::new(eth.payload()) {
        Some(a) => a,
        None => return,
    };
    let sender_mac = arp.get_sender_hw_addr();
    let sender_ip = arp.get_sender_proto_addr();
    let target_ip = arp.get_target_proto_addr();

    // A 0.0.0.0 sender is an ARP probe (DAD): the host has not claimed the
    // address yet, but the target field reveals which one it is about to take.
    if sender_ip.is_unspecified() {
        if !target_ip.is_unspecified() {
            let _ = tx.send(Event::V4 { mac: sender_mac, ip: target_ip, src: Source::Gratuitous });
        }
        return;
    }

    let src = if arp.get_operation() == ArpOperations::Reply {
        Source::ArpReply
    } else if sender_ip == target_ip {
        Source::Gratuitous
    } else {
        Source::ArpRequest
    };
    let _ = tx.send(Event::V4 { mac: sender_mac, ip: sender_ip, src });
}

fn handle_ipv4(eth: &EthernetPacket, tx: &Sender<Event>) {
    let ip = match Ipv4Packet::new(eth.payload()) {
        Some(p) => p,
        None => return,
    };
    let src_ip = ip.get_source();
    let mac = eth.get_source();

    // DHCP travels with a 0.0.0.0 source before the lease exists; the pair
    // (MAC, 0.0.0.0) says nothing, but the BOOTP payload says everything.
    if ip.get_next_level_protocol() == pnet::packet::ip::IpNextHeaderProtocols::Udp {
        if let Some(udp) = UdpPacket::new(ip.payload()) {
            let (sp, dp) = (udp.get_source(), udp.get_destination());
            if sp == 67 || sp == 68 || dp == 67 || dp == 68 {
                if let Some(obs) = dhcp::parse(udp.payload(), mac, src_ip) {
                    let _ = tx.send(Event::Dhcp(Box::new(obs)));
                }
            }
        }
    }

    if !src_ip.is_unspecified() && !src_ip.is_broadcast() && !src_ip.is_multicast() {
        let _ = tx.send(Event::V4 { mac, ip: src_ip, src: Source::Ipv4Source });
    }
}

fn handle_ipv6(eth: &EthernetPacket, tx: &Sender<Event>) {
    let ip = match Ipv6Packet::new(eth.payload()) {
        Some(p) => p,
        None => return,
    };
    let mac = eth.get_source();
    let src = ip.get_source();
    if !src.is_unspecified() && !src.is_multicast() {
        let _ = tx.send(Event::V6 { mac, ip: src });
    }
}
