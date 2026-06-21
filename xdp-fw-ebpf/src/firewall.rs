use crate::parse::ptr_at;
use aya_ebpf::bindings::xdp_action::{XDP_DROP, XDP_PASS};
use aya_ebpf::macros::map;
use aya_ebpf::maps::{Array, RingBuf};
use aya_ebpf::programs::XdpContext;

use core::net::Ipv4Addr;

use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

use xdp_fw_common::logs::logs::LogEvent;
use xdp_fw_common::rules::rules::{
    ipv4_bytes_to_u32, rule_matches, FlowKey, Rule, MAX_RULES,
};

#[map]
static RULES: Array<Rule> = Array::with_max_entries(MAX_RULES as u32, 0);

#[map]
static RULE_COUNT: Array<u32> = Array::with_max_entries(1, 0);

#[map]
static LOGS: RingBuf = RingBuf::with_byte_size(1024 * 64, 0);

pub fn handle(ctx: XdpContext) -> Result<u32, ()> {
    let eth: *const EthHdr = ptr_at(&ctx, 0)?;
    if unsafe { (*eth).ether_type } != EtherType::Ipv4 as u16 {
        return Ok(XDP_PASS);
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let src = unsafe { (*ipv4hdr).src_addr };
    let dst = unsafe { (*ipv4hdr).dst_addr };
    let ip_proto = unsafe { (*ipv4hdr).proto };

    let mut source_port: u16 = 0;
    let mut dest_port: u16 = 0;
    let mut protocol: u8 = ip_proto as u8;

    match ip_proto {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr =
                ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            protocol = 6;
            source_port = u16::from_be_bytes(unsafe { (*tcphdr).source });
            dest_port = u16::from_be_bytes(unsafe { (*tcphdr).dest });
        }

        IpProto::Udp => {
            let udphdr: *const UdpHdr =
                ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            protocol = 17;
            source_port = unsafe { (*udphdr).src_port() };
            dest_port = unsafe { (*udphdr).dst_port() };
        }

        _ => {}
    }

    let key = FlowKey {
        src_ip: ipv4_bytes_to_u32(src),
        dest_ip: ipv4_bytes_to_u32(dst),
        src_port: source_port,
        dest_port,
        protocol,
    };

    let mut action: u8 = 0;

    let rule_count = RULE_COUNT
        .get(0)
        .copied()
        .unwrap_or(0)
        .min(MAX_RULES as u32);

    let mut i = 0u32;
    while i < rule_count {
        if let Some(rule) = RULES.get(i) {
            if rule_matches(rule, &key) {
                action = rule.action;
                break;
            }
        }
        i += 1;
    }

    let ip = Ipv4Addr::from(src);

    if let Some(mut slot) = LOGS.reserve::<LogEvent>(0) {
        slot.write(LogEvent {
            src_ip: ip.octets(),
            source_port,
            dest_port,
            protocol,
            action,
        });
        slot.submit(0);
    }

    match action {
        1 => Ok(XDP_DROP),
        _ => Ok(XDP_PASS),
    }
}
