use crate::parse::ptr_at;
use aya_ebpf::bindings::xdp_action::{XDP_DROP, XDP_PASS};
use aya_ebpf::macros::map;
use aya_ebpf::maps::{HashMap, RingBuf};
use aya_ebpf::programs::XdpContext;
use aya_log_ebpf::info;
use core::net::Ipv4Addr;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use xdp_fw_common::logs::logs::LogEvent;
use xdp_fw_common::rules::rules::{FlowKey, Rule};

#[map]
static RULES: HashMap<FlowKey, Rule> = HashMap::with_max_entries(1024, 0);

#[map]
static LOGS: RingBuf = RingBuf::with_byte_size(1024 * 64, 0);

pub fn handle(ctx: XdpContext) -> Result<u32, ()> {
    let eth: *const EthHdr = ptr_at(&ctx, 0)?;
    if unsafe { (*eth).ether_type } != EtherType::Ipv4 as u16 {
        return Ok(XDP_PASS);
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let src = unsafe { (*ipv4hdr).src_addr };
    let mut protocol: u8 = 0;
    let (source_port, dest_port) = match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            protocol = 6;

            let src = u16::from_be_bytes(unsafe { (*tcphdr).source });
            let dst = u16::from_be_bytes(unsafe { (*tcphdr).dest });
            (src, dst)
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            protocol = 17;

            let src = unsafe { (*udphdr).src_port() };
            let dst = unsafe { (*udphdr).dst_port() };
            (src, dst)
        }
        _ => (0, 0),
    };

    let key = FlowKey { src_ip: src };
    if let Some(rule) = unsafe { RULES.get(&key) } {
        let ip = Ipv4Addr::from(rule.src_ip);
        info!(
            &ctx,
            "rule match src={} sport={} dport={} proto={} action={}",
            ip,
            rule.src_port,
            rule.dest_port,
            rule.protocol,
            rule.action
        );

        return match rule.action {
            0 => Ok(XDP_PASS),
            1 => Ok(XDP_DROP),
            _ => Ok(XDP_PASS),
        };
    } else {
        let ip = Ipv4Addr::from(src);
        if let Some(mut slot) = LOGS.reserve::<LogEvent>(0) {
            slot.write(LogEvent {
                src_ip: ip.octets(),
                source_port,
                dest_port,
                protocol,
                action: 0,
            });
            slot.submit(0);
        }
    }

    Ok(XDP_PASS)
}
