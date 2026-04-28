#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_ebpf::bindings::xdp_action::{XDP_DROP, XDP_PASS};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use core::net::Ipv4Addr;
use core::mem;
#[inline(always)] // (1)
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}


#[xdp]
pub fn xdp_fw(ctx: XdpContext) -> u32 {
    match try_xdp_fw(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_xdp_fw(ctx: XdpContext) -> Result<u32, ()> {
    let ethaddr: *const EthHdr = ptr_at(&ctx,0)?;
    // info!(&ctx, "HELLO FROM THE KERNEL");
    if unsafe { (*ethaddr).ether_type } != EtherType::Ipv4 as u16{
        return Ok(XDP_PASS);
    }
    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx,EthHdr::LEN)?;
    let source_addr = unsafe {(*ipv4hdr).src_addr };
    let ip = Ipv4Addr::from(source_addr);
    if ip == Ipv4Addr::from(u32::from_be_bytes([8,8,8,8])) {
        info!(&ctx, "blocked a packet from {}", ip);

        return Ok(XDP_DROP);
    }
    // info!(&ctx, "HELLO FROM THE KERNEL");
    info!(&ctx, "received a packet from {}", ip);
    Ok(xdp_action::XDP_DROP)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
