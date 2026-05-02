#![no_std]
#![no_main]

mod firewall;
mod parse;

use aya_ebpf::bindings::xdp_action;
use aya_ebpf::macros::xdp;
use aya_ebpf::programs::XdpContext;

#[xdp]
pub fn xdp_fw(ctx: XdpContext) -> u32 {
    match firewall::handle(ctx) {
        Ok(ret) => ret,
        Err(()) => xdp_action::XDP_ABORTED,
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
