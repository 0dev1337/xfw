#![cfg_attr(target_arch = "bpf", no_std)]
#![cfg_attr(target_arch = "bpf", no_main)]

#[cfg(target_arch = "bpf")]
mod firewall;
#[cfg(target_arch = "bpf")]
mod parse;

#[cfg(target_arch = "bpf")]
use aya_ebpf::bindings::xdp_action;
#[cfg(target_arch = "bpf")]
use aya_ebpf::macros::xdp;
#[cfg(target_arch = "bpf")]
use aya_ebpf::programs::XdpContext;

#[cfg(target_arch = "bpf")]
#[xdp]
pub fn xdp_fw(ctx: XdpContext) -> u32 {
    match firewall::handle(ctx) {
        Ok(ret) => ret,
        Err(()) => xdp_action::XDP_ABORTED,
    }
}

#[cfg(all(target_arch = "bpf", not(test)))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[cfg(target_arch = "bpf")]
#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";

#[cfg(not(target_arch = "bpf"))]
fn main() {}
