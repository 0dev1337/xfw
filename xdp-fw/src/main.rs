use anyhow::Result;
use clap::Parser;
use std::net::Ipv4Addr;
use tokio::signal;

use aya::maps::{HashMap, RingBuf};

use xdp_fw::app::App;
use xdp_fw::cli::Opt;
use xdp_fw::loader::{attach_xdp, bump_memlock_rlimit, init_aya_log, load_ebpf};
use xdp_fw::tui::Tui;

use xdp_fw_common::rules::rules::{Action, FlowKey, Protocol, Rule};

fn insert_rule(
    rules: &mut HashMap<&mut aya::maps::MapData, FlowKey, Rule>,
    src_ip: &str,
    src_port: u16,
    dest_ip: &str,
    dest_port: u16,
    protocol: Protocol,
    action: Action,
) -> Result<()> {
    let src_ip: Ipv4Addr = src_ip.parse()?;
    let dest_ip: Ipv4Addr = dest_ip.parse()?;

    let key = FlowKey {
        src_ip: src_ip.octets(),
    };
    let rule = Rule {
        src_ip: src_ip.octets(),
        src_port,
        dest_ip: dest_ip.octets(),
        dest_port,
        protocol: protocol as u8,
        action: action as u8,
    };

    rules.insert(key, rule, 0)?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::parse();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    bump_memlock_rlimit();

    let mut ebpf = load_ebpf()?;

    init_aya_log(&mut ebpf);

    attach_xdp(&mut ebpf, &opt.iface)?;

    {
        let mut rules =
            HashMap::try_from(ebpf.map_mut("RULES").expect("RULES map"))?;
        insert_rule(
            &mut rules,
            "1.1.1.1",
            0,
            "0.0.0.0",
            0,
            Protocol::Any,
            Action::Drop,
        )?;
    }

    let mut log_ring = RingBuf::try_from(ebpf.map_mut("LOGS").expect("LOGS ring buffer"))?;

    let mut app = App::new();
    let mut tui = Tui::new()?;
    tui.run(&mut app, &mut log_ring).await?;

    println!("Ctrl-C to exit.");
    signal::ctrl_c().await?;

    Ok(())
}
