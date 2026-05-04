use anyhow::Result;
use clap::Parser;
use std::{net::Ipv4Addr, sync::Arc, time::Duration};
use aya::maps::{HashMap, RingBuf};
use tokio::{sync::Mutex, time};

use rand::Rng;
use ratatui::text::Line;
#[allow(unused_imports)]
use xdp_fw::app::App;
use xdp_fw::cli::Opt;
use xdp_fw::loader::{attach_xdp, bump_memlock_rlimit, init_aya_log, load_ebpf};
#[allow(unused_imports)]
use xdp_fw::tui::Tui;
use xdp_fw_common::logs::logs::LogEvent;
use xdp_fw_common::rules::rules::{Action, FlowKey, Protocol, Rule};

fn drain_log_ring_once(log_ring: &mut RingBuf<&mut aya::maps::MapData>,app: &mut App) {
    while let Some(item) = log_ring.next() {
        let data: &[u8] = &*item;

        if data.len() < std::mem::size_of::<LogEvent>() {
            continue;
        }

        let event =
            unsafe { std::ptr::read_unaligned(data.as_ptr().cast::<LogEvent>()) };

        let ip = std::net::Ipv4Addr::from(event.src_ip);

        // println!(
        //     "ip={ip} sport={} dport={} proto={} action={}",
        //     event.source_port,
        //     event.dest_port,
        //     event.protocol,
        //     event.action,
        // );

        app.logs.push(Line::from(format!("ip={ip} sport={} dport={} proto={} action={}",
                                         event.source_port,
                                         event.dest_port,
                                         event.protocol,
                                         event.action,)))
    }
}

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
            "1.1.1.2",
            0,
            "0.0.0.0",
            0,
            Protocol::Any,
            Action::Drop,
        )?;
    }

    let app = Arc::new(Mutex::new(App::new()));
    let app_drain = Arc::clone(&app);


    println!("Polling LOGS ring (Ctrl+C to exit).");

    let _drain_join = tokio::spawn(async move {
        let mut ebpf = ebpf;

        let ctrl_c = tokio::signal::ctrl_c();
        tokio::pin!(ctrl_c);
        loop {
            let mut log_ring =
                match RingBuf::try_from(ebpf.map_mut("LOGS").expect("LOGS ring buffer")) {
                    Ok(r) => r,
                    Err(_) => break,
                };
            tokio::select! {
              _ = ctrl_c.as_mut() => break,
              _ = time::sleep(Duration::from_millis(50)) => {
                  let mut g = app_drain.lock().await;
                  drain_log_ring_once(&mut log_ring, &mut *g);
              }
          }
            // `log_ring` dropped here → next iteration can borrow `ebpf` again for `map_mut`
        }
        drop(ebpf);
    });
    let mut tui = Tui::new()?;
    tui.run(app).await?;
    Ok(())
}
