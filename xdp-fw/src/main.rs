use anyhow::Result;
use clap::Parser;
use std::{sync::Arc, time::Duration};

use aya::maps::{HashMap, RingBuf};
use tokio::{sync::Mutex, time};

use ratatui::text::Line;
use xdp_fw::tui::Tui;
use xdp_fw::{app, util};
use xdp_fw::app::App;
use xdp_fw::cli::Opt;
use xdp_fw::loader::{attach_xdp, bump_memlock_rlimit, init_aya_log, load_ebpf};

use xdp_fw_common::logs::logs::LogEvent;
use xdp_fw_common::rules::rules::{Action, Protocol};

fn drain_log_ring_once(
    log_ring: &mut RingBuf<&mut aya::maps::MapData>,
    app: &mut App,
) {
    while let Some(item) = log_ring.next() {
        let data: &[u8] = &*item;

        if data.len() < std::mem::size_of::<LogEvent>() {
            continue;
        }

        let event = unsafe {
            std::ptr::read_unaligned(data.as_ptr().cast::<LogEvent>())
        };

        let ip = std::net::Ipv4Addr::from(event.src_ip);

        let msg = Line::from(format!(
            "ip={ip} sport={} dport={} proto={} action={}",
            event.source_port,
            event.dest_port,
            event.protocol,
            event.action,
        ));

        if event.action == Action::Allow as u8 {
            app.push_allow(msg);
        } else {
            app.push_deny(msg);
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::parse();
    let app = Arc::new(Mutex::new(App::new()));
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    bump_memlock_rlimit();

    let mut ebpf = load_ebpf()?;

    init_aya_log(&mut ebpf);

    attach_xdp(&mut ebpf, &opt.iface)?;

    {
        let mut g = app.lock().await;
        g.set_ebpf(ebpf);
        let ebpf = g.ebpf_mut().expect("ebpf set above");
        let mut rules =
            HashMap::try_from(ebpf.map_mut("RULES").expect("RULES map"))?;
        util::insert_rule(
            &mut rules,
            "1.1.1.2",
            0,
            "0.0.0.0",
            0,
            Protocol::Any,
            Action::Drop,
        )?;
    }

    let app_drain = Arc::clone(&app);

    println!("Polling LOGS ring (Ctrl+C to exit).");

    let _drain_join = tokio::spawn(async move {
        let ctrl_c = tokio::signal::ctrl_c();
        tokio::pin!(ctrl_c);
        loop {
            tokio::select! {
                _ = ctrl_c.as_mut() => break,
                _ = time::sleep(Duration::from_millis(50)) => {
                    let mut g = app_drain.lock().await;
                    let mut ebpf = g.ebpf.take().expect("ebpf");
                    let mut log_ring = match RingBuf::try_from(
                        ebpf.map_mut("LOGS").expect("LOGS ring buffer"),
                    ) {
                        Ok(r) => r,
                        Err(_) => {
                            g.set_ebpf(ebpf);
                            break;
                        }
                    };
                    drain_log_ring_once(&mut log_ring, &mut *g);
                    g.set_ebpf(ebpf);
                }
            }
        }
    });
    let mut tui = Tui::new()?;
    tui.run(app).await?;
    Ok(())
}