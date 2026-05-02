use anyhow::Context as _;
use aya::Ebpf;
use aya::programs::{Xdp, XdpFlags};


use log::{debug, warn};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
pub fn bump_memlock_rlimit() {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) } != 0 {
        debug!("setrlimit(RLIMIT_MEMLOCK) failed");
    }
}

pub fn load_ebpf() -> anyhow::Result<Ebpf> {
    Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/xdp-fw"
    )))
    .map_err(Into::into)
}

pub fn init_aya_log(ebpf: &mut Ebpf) {
    match aya_log::EbpfLogger::init(ebpf) {
        Err(e) => warn!("eBPF logger init failed: {e}"),
        Ok(logger) => {
            let Ok(logger) = AsyncFd::with_interest(logger, Interest::READABLE) else {
                return;
            };
            tokio::task::spawn(async move {
                let mut logger = logger;
                loop {
                    let mut guard = logger.readable_mut().await.expect("asyncfd");
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
}

pub fn attach_xdp(ebpf: &mut Ebpf, iface: &str) -> anyhow::Result<()> {
    let prog: &mut Xdp = ebpf
        .program_mut("xdp_fw")
        .context("program xdp_fw")?
        .try_into()?;
    prog.load()?;
    prog.attach(iface, XdpFlags::default())
        .context("attach XDP (try XdpFlags::SKB_MODE if default fails)")?;
    Ok(())
}
