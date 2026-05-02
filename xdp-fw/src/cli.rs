use clap::Parser;

#[derive(Debug, Parser)]
pub struct Opt {
    #[arg(short, long, default_value = "enp10s0")]
    pub iface: String,
}
