use std::net::Ipv4Addr;
use aya::maps::HashMap;
use xdp_fw_common::rules::rules::{Action, FlowKey, Protocol, Rule};

pub fn insert_rule(
    rules: &mut HashMap<&mut aya::maps::MapData, FlowKey, Rule>,
    src_ip: &str,
    src_port: u16,
    dest_ip: &str,
    dest_port: u16,
    protocol: Protocol,
    action: Action,
) -> anyhow::Result<()> {
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

