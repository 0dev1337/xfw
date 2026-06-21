use std::net::Ipv4Addr;

use anyhow::{bail, Context as _};
use aya::maps::Array;
use aya::Ebpf;
use chrono::Local;
use ratatui::text::Line;

use xdp_fw_common::rules::rules::{Action, MAX_RULES, Protocol, Rule};

const ZERO_RULE: Rule = Rule {
    src_ip: 0, src_mask: 0, dest_ip: 0, dest_mask: 0,
    src_port: 0, dest_port: 0, protocol: 0, action: 0,
};

fn protocol_name(p: u8) -> &'static str {
    match p {
        1 => "icmp",
        6 => "tcp",
        17 => "udp",
        47 => "gre",
        50 => "esp",
        51 => "ah",
        132 => "sctp",
        255 => "any",
        _ => "?",
    }
}

fn action_name(a: u8) -> &'static str {
    match a {
        0 => "allow",
        1 => "drop",
        _ => "?",
    }
}

fn mask_to_prefix(mask: u32) -> u8 {
    mask.leading_ones() as u8
}

fn ip_cidr_str(ip: u32, mask: u32) -> String {
    if mask == 0 {
        return "*".to_string();
    }
    let addr = Ipv4Addr::from(ip.to_be_bytes());
    let prefix = mask_to_prefix(mask);
    if prefix == 32 {
        addr.to_string()
    } else {
        format!("{addr}/{prefix}")
    }
}

fn port_str(port: u16) -> String {
    if port == 0 { "*".to_string() } else { port.to_string() }
}

pub fn format_rule(index: u32, rule: &Rule) -> String {
    format!(
        "#{:<3} src={:<18} sport={:<5} dst={:<18} dport={:<5} proto={:<5} action={}",
        index,
        ip_cidr_str(rule.src_ip, rule.src_mask),
        port_str(rule.src_port),
        ip_cidr_str(rule.dest_ip, rule.dest_mask),
        port_str(rule.dest_port),
        protocol_name(rule.protocol),
        action_name(rule.action),
    )
}

pub fn list_rules(ebpf: &mut Ebpf, filter_ip: Option<u32>) -> anyhow::Result<Vec<(u32, Rule)>> {
    let count = {
        let count_map = ebpf.map_mut("RULE_COUNT").context("RULE_COUNT map")?;
        let c = Array::<_, u32>::try_from(count_map)?;
        c.get(&0, 0)?
    };

    let rules_map = ebpf.map_mut("RULES").context("RULES map")?;
    let rules = Array::<_, Rule>::try_from(rules_map)?;

    let mut result = Vec::new();
    for i in 0..count.min(MAX_RULES as u32) {
        let rule = rules.get(&i, 0)?;
        if let Some(ip) = filter_ip {
            let src_hit = rule.src_mask != 0 && (ip & rule.src_mask) == (rule.src_ip & rule.src_mask);
            let dst_hit = rule.dest_mask != 0 && (ip & rule.dest_mask) == (rule.dest_ip & rule.dest_mask);
            if !src_hit && !dst_hit {
                continue;
            }
        }
        result.push((i, rule));
    }
    Ok(result)
}

/// Parse "1.2.3.4" or "1.2.3.0/24" into (network_addr, mask).
pub fn parse_cidr(s: &str) -> anyhow::Result<(u32, u32)> {
    if let Some((ip_part, prefix_part)) = s.split_once('/') {
        let ip: Ipv4Addr = ip_part.parse().context("invalid ipv4 address")?;
        let prefix: u8 = prefix_part.parse().context("invalid prefix length")?;
        if prefix > 32 {
            bail!("prefix length must be 0-32, got {prefix}");
        }
        let mask = xdp_fw_common::rules::rules::prefix_to_mask(prefix);
        let addr = u32::from_be_bytes(ip.octets()) & mask;
        Ok((addr, mask))
    } else {
        let ip: Ipv4Addr = s.parse().context("invalid ipv4 address")?;
        let addr = u32::from_be_bytes(ip.octets());
        let mask = if addr == 0 { 0 } else { !0u32 };
        Ok((addr, mask))
    }
}

pub fn insert_rule(
    ebpf: &mut Ebpf,
    src_ip: u32,
    src_mask: u32,
    src_port: u16,
    dest_ip: u32,
    dest_mask: u32,
    dest_port: u16,
    protocol: Protocol,
    action: Action,
) -> anyhow::Result<()> {
    let index = {
        let count_map = ebpf.map_mut("RULE_COUNT").context("RULE_COUNT map")?;
        let count = Array::try_from(count_map)?;
        count.get(&0, 0)?
    };

    if index >= MAX_RULES as u32 {
        bail!("rule table full (max {MAX_RULES} rules)");
    }

    let rule = Rule {
        src_ip,
        src_mask,
        dest_ip,
        dest_mask,
        src_port,
        dest_port,
        protocol: protocol as u8,
        action: action as u8,
    };

    {
        let rules_map = ebpf.map_mut("RULES").context("RULES map")?;
        let mut rules = Array::try_from(rules_map)?;
        rules.set(index, rule, 0)?;
    }

    {
        let count_map = ebpf.map_mut("RULE_COUNT").context("RULE_COUNT map")?;
        let mut count = Array::try_from(count_map)?;
        count.set(0, index + 1, 0)?;
    }

    Ok(())
}

pub fn remove_rule(ebpf: &mut Ebpf, index: u32) -> anyhow::Result<()> {
    let count = {
        let count_map = ebpf.map_mut("RULE_COUNT").context("RULE_COUNT map")?;
        let c = Array::<_, u32>::try_from(count_map)?;
        c.get(&0, 0)?
    };

    if index >= count {
        bail!("rule #{index} does not exist (active rules: 0..{})", count.saturating_sub(1));
    }

    let last = count - 1;

    if index != last {
        let last_rule = {
            let rules_map = ebpf.map_mut("RULES").context("RULES map")?;
            let rules = Array::<_, Rule>::try_from(rules_map)?;
            rules.get(&last, 0)?
        };
        let rules_map = ebpf.map_mut("RULES").context("RULES map")?;
        let mut rules = Array::try_from(rules_map)?;
        rules.set(index, last_rule, 0)?;
    }

    {
        let rules_map = ebpf.map_mut("RULES").context("RULES map")?;
        let mut rules = Array::try_from(rules_map)?;
        rules.set(last, ZERO_RULE, 0)?;
    }

    {
        let count_map = ebpf.map_mut("RULE_COUNT").context("RULE_COUNT map")?;
        let mut count = Array::try_from(count_map)?;
        count.set(0, last, 0)?;
    }

    Ok(())
}

pub fn remove_all_rules(ebpf: &mut Ebpf) -> anyhow::Result<u32> {
    let count = {
        let count_map = ebpf.map_mut("RULE_COUNT").context("RULE_COUNT map")?;
        let c = Array::<_, u32>::try_from(count_map)?;
        c.get(&0, 0)?
    };

    for i in 0..count.min(MAX_RULES as u32) {
        let rules_map = ebpf.map_mut("RULES").context("RULES map")?;
        let mut rules = Array::try_from(rules_map)?;
        rules.set(i, ZERO_RULE, 0)?;
    }

    {
        let count_map = ebpf.map_mut("RULE_COUNT").context("RULE_COUNT map")?;
        let mut count_arr = Array::try_from(count_map)?;
        count_arr.set(0, 0u32, 0)?;
    }

    Ok(count)
}

pub fn remove_rules_by_ip(ebpf: &mut Ebpf, ip: u32) -> anyhow::Result<u32> {
    let indices: Vec<u32> = list_rules(ebpf, Some(ip))?
        .into_iter()
        .map(|(i, _)| i)
        .collect();

    let removed = indices.len() as u32;
    for idx in indices.into_iter().rev() {
        remove_rule(ebpf, idx)?;
    }
    Ok(removed)
}

pub fn system_line(msg: impl AsRef<str>) -> Line<'static> {
    Line::from(format!(
        "[{}] {}",
        Local::now().format("%H:%M:%S"),
        msg.as_ref()
    ))
}
