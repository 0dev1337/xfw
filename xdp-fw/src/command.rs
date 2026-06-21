use std::net::Ipv4Addr;

use anyhow::{bail, Context as _};
use ratatui::text::Line;
use xdp_fw_common::rules::rules::{Action, Protocol};

use crate::app::App;
use crate::util;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockProtocol {
    Tcp,
    Udp,
    Any,
}

impl BlockProtocol {
    fn to_protocol(self) -> Protocol {
        match self {
            BlockProtocol::Tcp => Protocol::TCP,
            BlockProtocol::Udp => Protocol::UDP,
            BlockProtocol::Any => Protocol::Any,
        }
    }

    fn name(self) -> &'static str {
        match self {
            BlockProtocol::Tcp => "tcp",
            BlockProtocol::Udp => "udp",
            BlockProtocol::Any => "any",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleTarget {
    FromIp { ip: String },
    Port {
        port: u16,
        protocol: BlockProtocol,
        src_ip: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoveTarget {
    All,
    ById(u32),
    ByIp(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Help { topic: Option<String> },
    Block(RuleTarget),
    Allow(RuleTarget),
    Rules { ip: Option<String> },
    Remove(RemoveTarget),
    Clear,
}

struct RuleSpec {
    src_ip: u32,
    src_mask: u32,
    src_port: u16,
    dest_ip: u32,
    dest_mask: u32,
    dest_port: u16,
    protocol: BlockProtocol,
}

pub const HELP_GENERAL: &[&str] = &[
    "commands:",
    "  help [topic]     show help (topics: block, allow)",
    "  block ...        drop matching traffic (alias: deny)",
    "  allow ...        permit matching traffic",
    "  rules [ip]       list active rules (optionally filter by ip)",
    "  remove ...       remove rules (all, by #id, or by ip)",
    "  clear            clear system logs",
    "  esc              exit the program",
    "examples:",
    "  block 1.2.3.4",
    "  block from 1.2.3.4",
    "  block port 80",
    "  block port 80/tcp",
    "  block port 443 proto tcp from 10.0.0.5",
    "  block tcp 80",
    "  allow from 192.168.1.10",
    "  rules",
    "  rules 1.2.3.4",
    "  remove all",
    "  remove 0",
    "  remove 1.2.3.4",
];

const HELP_BLOCK: &[&str] = &[
    "block — drop matching traffic (alias: deny)",
    "  block <ip|cidr>",
    "  block from <ip|cidr>",
    "  block port <port>",
    "  block port <port>/<proto>",
    "  block port <port> proto <tcp|udp|any>",
    "  block port <port> from <ip|cidr>",
    "  block port <port> proto <proto> from <ip|cidr>",
    "  block <tcp|udp|any> <port>          (legacy)",
    "protocols: tcp, udp, any",
    "cidr examples: 10.0.0.0/8, 192.168.1.0/24",
];

pub const HELP_ALLOW: &[&str] = &[
    "allow — permit matching traffic",
    "  allow <ip|cidr>",
    "  allow from <ip|cidr>",
    "  allow port <port>",
    "  allow port <port>/<proto>",
    "  allow port <port> proto <tcp|udp|any>",
    "  allow port <port> from <ip|cidr>",
    "  allow port <port> proto <proto> from <ip|cidr>",
    "  allow <tcp|udp|any> <port>          (legacy)",
];

pub fn parse(input: &str) -> anyhow::Result<Command> {
    let input = input.trim();
    if input.is_empty() {
        bail!("empty command (try 'help')");
    }

    let parts: Vec<&str> = input.split_whitespace().collect();
    match parts[0].to_ascii_lowercase().as_str() {
        "help" | "?" => parse_help(&parts[1..]),
        "block" | "deny" => parse_rule_command(&parts[1..], true),
        "allow" => parse_rule_command(&parts[1..], false),
        "rules" | "list" => parse_rules_command(&parts[1..]),
        "remove" | "rm" | "del" | "delete" => parse_remove_command(&parts[1..]),
        _ => bail!("unknown command: {} (try 'help')", parts[0]),
    }
}

fn parse_help(args: &[&str]) -> anyhow::Result<Command> {
    if args.is_empty() {
        return Ok(Command::Help { topic: None });
    }
    if args.len() == 1 {
        return Ok(Command::Help {
            topic: Some(args[0].to_ascii_lowercase()),
        });
    }
    bail!("usage: help [block|allow]");
}

fn parse_rules_command(args: &[&str]) -> anyhow::Result<Command> {
    match args.len() {
        0 => Ok(Command::Rules { ip: None }),
        1 => {
            let ip = parse_ip(args[0])?;
            Ok(Command::Rules { ip: Some(ip) })
        }
        _ => bail!("usage: rules [ip]"),
    }
}

fn parse_remove_command(args: &[&str]) -> anyhow::Result<Command> {
    if args.len() != 1 {
        bail!("usage: remove <all | #id | ip>");
    }
    let arg = args[0].to_ascii_lowercase();
    if arg == "all" {
        return Ok(Command::Remove(RemoveTarget::All));
    }
    if let Ok(id) = arg.parse::<u32>() {
        return Ok(Command::Remove(RemoveTarget::ById(id)));
    }
    let ip = parse_ip(args[0])?;
    Ok(Command::Remove(RemoveTarget::ByIp(ip)))
}

fn parse_rule_command(args: &[&str], is_block: bool) -> anyhow::Result<Command> {
    let target = parse_rule_target(args)?;
    Ok(if is_block {
        Command::Block(target)
    } else {
        Command::Allow(target)
    })
}

fn parse_rule_target(args: &[&str]) -> anyhow::Result<RuleTarget> {
    if args.is_empty() {
        bail!("usage: ... (try 'help block')");
    }

    match args[0].to_ascii_lowercase().as_str() {
        "from" => {
            if args.len() != 2 {
                bail!("usage: from <ip|cidr>");
            }
            let ip = parse_ip_or_cidr(args[1])?;
            Ok(RuleTarget::FromIp { ip })
        }
        "port" => parse_port_rule(&args[1..]),
        _ => {
            if args.len() == 1 && parse_ip_or_cidr(args[0]).is_ok() {
                return Ok(RuleTarget::FromIp {
                    ip: args[0].to_string(),
                });
            }
            if args.len() == 2 {
                let protocol = parse_protocol(args[0])?;
                let port = parse_port(args[1])?;
                return Ok(RuleTarget::Port {
                    port,
                    protocol,
                    src_ip: None,
                });
            }
            bail!("usage: ... (try 'help block')");
        }
    }
}

fn parse_port_rule(args: &[&str]) -> anyhow::Result<RuleTarget> {
    if args.is_empty() {
        bail!("usage: port <port> [proto <tcp|udp|any>] [from <ip>]");
    }

    let (port, protocol_from_suffix) = parse_port_token(args[0])?;
    let mut protocol = protocol_from_suffix.unwrap_or(BlockProtocol::Any);
    let mut src_ip = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].to_ascii_lowercase().as_str() {
            "proto" => {
                i += 1;
                let proto = args
                    .get(i)
                    .context("missing protocol after 'proto'")?;
                protocol = parse_protocol(proto)?;
                i += 1;
            }
            "from" => {
                i += 1;
                let ip = args.get(i).context("missing ip after 'from'")?;
                src_ip = Some(parse_ip_or_cidr(ip)?);
                i += 1;
            }
            other => bail!("unexpected token: {other}"),
        }
    }

    Ok(RuleTarget::Port {
        port,
        protocol,
        src_ip,
    })
}

fn parse_port_token(s: &str) -> anyhow::Result<(u16, Option<BlockProtocol>)> {
    if let Some((port, proto)) = s.split_once('/') {
        let port = parse_port(port)?;
        let protocol = parse_protocol(proto)?;
        return Ok((port, Some(protocol)));
    }
    Ok((parse_port(s)?, None))
}

fn parse_port(s: &str) -> anyhow::Result<u16> {
    let port: u16 = s.parse().context("invalid port")?;
    if port == 0 {
        bail!("port must be 1-65535");
    }
    Ok(port)
}

fn parse_ip_or_cidr(s: &str) -> anyhow::Result<String> {
    if s.contains('/') {
        util::parse_cidr(s)?;
        Ok(s.to_string())
    } else {
        let ip: Ipv4Addr = s.parse().context("invalid ipv4 address")?;
        Ok(ip.to_string())
    }
}

fn parse_ip(s: &str) -> anyhow::Result<String> {
    let ip: Ipv4Addr = s.parse().context("invalid ipv4 address")?;
    Ok(ip.to_string())
}

fn parse_protocol(s: &str) -> anyhow::Result<BlockProtocol> {
    match s.to_ascii_lowercase().as_str() {
        "tcp" => Ok(BlockProtocol::Tcp),
        "udp" => Ok(BlockProtocol::Udp),
        "any" => Ok(BlockProtocol::Any),
        _ => bail!("invalid protocol: {s} (expected tcp, udp, or any)"),
    }
}

pub fn handle_input(app: &mut App, input: &str) {
    if input == "clear" {
        app.system_logs.clear();
        app.push_system(util::system_line("system logs cleared"));
        return;
    }

    match parse(input) {
        Ok(cmd) => execute(app, cmd),
        Err(err) => app.push_system(util::system_line(format!("{err:#}"))),
    }
}

pub fn execute(app: &mut App, cmd: Command) {
    match cmd {
        Command::Help { topic } => show_help(app, topic.as_deref()),
        Command::Block(target) => apply_rule(app, target, Action::Drop, "blocked"),
        Command::Allow(target) => apply_rule(app, target, Action::Allow, "allowed"),
        Command::Rules { ip } => show_rules(app, ip),
        Command::Remove(target) => do_remove(app, target),
        Command::Clear => {
            app.system_logs.clear();
            app.push_system(util::system_line("system logs cleared"));
        }
    }
}

fn show_help(app: &mut App, topic: Option<&str>) {
    let lines: &[&str] = match topic {
        None => HELP_GENERAL,
        Some("block") | Some("deny") => HELP_BLOCK,
        Some("allow") => HELP_ALLOW,
        Some(other) => {
            app.push_system(util::system_line(format!(
                "unknown help topic: {other} (try: block, allow)"
            )));
            return;
        }
    };

    for line in lines {
        app.push_system(Line::from(*line)); // no timestamp for help
    }
}
fn show_rules(app: &mut App, filter_ip: Option<String>) {
    let mut ebpf = match app.ebpf.take() {
        Some(ebpf) => ebpf,
        None => {
            app.push_system(util::system_line("eBPF not loaded"));
            return;
        }
    };

    let filter_u32 = filter_ip.as_deref().map(|s| {
        s.parse::<Ipv4Addr>()
            .map(|ip| u32::from_be_bytes(ip.octets()))
    });

    let result = match filter_u32 {
        Some(Err(_)) => {
            app.set_ebpf(ebpf);
            app.push_system(util::system_line("invalid filter ip"));
            return;
        }
        Some(Ok(ip)) => util::list_rules(&mut ebpf, Some(ip)),
        None => util::list_rules(&mut ebpf, None),
    };

    app.set_ebpf(ebpf);

    match result {
        Ok(rules) => {
            if rules.is_empty() {
                let msg = match filter_ip {
                    Some(ip) => format!("no rules matching {ip}"),
                    None => "no active rules".to_string(),
                };
                app.push_system(util::system_line(msg));
            } else {
                let header = match &filter_ip {
                    Some(ip) => format!("{} rule(s) matching {ip}:", rules.len()),
                    None => format!("{} active rule(s):", rules.len()),
                };
                app.push_system(util::system_line(header));
                for (idx, rule) in &rules {
                    app.push_system(Line::from(util::format_rule(*idx, rule)));
                }
            }
        }
        Err(err) => {
            app.push_system(util::system_line(format!("failed to read rules: {err:#}")));
        }
    }
}

fn do_remove(app: &mut App, target: RemoveTarget) {
    let mut ebpf = match app.ebpf.take() {
        Some(ebpf) => ebpf,
        None => {
            app.push_system(util::system_line("eBPF not loaded"));
            return;
        }
    };

    let result: anyhow::Result<String> = (|| match &target {
        RemoveTarget::All => {
            let n = util::remove_all_rules(&mut ebpf)?;
            Ok(format!("removed all {n} rule(s)"))
        }
        RemoveTarget::ById(id) => {
            util::remove_rule(&mut ebpf, *id)?;
            Ok(format!("removed rule #{id}"))
        }
        RemoveTarget::ByIp(ip) => {
            let ip_u32 = ip.parse::<Ipv4Addr>()
                .map(|a| u32::from_be_bytes(a.octets()))
                .context("invalid ip")?;
            let n = util::remove_rules_by_ip(&mut ebpf, ip_u32)?;
            if n == 0 {
                Ok(format!("no rules matching {ip}"))
            } else {
                Ok(format!("removed {n} rule(s) matching {ip}"))
            }
        }
    })();

    app.set_ebpf(ebpf);

    match result {
        Ok(msg) => app.push_system(util::system_line(msg)),
        Err(err) => app.push_system(util::system_line(format!("remove failed: {err:#}"))),
    }
}

fn rule_target_to_spec(target: RuleTarget) -> anyhow::Result<(RuleSpec, String)> {
    match target {
        RuleTarget::FromIp { ip } => {
            let (addr, mask) = util::parse_cidr(&ip)?;
            Ok((
                RuleSpec {
                    src_ip: addr,
                    src_mask: mask,
                    src_port: 0,
                    dest_ip: 0,
                    dest_mask: 0,
                    dest_port: 0,
                    protocol: BlockProtocol::Any,
                },
                format!("from {ip}"),
            ))
        }
        RuleTarget::Port {
            port,
            protocol,
            src_ip,
        } => {
            let (src_addr, src_mask) = match &src_ip {
                Some(s) => util::parse_cidr(s)?,
                None => (0, 0),
            };
            let src = src_ip.as_deref().unwrap_or("any");
            let proto = protocol.name();
            let desc = if src_ip.is_some() {
                format!("{proto} port {port} from {src}")
            } else {
                format!("{proto} port {port}")
            };
            Ok((
                RuleSpec {
                    src_ip: src_addr,
                    src_mask,
                    src_port: 0,
                    dest_ip: 0,
                    dest_mask: 0,
                    dest_port: port,
                    protocol,
                },
                desc,
            ))
        }
    }
}

fn apply_rule(app: &mut App, target: RuleTarget, action: Action, verb: &str) {
    let (spec, desc) = match rule_target_to_spec(target) {
        Ok(v) => v,
        Err(err) => {
            app.push_system(util::system_line(format!("{verb} failed: {err:#}")));
            return;
        }
    };

    let mut ebpf = match app.ebpf.take() {
        Some(ebpf) => ebpf,
        None => {
            app.push_system(util::system_line("eBPF not loaded"));
            return;
        }
    };

    let result: anyhow::Result<()> = (|| {
        util::insert_rule(
            &mut ebpf,
            spec.src_ip,
            spec.src_mask,
            spec.src_port,
            spec.dest_ip,
            spec.dest_mask,
            spec.dest_port,
            spec.protocol.to_protocol(),
            action,
        )?;

        Ok(())
    })();

    app.set_ebpf(ebpf);

    match result {
        Ok(()) => {
            app.push_system(util::system_line(format!("{verb} {desc}")));
        }
        Err(err) => {
            app.push_system(util::system_line(format!(
                "{verb} {desc} failed: {err:#}"
            )));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_help() {
        assert_eq!(parse("help").unwrap(), Command::Help { topic: None });
        assert_eq!(
            parse("help block").unwrap(),
            Command::Help {
                topic: Some("block".to_string())
            }
        );
    }

    #[test]
    fn parse_block_ip() {
        assert_eq!(
            parse("block 1.2.3.4").unwrap(),
            Command::Block(RuleTarget::FromIp {
                ip: "1.2.3.4".to_string()
            })
        );
        assert_eq!(
            parse("block from 10.0.0.1").unwrap(),
            Command::Block(RuleTarget::FromIp {
                ip: "10.0.0.1".to_string()
            })
        );
    }

    #[test]
    fn parse_block_port() {
        assert_eq!(
            parse("block port 80").unwrap(),
            Command::Block(RuleTarget::Port {
                port: 80,
                protocol: BlockProtocol::Any,
                src_ip: None,
            })
        );
        assert_eq!(
            parse("deny port 443/tcp").unwrap(),
            Command::Block(RuleTarget::Port {
                port: 443,
                protocol: BlockProtocol::Tcp,
                src_ip: None,
            })
        );
    }

    #[test]
    fn parse_block_port_from_src() {
        assert_eq!(
            parse("block port 22 proto tcp from 192.168.1.5").unwrap(),
            Command::Block(RuleTarget::Port {
                port: 22,
                protocol: BlockProtocol::Tcp,
                src_ip: Some("192.168.1.5".to_string()),
            })
        );
        assert_eq!(
            parse("block port 8080 from 1.1.1.1").unwrap(),
            Command::Block(RuleTarget::Port {
                port: 8080,
                protocol: BlockProtocol::Any,
                src_ip: Some("1.1.1.1".to_string()),
            })
        );
    }

    #[test]
    fn parse_legacy_block_proto_port() {
        assert_eq!(
            parse("block tcp 80").unwrap(),
            Command::Block(RuleTarget::Port {
                port: 80,
                protocol: BlockProtocol::Tcp,
                src_ip: None,
            })
        );
        assert_eq!(
            parse("BLOCK UDP 53").unwrap(),
            Command::Block(RuleTarget::Port {
                port: 53,
                protocol: BlockProtocol::Udp,
                src_ip: None,
            })
        );
    }

    #[test]
    fn parse_allow() {
        assert_eq!(
            parse("allow from 192.168.0.2").unwrap(),
            Command::Allow(RuleTarget::FromIp {
                ip: "192.168.0.2".to_string()
            })
        );
    }

    #[test]
    fn parse_unknown_command() {
        assert!(parse("flush").is_err());
    }

    #[test]
    fn parse_invalid_port() {
        assert!(parse("block port abc").is_err());
        assert!(parse("block port 70000").is_err());
        assert!(parse("block port 0").is_err());
    }

    #[test]
    fn parse_invalid_ip() {
        assert!(parse("block from not-an-ip").is_err());
        assert!(parse("block 999.999.999.999").is_err());
    }
}
