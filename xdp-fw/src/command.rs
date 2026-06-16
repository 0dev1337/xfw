use std::net::Ipv4Addr;

use anyhow::{bail, Context as _};
use aya::maps::HashMap;
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
pub enum Command {
    Help { topic: Option<String> },
    Block(RuleTarget),
    Allow(RuleTarget),
}

struct RuleSpec {
    src_ip: String,
    src_port: u16,
    dest_ip: String,
    dest_port: u16,
    protocol: BlockProtocol,
}

const HELP_GENERAL: &[&str] = &[
    "commands:",
    "  help [topic]     show help (topics: block, allow)",
    "  block ...        drop matching traffic (alias: deny)",
    "  allow ...        permit matching traffic",
    "examples:",
    "  block 1.2.3.4",
    "  block from 1.2.3.4",
    "  block port 80",
    "  block port 80/tcp",
    "  block port 443 proto tcp from 10.0.0.5",
    "  block tcp 80",
    "  allow from 192.168.1.10",
];

const HELP_BLOCK: &[&str] = &[
    "block — drop matching traffic (alias: deny)",
    "  block <ip>",
    "  block from <ip>",
    "  block port <port>",
    "  block port <port>/<proto>",
    "  block port <port> proto <tcp|udp|any>",
    "  block port <port> from <ip>",
    "  block port <port> proto <proto> from <ip>",
    "  block <tcp|udp|any> <port>          (legacy)",
    "protocols: tcp, udp, any",
];

const HELP_ALLOW: &[&str] = &[
    "allow — permit matching traffic",
    "  allow <ip>",
    "  allow from <ip>",
    "  allow port <port>",
    "  allow port <port>/<proto>",
    "  allow port <port> proto <tcp|udp|any>",
    "  allow port <port> from <ip>",
    "  allow port <port> proto <proto> from <ip>",
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
                bail!("usage: from <ip>");
            }
            let ip = parse_ip(args[1])?;
            Ok(RuleTarget::FromIp { ip })
        }
        "port" => parse_port_rule(&args[1..]),
        _ => {
            if args.len() == 1 && parse_ip(args[0]).is_ok() {
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
                src_ip = Some(parse_ip(ip)?);
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
    match parse(input) {
        Ok(cmd) => execute(app, cmd),
        Err(err) => app.push_system(Line::from(format!("{err:#}"))),
    }
}

pub fn execute(app: &mut App, cmd: Command) {
    match cmd {
        Command::Help { topic } => show_help(app, topic.as_deref()),
        Command::Block(target) => apply_rule(app, target, Action::Drop, "blocked"),
        Command::Allow(target) => apply_rule(app, target, Action::Allow, "allowed"),
    }
}

fn show_help(app: &mut App, topic: Option<&str>) {
    let lines: &[&str] = match topic {
        None => HELP_GENERAL,
        Some("block") | Some("deny") => HELP_BLOCK,
        Some("allow") => HELP_ALLOW,
        Some(other) => {
            app.push_system(Line::from(format!(
                "unknown help topic: {other} (try: block, allow)"
            )));
            return;
        }
    };

    for line in lines {
        app.push_system(Line::from(*line));
    }
}

fn rule_target_to_spec(target: RuleTarget) -> (RuleSpec, String) {
    match target {
        RuleTarget::FromIp { ip } => (
            RuleSpec {
                src_ip: ip.clone(),
                src_port: 0,
                dest_ip: "0.0.0.0".to_string(),
                dest_port: 0,
                protocol: BlockProtocol::Any,
            },
            format!("from {ip}"),
        ),
        RuleTarget::Port {
            port,
            protocol,
            src_ip,
        } => {
            let src = src_ip.clone().unwrap_or_else(|| "any".to_string());
            let proto = protocol.name();
            let desc = if src_ip.is_some() {
                format!("{proto} port {port} from {src}")
            } else {
                format!("{proto} port {port}")
            };
            (
                RuleSpec {
                    src_ip: src_ip.unwrap_or_else(|| "0.0.0.0".to_string()),
                    src_port: 0,
                    dest_ip: "0.0.0.0".to_string(),
                    dest_port: port,
                    protocol,
                },
                desc,
            )
        }
    }
}

fn apply_rule(app: &mut App, target: RuleTarget, action: Action, verb: &str) {
    let (spec, desc) = rule_target_to_spec(target);

    let mut ebpf = match app.ebpf.take() {
        Some(ebpf) => ebpf,
        None => {
            app.push_system(Line::from("eBPF not loaded"));
            return;
        }
    };

    let result: anyhow::Result<()> = (|| {
        let mut rules = HashMap::try_from(
            ebpf.map_mut("RULES").expect("RULES map"),
        )?;
        util::insert_rule(
            &mut rules,
            &spec.src_ip,
            spec.src_port,
            &spec.dest_ip,
            spec.dest_port,
            spec.protocol.to_protocol(),
            action,
        )?;
        Ok(())
    })();

    app.set_ebpf(ebpf);

    match result {
        Ok(()) => app.push_system(Line::from(format!("{verb} {desc}"))),
        Err(err) => app.push_system(Line::from(format!("{verb} {desc} failed: {err:#}"))),
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
