#[repr(u8)]
#[derive(Clone, Copy)]
pub enum Action {
    Allow = 0,
    Drop = 1,
}

pub const MAX_RULES: usize = 256;

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum Protocol {
    ICMP = 1,
    TCP = 6,
    UDP = 17,
    GRE = 47,
    ESP = 50,
    AH = 51,
    SCTP = 132,
    Any = 255,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FlowKey {
    pub src_ip: u32,
    pub dest_ip: u32,
    pub src_port: u16,
    pub dest_port: u16,
    pub protocol: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Rule {
    pub src_ip: u32,
    pub src_mask: u32,
    pub dest_ip: u32,
    pub dest_mask: u32,
    pub src_port: u16,
    pub dest_port: u16,
    pub protocol: u8,
    pub action: u8,
}

#[inline]
pub const fn ipv4_bytes_to_u32(ip: [u8; 4]) -> u32 {
    u32::from_be_bytes(ip)
}

/// Compute a bitmask from a CIDR prefix length (0..=32).
/// e.g. prefix_to_mask(24) => 0xFFFFFF00
#[inline]
pub const fn prefix_to_mask(prefix: u8) -> u32 {
    if prefix == 0 { 0 } else { !0u32 << (32 - prefix) }
}

pub fn is_empty_rule(rule: &Rule) -> bool {
    rule.src_ip == 0
        && rule.src_mask == 0
        && rule.dest_ip == 0
        && rule.dest_mask == 0
        && rule.src_port == 0
        && rule.dest_port == 0
        && rule.protocol == 0
        && rule.action == 0
}

pub fn rule_matches(rule: &Rule, key: &FlowKey) -> bool {
    if rule.protocol != Protocol::Any as u8 && rule.protocol != key.protocol {
        return false;
    }

    if rule.src_port != 0 && rule.src_port != key.src_port {
        return false;
    }

    if rule.dest_port != 0 && rule.dest_port != key.dest_port {
        return false;
    }

    if rule.src_mask != 0 && (key.src_ip & rule.src_mask) != (rule.src_ip & rule.src_mask) {
        return false;
    }

    if rule.dest_mask != 0 && (key.dest_ip & rule.dest_mask) != (rule.dest_ip & rule.dest_mask) {
        return false;
    }

    true
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowKey {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Rule {}
