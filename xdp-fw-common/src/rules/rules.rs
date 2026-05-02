#[repr(u8)]
#[derive(Clone, Copy)]
pub enum Action {
    Allow = 0,
    Drop = 1,
}

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum Protocol {
    ICMP = 0,
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
    pub src_ip: [u8; 4],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Rule {
    pub src_ip: [u8; 4],
    pub src_port: u16,
    pub dest_ip: [u8; 4],
    pub dest_port: u16,
    pub protocol: u8,
    pub action: u8,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowKey {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Rule {}