#[repr(C)]
#[derive(Clone, Copy)]
pub struct LogEvent {
    pub src_ip: [u8; 4],
    pub source_port: u16,
    pub dest_port: u16,
    pub protocol: u8,
    pub action: u8,
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for LogEvent {}
