use aya::Ebpf;
use ratatui::text::Line;

pub struct App {
    pub input: String,

    pub allow_logs: Vec<Line<'static>>,
    pub deny_logs: Vec<Line<'static>>,
    pub system_logs: Vec<Line<'static>>,

    pub should_exit: bool,

    // eBPF is optional so it can be safely initialized after App creation
    pub ebpf: Option<Ebpf>,
}

impl App {
    /// Create an empty UI app (eBPF will be attached later in main)
    pub fn new() -> Self {
        Self {
            input: String::new(),
            allow_logs: vec![],
            deny_logs: vec![],
            system_logs: vec![],
            should_exit: false,
            ebpf: None,
        }
    }

    /// Attach loaded eBPF program after initialization
    pub fn set_ebpf(&mut self, ebpf: Ebpf) {
        self.ebpf = Some(ebpf);
    }

    /// Safe helper to access eBPF mutably
    pub fn ebpf_mut(&mut self) -> Option<&mut Ebpf> {
        self.ebpf.as_mut()
    }

    /// Safe helper to access eBPF immutably
    pub fn ebpf(&self) -> Option<&Ebpf> {
        self.ebpf.as_ref()
    }

    /// Simple log helpers
    pub fn push_allow(&mut self, line: Line<'static>) {
        if self.allow_logs.len() > 500 {
            self.allow_logs.remove(0);
        }
        self.allow_logs.push(line);
    }

    pub fn push_deny(&mut self, line: Line<'static>) {
        if self.deny_logs.len() > 500 {
            self.deny_logs.remove(0);
        }
        self.deny_logs.push(line);
    }

    pub fn push_system(&mut self, line: Line<'static>) {
        if self.system_logs.len() > 500 {
            self.system_logs.remove(0);
        }
        self.system_logs.push(line);
    }
}