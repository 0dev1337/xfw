use ratatui::text::Line;

pub struct App {
    pub input: String,
    pub allow_logs: Vec<Line<'static>>,
    pub deny_logs: Vec<Line<'static>>,
    pub system_logs: Vec<Line<'static>>,
    pub should_exit: bool,
}

impl App {
    pub fn new() -> Self {
        Self {
            input: String::new(),
            allow_logs: vec![],
            deny_logs: vec![],
            system_logs: vec![],
            should_exit: false,
        }
    }
}