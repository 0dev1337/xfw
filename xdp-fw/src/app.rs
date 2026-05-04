use ratatui::text::Line;

pub struct App {
    pub input: String,
    pub logs: Vec<Line<'static>>,
    pub should_exit: bool,
}

impl App {
    pub fn new() -> Self {
        Self {
            input: String::new(),
            logs: vec![],
            should_exit: false,
        }
    }
}