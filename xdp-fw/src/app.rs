pub struct App {
    pub input: String,
    pub logs: Vec<String>,
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