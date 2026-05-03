use crossterm::{
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::Terminal;
use std::{io, sync::Arc};

use tokio::sync::Mutex;

use crate::{app::App, event, ui};

pub struct Tui {
    terminal: Terminal<ratatui::backend::CrosstermBackend<io::Stdout>>,
}

impl Tui {
    pub fn new() -> io::Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let backend = ratatui::backend::CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;
        terminal.clear()?;
        Ok(Self { terminal })
    }

    pub async fn run(&mut self, app: Arc<Mutex<App>>) -> io::Result<()> {
        loop {
            let should_exit = {
                let mut app = app.lock().await;

                self.terminal.draw(|f| ui::draw(f, &mut *app))?;

                if crossterm::event::poll(std::time::Duration::from_millis(50))? {
                    let event = crossterm::event::read()?;
                    event::handle_event(&mut *app, event);
                }

                app.should_exit
            };

            if should_exit {
                break;
            }
        }

        execute!(self.terminal.backend_mut(), LeaveAlternateScreen)?;
        disable_raw_mode()?;
        Ok(())
    }
}
