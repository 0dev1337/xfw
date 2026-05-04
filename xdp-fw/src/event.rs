use crossterm::event::{Event, KeyCode};
use ratatui::text::Line;
use crate::app::App;

pub fn handle_event(app: &mut App, event: Event) {
    if let Event::Key(key) = event {
        match key.code {
            KeyCode::Char(c) => app.input.push(c),
            KeyCode::Backspace => { app.input.pop(); }
            KeyCode::Enter => {
                app.logs.push(Line::from(app.input.clone()));
                app.input.clear();
            }
            KeyCode::Esc => app.should_exit = true,
            _ => {}
        }
    }
}