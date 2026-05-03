use crossterm::event::{Event, KeyCode};

use crate::app::App;

pub fn handle_event(app: &mut App, event: Event) {
    if let Event::Key(key) = event {
        match key.code {
            KeyCode::Char(c) => app.input.push(c),
            KeyCode::Backspace => { app.input.pop(); }
            KeyCode::Enter => {
                app.logs.push(app.input.clone());
                app.input.clear();
            }
            KeyCode::Esc => app.should_exit = true,
            _ => {}
        }
    }
}