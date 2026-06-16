use crossterm::event::{Event, KeyCode};

use crate::app::App;
use crate::command;

pub fn handle_event(app: &mut App, event: Event) {
    if let Event::Key(key) = event {
        match key.code {
            KeyCode::Char(c) => app.input.push(c),
            KeyCode::Backspace => {
                app.input.pop();
            }
            KeyCode::Enter => {
                let input = app.input.clone();
                if !input.is_empty() {
                    command::handle_input(app, &input);
                }
                app.input.clear();
            }
            KeyCode::Esc => app.should_exit = true,
            _ => {}
        }
    }
}
