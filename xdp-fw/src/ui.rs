use ratatui::{
    layout::{Constraint, Direction, Layout},
    widgets::*,
    Frame,
};

use crate::app::App;

pub fn draw(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(1),
            Constraint::Length(3),
        ])
        .split(frame.area());


    let visible_height = chunks[0].height.saturating_sub(2);
    let scroll = (app.logs.len() as u16).saturating_sub(visible_height);
    let logs = Paragraph::new(app.logs.clone())
        .block(Block::default().title("Logs").borders(Borders::ALL)).scroll((scroll, 0));

    let input = Paragraph::new(app.input.as_str())
        .block(Block::default().title("Input").borders(Borders::ALL));
 
    frame.render_widget(logs, chunks[0]);
    frame.render_widget(input, chunks[1]);
}
