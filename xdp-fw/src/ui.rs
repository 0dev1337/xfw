use ratatui::{
    layout::{Constraint, Direction, Layout},
    widgets::*,
    style::{Color, Style},
    Frame,
};

use crate::app::App;

pub fn draw(frame: &mut Frame, app: &App) {
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(12),
            Constraint::Min(6),
            Constraint::Length(4),
        ])
        .split(frame.area());

    let top = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(outer[0]);

    let allow_visible_height = top[0].height.saturating_sub(2);
    let deny_visible_height = top[1].height.saturating_sub(2);
    let system_visible_height = outer[1].height.saturating_sub(2);

    let allow_scroll = (app.allow_logs.len() as u16).saturating_sub(allow_visible_height);
    let deny_scroll = (app.deny_logs.len() as u16).saturating_sub(deny_visible_height);
    let system_scroll = (app.system_logs.len() as u16).saturating_sub(system_visible_height);

    let allow_logs = Paragraph::new(app.allow_logs.clone())
        .block(Block::default().title("Allowed").borders(Borders::ALL))
        .scroll((allow_scroll, 0));

    let deny_logs = Paragraph::new(app.deny_logs.clone())
        .block(Block::default().title("Denied").borders(Borders::ALL))
        .scroll((deny_scroll, 0));

    let system_logs = Paragraph::new(app.system_logs.clone())
        .block(Block::default().title("System Logs").borders(Borders::ALL))
        .scroll((system_scroll, 0));


    let (text, _) = if app.input.is_empty() {
        ("help for command utility", Style::default().fg(Color::DarkGray))
    } else {
        (app.input.as_str(), Style::default())
    };

    let input = Paragraph::new(text)
        .block(Block::default().title("Exec").borders(Borders::ALL));

    frame.render_widget(allow_logs, top[0]);
    frame.render_widget(deny_logs, top[1]);
    frame.render_widget(system_logs, outer[1]);
    frame.render_widget(input, outer[2]);
}
