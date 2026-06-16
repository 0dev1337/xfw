use ratatui::{
    layout::{Constraint, Direction, Layout},
    widgets::*,
    Frame,
};

use crate::app::App;

pub fn draw(frame: &mut Frame, app: &App) {
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(12),      // top (A + B)
            Constraint::Length(35),      // system logs
            Constraint::Length(4),   // input
        ])
        .split(frame.area());

    let top = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(50),
            Constraint::Percentage(50),
        ]).split(outer[0]);

    let allow_logs_visible_height = top[0].height.saturating_sub(2);
    let system_logs_visible_height = outer[1].height.saturating_sub(2);
    let allow_scroll = (app.allow_logs.len() as u16).saturating_sub(allow_logs_visible_height);
    let system_scroll = (app.system_logs.len() as u16).saturating_sub(system_logs_visible_height);
    let allow_logs = Paragraph::new(app.allow_logs.clone())
        .block(Block::default().title("Allowed").borders(Borders::ALL))
        .scroll((allow_scroll, 0));

    let deny_logs = Paragraph::new("")
        .block(Block::default().title("Denied").borders(Borders::ALL));

    let system_logs = Paragraph::new(app.system_logs.clone())
        .block(Block::default().title("System Logs").borders(Borders::ALL)).scroll((system_scroll, 0));

    let input = Paragraph::new(app.input.as_str())
        .block(Block::default().title("Exec").borders(Borders::ALL));

    frame.render_widget(allow_logs, top[0]);
    frame.render_widget(deny_logs, top[1]);
    frame.render_widget(system_logs, outer[1]);
    frame.render_widget(input, outer[2]);
}