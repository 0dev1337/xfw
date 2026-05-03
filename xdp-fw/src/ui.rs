use std::{mem::size_of, net::Ipv4Addr};

use aya::maps::{MapData, RingBuf};
use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::Style,
    widgets::*,
    Frame,
};

use crate::app::App;
use xdp_fw_common::logs::logs::LogEvent;

/// Max lines kept from the BPF ring buffer (oldest dropped first).
const RINGBUF_LOG_CAP: usize = 512;

/// Decode one `LogEvent` from raw ringbuf bytes (written by the eBPF program).
fn parse_log_event(slice: &[u8]) -> Option<LogEvent> {
    let n = size_of::<LogEvent>();
    if slice.len() < n {
        return None;
    }
    Some(unsafe { slice.as_ptr().cast::<LogEvent>().read_unaligned() })
}

fn trim_logs(logs: &mut Vec<String>) {
    if logs.len() > RINGBUF_LOG_CAP {
        let drop = logs.len() - RINGBUF_LOG_CAP;
        logs.drain(..drop);
    }
}

/// Drain all currently available records from the `LOGS` ring buffer into `app.logs`.
pub fn drain_ringbuf_logs(ring: &mut RingBuf<&mut MapData>, app: &mut App) {
    while let Some(item) = ring.next() {
        if let Some(ev) = parse_log_event(&item[..]) {
            let ip = Ipv4Addr::from(ev.src_ip);
            let line = format!(
                "{ip} sport={} dport={} proto={} action={}",
                ev.source_port, ev.dest_port, ev.protocol, ev.action,
            );
            app.logs.push(line);
            trim_logs(&mut app.logs);
        }
    }
}

pub fn draw(frame: &mut Frame, app: &mut App, ring: &mut RingBuf<&mut MapData>) {
    drain_ringbuf_logs(ring, app);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(3)])
        .split(frame.area());

    let log_items: Vec<ListItem<'_>> = app
        .logs
        .iter()
        .map(|line| ListItem::new(line.as_str()))
        .collect();

    let mut log_state = ListState::default();
    if let Some(last) = log_items.len().checked_sub(1) {
        log_state.select(Some(last));
    }

    let log_list = List::new(log_items)
        .block(Block::default().title("Logs (ringbuf)").borders(Borders::ALL))
        .highlight_spacing(HighlightSpacing::Never)
        .highlight_style(Style::new());

    let input = Paragraph::new(app.input.as_str())
        .block(Block::default().title("Input").borders(Borders::ALL));

    frame.render_stateful_widget(log_list, chunks[0], &mut log_state);
    frame.render_widget(input, chunks[1]);
}
