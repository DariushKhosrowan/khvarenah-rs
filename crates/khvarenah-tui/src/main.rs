//! Khvarenah TUI (ratatui).
//!
//! A terminal dashboard that shares the core library. It shows a live,
//! friendly overview of profiles, tokens, config history, clean IPs, recently
//! generated share links, and the current application state. Navigation is
//! minimal but functional:
//!
//! * `q` / `Esc` — quit
//! * `Tab` — cycle between the Overview / Profiles / Share-link panels
//!
//! For full operations (deploy, scan, DNS, routes, backup, audit) prefer the
//! CLI (`khvarenah`), which drives the same core library.

use khvarenah_core::store::profiles::{list_profiles, load_profile, migrate_legacy};

use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

const GOLD: Color = Color::Rgb(212, 175, 55);
const GOLD_DIM: Color = Color::Rgb(150, 120, 40);
const TEXT: Color = Color::Rgb(235, 228, 200);

fn main() -> std::io::Result<()> {
    let _ = migrate_legacy();

    let mut terminal = ratatui::init();
    let res = run_app(&mut terminal);
    ratatui::restore();
    res
}

#[derive(Clone, Copy, PartialEq)]
enum Tab {
    Overview,
    Profiles,
    Links,
}

fn run_app(terminal: &mut ratatui::DefaultTerminal) -> std::io::Result<()> {
    let mut tab = Tab::Overview;

    loop {
        terminal.draw(|frame| {
            let area = frame.area();
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3), // title bar
                    Constraint::Length(1), // tab strip
                    Constraint::Length(1), // separator
                    Constraint::Min(0),    // body
                ])
                .split(area);

            // Title bar
            let title = Paragraph::new(Line::from(vec![
                Span::styled(
                    " Khvarenah ",
                    Style::default()
                        .fg(Color::Black)
                        .bg(GOLD)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!(
                        "  v{} — Cloudflare-Workers VLESS VPN console",
                        khvarenah_core::VERSION
                    ),
                    Style::default().fg(GOLD_DIM),
                ),
            ]));
            frame.render_widget(title, chunks[0]);

            // Tab strip
            let tabs = Line::from(vec![
                tab_span(" Overview ", tab == Tab::Overview),
                Span::raw("   "),
                tab_span(" Profiles ", tab == Tab::Profiles),
                Span::raw("   "),
                tab_span(" Share Links ", tab == Tab::Links),
            ]);
            frame.render_widget(Paragraph::new(tabs), chunks[1]);
            frame.render_widget(Block::default().borders(Borders::TOP), chunks[2]);

            match tab {
                Tab::Overview => render_overview(frame, chunks[3]),
                Tab::Profiles => render_profiles(frame, chunks[3]),
                Tab::Links => render_links(frame, chunks[3]),
            }
        })?;

        if crossterm::event::poll(std::time::Duration::from_millis(100))? {
            if let crossterm::event::Event::Key(key) = crossterm::event::read()? {
                match key.code {
                    crossterm::event::KeyCode::Char('q') | crossterm::event::KeyCode::Esc => break,
                    crossterm::event::KeyCode::Tab => {
                        tab = match tab {
                            Tab::Overview => Tab::Profiles,
                            Tab::Profiles => Tab::Links,
                            Tab::Links => Tab::Overview,
                        };
                    }
                    crossterm::event::KeyCode::Char('1') => tab = Tab::Overview,
                    crossterm::event::KeyCode::Char('2') => tab = Tab::Profiles,
                    crossterm::event::KeyCode::Char('3') => tab = Tab::Links,
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

fn tab_span(label: &str, active: bool) -> Span<'static> {
    if active {
        Span::styled(
            label.to_string(),
            Style::default()
                .fg(Color::Black)
                .bg(GOLD)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(label.to_string(), Style::default().fg(GOLD_DIM))
    }
}

fn boxed(title: &str) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(GOLD_DIM))
        .title(Span::styled(
            title.to_string(),
            Style::default().fg(GOLD).add_modifier(Modifier::BOLD),
        ))
}

fn render_overview(frame: &mut ratatui::Frame, area: ratatui::layout::Rect) {
    let profiles = list_profiles();
    let mut lines = vec![Line::from(Span::styled(
        "Welcome to Khvarenah — your Cloudflare Workers VLESS control plane.",
        Style::default().fg(TEXT),
    ))];

    let mut total_clean = 0usize;
    let mut total_configs = 0usize;
    for m in &profiles {
        let p = load_profile(&m.id);
        total_clean += p.clean_ips.len();
        total_configs += p.history.len();
    }

    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled(
        format!("Profiles: {}", profiles.len()),
        Style::default().fg(GOLD),
    )));
    lines.push(Line::from(Span::styled(
        format!("Saved configs: {total_configs}"),
        Style::default().fg(TEXT),
    )));
    lines.push(Line::from(Span::styled(
        format!("Clean IPs: {total_clean}"),
        Style::default().fg(TEXT),
    )));
    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled(
        "Keyboard: 1/2/3 or Tab = switch panel · q/Esc = quit",
        Style::default().fg(GOLD_DIM),
    )));
    lines.push(Line::from(Span::styled(
        "Full tooling (deploy, scan, DNS, routes, backup, audit) lives in the CLI:",
        Style::default().fg(GOLD_DIM),
    )));
    lines.push(Line::from(Span::styled(
        "  khvarenah --help",
        Style::default().fg(GOLD).add_modifier(Modifier::BOLD),
    )));

    let widget = Paragraph::new(lines).block(boxed(" Overview "));
    frame.render_widget(widget, area);
}

fn render_profiles(frame: &mut ratatui::Frame, area: ratatui::layout::Rect) {
    let profiles = list_profiles();
    let mut lines: Vec<Line> = Vec::new();

    if profiles.is_empty() {
        lines.push(Line::from(Span::styled(
            "No profiles yet — create one with `khvarenah profile-create <name>`.",
            Style::default().fg(TEXT),
        )));
    } else {
        for m in &profiles {
            let p = load_profile(&m.id);
            lines.push(Line::from(Span::styled(
                format!("• {} ({})", p.meta.name, p.meta.id),
                Style::default().fg(GOLD).add_modifier(Modifier::BOLD),
            )));
            lines.push(Line::from(Span::styled(
                format!(
                    "    tokens: {}   accounts: {}   configs: {}   clean IPs: {}",
                    p.tokens.len(),
                    p.accounts.len(),
                    p.history.len(),
                    p.clean_ips.len()
                ),
                Style::default().fg(TEXT),
            )));
        }
    }

    let widget = Paragraph::new(lines).block(boxed(" Profiles "));
    frame.render_widget(widget, area);
}

fn render_links(frame: &mut ratatui::Frame, area: ratatui::layout::Rect) {
    let profiles = list_profiles();
    let mut lines: Vec<Line> = Vec::new();

    for m in profiles.iter().take(1) {
        let p = load_profile(&m.id);
        let recent: Vec<_> = p.history.iter().take(6).collect();
        if recent.is_empty() {
            lines.push(Line::from(Span::styled(
                "No share links yet — run `khvarenah deploy` then `khvarenah scan`.",
                Style::default().fg(TEXT),
            )));
        } else {
            for r in recent {
                let tag = if r.clean_ip {
                    "clean-IP"
                } else {
                    "workers.dev"
                };
                lines.push(Line::from(vec![
                    Span::styled(
                        format!("[{}] ", tag),
                        Style::default().fg(if r.clean_ip { GOLD } else { GOLD_DIM }),
                    ),
                    Span::styled(
                        format!(
                            "{} — ",
                            if r.name.is_empty() {
                                &r.address
                            } else {
                                &r.name
                            }
                        ),
                        Style::default().fg(TEXT),
                    ),
                    Span::styled(r.ts.clone(), Style::default().fg(GOLD_DIM)),
                ]));
                if r.link.len() <= 90 {
                    lines.push(Line::from(Span::styled(
                        r.link.clone(),
                        Style::default().fg(GOLD_DIM),
                    )));
                } else {
                    lines.push(Line::from(Span::styled(
                        format!("{}…", &r.link[..90]),
                        Style::default().fg(GOLD_DIM),
                    )));
                }
            }
        }
    }

    let widget = Paragraph::new(lines).block(boxed(" Recent Share Links "));
    frame.render_widget(widget, area);
}
