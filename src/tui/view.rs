use std::borrow::Cow;

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::cli::Mode;

use super::app::{App, Focus, Status};
use super::ferris;
use super::pet::Stat;
use super::theme::{self, BLUSH_PINK, MINT_GREEN, MUTED_GRAY, RUST_ORANGE, SOFT_ROSE, WARM_AMBER};

const MAX_WIDTH: u16 = 78;
const SPINNER_FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const LOADING_BAR_WIDTH: usize = 12;
const STAT_BAR_SEGMENTS: usize = 10;

pub fn render(frame: &mut Frame, app: &App) {
    let full = frame.area();
    let card_area = Rect {
        x: full.x,
        y: full.y,
        width: full.width.min(MAX_WIDTH),
        height: full.height,
    };

    let border_color = if app.is_working() {
        WARM_AMBER
    } else {
        RUST_ORANGE
    };

    let outer = Block::default()
        .title(Line::from(vec![
            Span::styled(
                " rust-encrypt ",
                Style::default()
                    .fg(RUST_ORANGE)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("aes-256-gcm · argon2id ", Style::default().fg(MUTED_GRAY)),
        ]))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color));

    let inner = outer.inner(card_area);
    frame.render_widget(outer, card_area);

    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(ferris::ART_HEIGHT), // ferris + speech + stats
            Constraint::Length(1),                  // divider
            Constraint::Length(4),                  // mode, input, output, key
            Constraint::Length(1),                  // status / loading bar
            Constraint::Length(1),                  // key hints
        ])
        .split(inner);

    render_pet_banner(frame, sections[0], app);
    render_divider(frame, sections[1]);
    render_form_rows(frame, sections[2], app);
    render_status_line(frame, sections[3], app);
    render_hints(frame, sections[4], app);
}

fn render_pet_banner(frame: &mut Frame, area: Rect, app: &App) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(ferris::ART_WIDTH), Constraint::Min(10)])
        .split(area);

    let pet = &app.pet;
    frame.render_widget(
        Paragraph::new(ferris::frame(pet.mood(), pet.tick())),
        cols[0],
    );

    let mood_color = theme::mood_color(pet.mood());
    let (speech, revealed) = pet.speech();

    let mut info = Vec::with_capacity(6);
    info.push(Line::from(vec![
        Span::styled(
            "Ferris",
            Style::default()
                .fg(RUST_ORANGE)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" the guardian crab · ", Style::default().fg(MUTED_GRAY)),
        Span::styled(
            pet.mood().label(),
            Style::default()
                .fg(mood_color)
                .add_modifier(Modifier::ITALIC),
        ),
    ]));
    info.extend(speech_bubble(
        speech,
        revealed,
        usize::from(cols[1].width),
        mood_color,
    ));

    let mut stats = stat_bar("♥", pet.happiness(), BLUSH_PINK);
    stats.push(Span::raw("  "));
    stats.extend(stat_bar("ϟ", pet.energy(), WARM_AMBER));
    info.push(Line::from(stats));

    let age = pet.age(app.now).as_secs();
    info.push(Line::from(vec![
        Span::styled(
            format!("sealed {}", pet.sealed()),
            Style::default().fg(RUST_ORANGE),
        ),
        Span::styled(" · ", Style::default().fg(MUTED_GRAY)),
        Span::styled(
            format!("opened {}", pet.opened()),
            Style::default().fg(MINT_GREEN),
        ),
        Span::styled(
            format!(" · age {}m{:02}s", age / 60, age % 60),
            Style::default().fg(MUTED_GRAY),
        ),
    ]));

    frame.render_widget(Paragraph::new(info), cols[1]);
}

fn speech_bubble(
    text: &str,
    revealed: usize,
    max_width: usize,
    color: Color,
) -> [Line<'static>; 3] {
    let room = max_width.saturating_sub(6).max(4);
    let mut chars: Vec<char> = text.chars().collect();
    if chars.len() > room {
        chars.truncate(room - 1);
        chars.push('…');
    }
    let width = chars.len();
    let shown_len = revealed.min(width);
    let shown: String = chars.into_iter().take(shown_len).collect();
    let padding = " ".repeat(width - shown_len);

    let border = Style::default().fg(MUTED_GRAY);
    let edge = "─".repeat(width + 2);
    [
        Line::from(Span::styled(format!(" ╭{edge}╮"), border)),
        Line::from(vec![
            Span::styled("◂┤ ", border),
            Span::styled(
                shown,
                Style::default().fg(color).add_modifier(Modifier::ITALIC),
            ),
            Span::raw(padding),
            Span::styled(" │", border),
        ]),
        Line::from(Span::styled(format!(" ╰{edge}╯"), border)),
    ]
}

fn stat_bar(icon: &'static str, stat: Stat, color: Color) -> Vec<Span<'static>> {
    let value = stat.get();
    let filled = usize::from(value.div_ceil(10)).min(STAT_BAR_SEGMENTS);
    let fill = if stat.is_low() { SOFT_ROSE } else { color };

    vec![
        Span::styled(format!("{icon} "), Style::default().fg(fill)),
        Span::styled("━".repeat(filled), Style::default().fg(fill)),
        Span::styled(
            "─".repeat(STAT_BAR_SEGMENTS - filled),
            Style::default().fg(MUTED_GRAY),
        ),
        Span::styled(format!(" {value:>3}%"), Style::default().fg(fill)),
    ]
}

fn render_divider(frame: &mut Frame, area: Rect) {
    let rule = "─".repeat(usize::from(area.width));
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            rule,
            Style::default().fg(MUTED_GRAY),
        ))),
        area,
    );
}

fn render_form_rows(frame: &mut Frame, area: Rect, app: &App) {
    let form = &app.form;
    let mode_line = Line::from(vec![
        focus_marker(form.focus == Focus::Mode),
        label_span("Mode   ", form.focus == Focus::Mode),
        Span::styled(
            " Encrypt ",
            mode_pill_style(form.mode == Mode::Encrypt, RUST_ORANGE),
        ),
        Span::raw(" "),
        Span::styled(
            " Decrypt ",
            mode_pill_style(form.mode == Mode::Decrypt, MINT_GREEN),
        ),
    ]);

    let input_line = text_row(
        "Input  ",
        Cow::Borrowed(form.input.as_str()),
        "path/to/file.txt",
        form.focus == Focus::Input,
    );
    let output_line = text_row(
        "Output ",
        Cow::Borrowed(form.output.as_str()),
        "path/to/file.renc",
        form.focus == Focus::Output,
    );

    let pass_display = if form.show_passphrase {
        Cow::Borrowed(form.passphrase())
    } else {
        Cow::Owned("•".repeat(form.passphrase().chars().count()))
    };
    let pass_line = text_row(
        "Key    ",
        pass_display,
        "passphrase (^T reveal)",
        form.focus == Focus::Passphrase,
    );

    frame.render_widget(
        Paragraph::new(vec![mode_line, input_line, output_line, pass_line]),
        area,
    );
}

fn mode_pill_style(active: bool, accent: Color) -> Style {
    if active {
        Style::default()
            .fg(Color::Black)
            .bg(accent)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(MUTED_GRAY)
    }
}

fn text_row<'a>(
    label: &'static str,
    value: Cow<'a, str>,
    placeholder: &'static str,
    focused: bool,
) -> Line<'a> {
    let mut spans = vec![focus_marker(focused), label_span(label, focused)];

    if value.is_empty() && !focused {
        spans.push(Span::styled(placeholder, Style::default().fg(MUTED_GRAY)));
    } else {
        spans.push(Span::styled(value, Style::default().fg(Color::Reset)));
        if focused {
            spans.push(Span::styled("▌", Style::default().fg(Color::Reset)));
        }
    }

    Line::from(spans)
}

fn focus_marker(focused: bool) -> Span<'static> {
    if focused {
        Span::styled(
            "› ",
            Style::default().fg(WARM_AMBER).add_modifier(Modifier::BOLD),
        )
    } else {
        Span::raw("  ")
    }
}

fn label_span(text: &'static str, focused: bool) -> Span<'static> {
    if focused {
        Span::styled(
            text,
            Style::default().fg(WARM_AMBER).add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(text, Style::default().fg(MUTED_GRAY))
    }
}

fn render_status_line(frame: &mut Frame, area: Rect, app: &App) {
    let line = if let Some(elapsed) = app.job_elapsed() {
        let secs = elapsed.as_secs_f64();
        let idx = usize::try_from(app.tick % SPINNER_FRAMES.len() as u64).unwrap_or(0);
        let spinner = SPINNER_FRAMES[idx];
        let bar = loading_bar(app.tick, LOADING_BAR_WIDTH);
        let stage = if secs < 0.25 {
            "argon2id kdf"
        } else {
            match app.form.mode {
                Mode::Encrypt => "aes-256-gcm seal",
                Mode::Decrypt => "aes-256-gcm open",
            }
        };

        Line::from(vec![
            Span::styled(format!(" {spinner} "), Style::default().fg(WARM_AMBER)),
            Span::styled(stage, Style::default().fg(Color::Reset)),
            Span::raw(" "),
            Span::styled(bar, Style::default().fg(RUST_ORANGE)),
            Span::styled(format!(" {secs:.1}s"), Style::default().fg(MUTED_GRAY)),
        ])
    } else {
        let (text, color) = match &app.status {
            Status::Hint(msg) => (*msg, MUTED_GRAY),
            Status::Success(msg) => (msg.as_str(), MINT_GREEN),
            Status::Error(msg) => (msg.as_str(), SOFT_ROSE),
        };
        Line::from(Span::styled(format!(" {text}"), Style::default().fg(color)))
    };

    frame.render_widget(Paragraph::new(line), area);
}

fn loading_bar(tick: u64, width: usize) -> String {
    let pos = usize::try_from(tick % width as u64).unwrap_or(0);
    let mut out = String::with_capacity(width + 2);
    out.push('[');
    for i in 0..width {
        let dist = (i + width - pos) % width;
        out.push(if dist < 4 { '█' } else { '░' });
    }
    out.push(']');
    out
}

fn render_hints(frame: &mut Frame, area: Rect, app: &App) {
    let text = if app.is_working() {
        " working... · Esc quit"
    } else {
        " Tab next · Enter run · ^M mode · ^T key · ^F feed · ^P pet · Esc quit"
    };
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            text,
            Style::default().fg(MUTED_GRAY),
        ))),
        area,
    );
}
