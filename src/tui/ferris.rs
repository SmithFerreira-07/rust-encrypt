use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

use super::pet::Mood;
use super::theme::{
    BLUSH_PINK, BYTES_DIM, CLAW, DREAM_BLUE, LEG, MINT_GREEN, MOUTH, NOTE, RUST_ORANGE,
    SHELL_HIGHLIGHT, SOFT_ROSE, SPARK, TEAR, THOUGHT, WARM_AMBER,
};

pub const ART_WIDTH: u16 = 30;
pub const ART_HEIGHT: u16 = 6;

const SPARKLES: [&str; 4] = ["✧", "·", "✦", "*"];
const WORK_BYTES: [&str; 12] = [
    "4f", "a3", "7c", "19", "e0", "b5", "28", "d1", "9a", "06", "f4", "6e",
];
const LEGS_SPLAYED: &str = "/_/ /   \\ \\_\\";
const LEGS_STEPPING: &str = "|_| |   | |_|";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Arms {
    Up,
    Down,
    WaveLeft,
    WaveRight,
}

impl Arms {
    // returns (left, right) [claw, forearm, elbow] slices
    const fn rows(self, snap: bool) -> ([&'static str; 3], [&'static str; 3]) {
        let (left_up, right_up) = match self {
            Self::Up => (true, true),
            Self::Down => (false, false),
            Self::WaveLeft => (true, false),
            Self::WaveRight => (false, true),
        };

        let left = match (left_up, snap) {
            (true, true) => ["  (/\\)  ", "   \\ \\ ", "    \\ "],
            (true, false) => ["  (\\/)  ", "   \\ \\ ", "    \\ "],
            (false, true) => ["        ", "       ", " (/\\)-"],
            (false, false) => ["        ", "       ", " (\\/)-"],
        };
        let right = match (right_up, snap) {
            (true, true) => ["  (/\\)  ", " / /   ", " /    "],
            (true, false) => ["  (\\/)  ", " / /   ", " /    "],
            (false, true) => ["        ", "       ", "-(/\\) "],
            (false, false) => ["        ", "       ", "-(\\/) "],
        };
        (left, right)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Gaze {
    Left,
    Center,
    Right,
}

impl Gaze {
    const fn padding(self) -> (&'static str, &'static str) {
        match self {
            Self::Left => ("  ", "    "),
            Self::Center => ("   ", "   "),
            Self::Right => ("    ", "  "),
        }
    }
}

struct FxGlyph {
    col: usize,
    glyph: &'static str,
    color: Color,
}

struct Look {
    eyes: [&'static str; 2],
    eye_style: Style,
    gaze: Gaze,
    mouth: &'static str,
    cheeks: [&'static str; 2],
    cheek_color: Color,
    arms: Arms,
    snap: bool,
    scuttle: bool,
    shake: bool,
    shell: Color,
    fx: Vec<FxGlyph>,
}

impl Look {
    fn fx(&mut self, col: usize, glyph: &'static str, color: Color) {
        self.fx.push(FxGlyph { col, glyph, color });
    }
}

impl Default for Look {
    fn default() -> Self {
        Self {
            eyes: ["●", "●"],
            eye_style: Style::default().add_modifier(Modifier::BOLD),
            gaze: Gaze::Center,
            mouth: "ω",
            cheeks: [",,", ",,"],
            cheek_color: BLUSH_PINK,
            arms: Arms::Down,
            snap: false,
            scuttle: false,
            shake: false,
            shell: RUST_ORANGE,
            fx: Vec::new(),
        }
    }
}

const fn pulse(tick: u64, period: u64) -> bool {
    (tick / period).is_multiple_of(2)
}

// quick blink every ~4s, with an occasional double blink
const fn blinking(tick: u64) -> bool {
    let phase = tick % 52;
    phase < 2 || (phase >= 4 && phase < 6 && (tick / 52).is_multiple_of(3))
}

pub fn frame(mood: Mood, tick: u64) -> Vec<Line<'static>> {
    let look = look_for(mood, tick);
    let pad = if look.shake && tick.is_multiple_of(2) {
        " "
    } else {
        ""
    };

    let ([left_claw, left_arm, left_elbow], [right_claw, right_arm, right_elbow]) =
        look.arms.rows(look.snap);
    let (gaze_left, gaze_right) = look.gaze.padding();

    let claw = Style::default().fg(CLAW);
    let shell = Style::default().fg(look.shell);
    let spikes = Style::default()
        .fg(SHELL_HIGHLIGHT)
        .add_modifier(Modifier::BOLD);
    let mouth = Style::default().fg(MOUTH).add_modifier(Modifier::BOLD);
    let cheeks = Style::default().fg(look.cheek_color);
    let legs = Style::default().fg(LEG);

    vec![
        fx_row(look.fx),
        Line::from(vec![
            Span::raw(pad),
            Span::styled(left_claw, claw),
            Span::styled("_.-", shell),
            Span::styled("~^~^~^~", spikes),
            Span::styled("-._", shell),
            Span::styled(right_claw, claw),
        ]),
        Line::from(vec![
            Span::raw(pad),
            Span::styled(left_arm, claw),
            Span::styled("/", shell),
            Span::raw(gaze_left),
            Span::styled(look.eyes[0], look.eye_style),
            Span::raw("     "),
            Span::styled(look.eyes[1], look.eye_style),
            Span::raw(gaze_right),
            Span::styled("\\", shell),
            Span::styled(right_arm, claw),
        ]),
        Line::from(vec![
            Span::raw(pad),
            Span::styled(left_elbow, claw),
            Span::styled("(", shell),
            Span::raw("   "),
            Span::styled(look.cheeks[0], cheeks),
            Span::raw("  "),
            Span::styled(look.mouth, mouth),
            Span::raw("  "),
            Span::styled(look.cheeks[1], cheeks),
            Span::raw("   "),
            Span::styled(")", shell),
            Span::styled(right_elbow, claw),
        ]),
        Line::from(vec![
            Span::raw(pad),
            Span::raw("     "),
            Span::styled("'-'", claw),
            Span::styled(".___________.", shell),
            Span::styled("'-'", claw),
        ]),
        Line::from(vec![
            Span::raw(pad),
            Span::raw("        "),
            Span::styled(
                if look.scuttle {
                    LEGS_STEPPING
                } else {
                    LEGS_SPLAYED
                },
                legs,
            ),
        ]),
    ]
}

fn fx_row(mut items: Vec<FxGlyph>) -> Line<'static> {
    items.sort_by_key(|item| item.col);

    let mut spans = Vec::with_capacity(items.len() * 2);
    let mut cursor = 0usize;
    for item in items {
        if item.col < cursor {
            continue;
        }
        spans.push(Span::raw(" ".repeat(item.col - cursor)));
        let width = item.glyph.chars().count();
        spans.push(Span::styled(item.glyph, Style::default().fg(item.color)));
        cursor = item.col + width;
    }
    Line::from(spans)
}

fn look_for(mood: Mood, tick: u64) -> Look {
    let mut look = Look::default();
    match mood {
        Mood::Idle => idle_look(&mut look, tick),
        Mood::Working => working_look(&mut look, tick),
        Mood::Happy => happy_look(&mut look, tick),
        Mood::Loved => loved_look(&mut look, tick),
        Mood::Eating => eating_look(&mut look, tick),
        Mood::Startled => startled_look(&mut look, tick),
        Mood::Sleepy => sleepy_look(&mut look, tick),
        Mood::Hungry => hungry_look(&mut look, tick),
        Mood::Sad => sad_look(&mut look, tick),
    }
    look
}

fn idle_look(look: &mut Look, tick: u64) {
    if blinking(tick) {
        look.eyes = ["-", "-"];
    }
    look.gaze = match (tick / 28) % 6 {
        1 => Gaze::Left,
        4 => Gaze::Right,
        _ => Gaze::Center,
    };
    if tick % 90 < 16 {
        look.arms = match (tick / 90) % 4 {
            0 => Arms::WaveLeft,
            2 => Arms::WaveRight,
            _ => Arms::Down,
        };
        look.snap = pulse(tick, 3);
    }
    look.scuttle = (tick / 40).is_multiple_of(5) && pulse(tick, 3);
    if (tick / 70).is_multiple_of(4) {
        let sway = pulse(tick, 5);
        let note = if sway { "♪" } else { "♫" };
        look.fx(22 + usize::from(sway), note, NOTE);
    }
}

fn working_look(look: &mut Look, tick: u64) {
    look.eyes = ["ò", "ó"];
    look.mouth = if pulse(tick, 3) { "-" } else { "~" };
    look.cheeks = ["  ", "  "];
    look.arms = if pulse(tick, 2) { Arms::Up } else { Arms::Down };
    look.snap = !pulse(tick, 2);
    look.scuttle = pulse(tick, 2);

    let step = usize::try_from(tick / 2).unwrap_or(0);
    for slot in 0..9usize {
        if (slot + step).is_multiple_of(3) {
            let col = 1 + slot * 3;
            let color = if (slot + step).is_multiple_of(2) {
                WARM_AMBER
            } else {
                BYTES_DIM
            };
            let byte = WORK_BYTES[(slot * 5 + step) % WORK_BYTES.len()];
            look.fx(col, byte, color);
        }
    }
}

fn happy_look(look: &mut Look, tick: u64) {
    look.eyes = ["^", "^"];
    look.mouth = "▽";
    look.arms = Arms::Up;
    look.snap = pulse(tick, 3);
    look.scuttle = !pulse(tick, 3);
    for (i, col) in [2usize, 8, 20, 26].into_iter().enumerate() {
        let idx = usize::try_from((tick / 3 + i as u64) % 4).unwrap_or(0);
        look.fx(col, SPARKLES[idx], SPARK);
    }
}

fn loved_look(look: &mut Look, tick: u64) {
    look.eyes = ["♥", "♥"];
    look.eye_style = Style::default().fg(BLUSH_PINK).add_modifier(Modifier::BOLD);
    look.arms = if pulse(tick, 6) {
        Arms::WaveLeft
    } else {
        Arms::WaveRight
    };
    for (i, col) in [3usize, 14, 24].into_iter().enumerate() {
        let phase = tick / 4 + i as u64;
        let sway = usize::from(phase.is_multiple_of(2));
        let heart = if phase.is_multiple_of(3) {
            "♡"
        } else {
            "♥"
        };
        look.fx(col + sway, heart, BLUSH_PINK);
    }
}

fn eating_look(look: &mut Look, tick: u64) {
    look.eyes = [">", "<"];
    look.mouth = if pulse(tick, 2) { "o" } else { "ω" };
    look.snap = pulse(tick, 2);
    let col = if pulse(tick, 5) { 4 } else { 21 };
    look.fx(col, "nom", MINT_GREEN);
}

fn startled_look(look: &mut Look, tick: u64) {
    look.eyes = [">", "<"];
    look.mouth = "Д";
    look.cheeks = ["  ", "  "];
    look.arms = Arms::Up;
    look.shake = true;
    if pulse(tick, 2) {
        look.shell = SOFT_ROSE;
        look.fx(5, "!", SOFT_ROSE);
        look.fx(23, "!", SOFT_ROSE);
    } else {
        look.fx(4, "!!", SOFT_ROSE);
        look.fx(23, "!!", SOFT_ROSE);
    }
}

fn sleepy_look(look: &mut Look, tick: u64) {
    look.eyes = ["-", "-"];
    look.mouth = if pulse(tick, 8) { "o" } else { "." };
    let shown = usize::try_from((tick / 6) % 4).unwrap_or(0);
    for (col, z) in [(20usize, "z"), (23, "Z"), (26, "z")]
        .into_iter()
        .take(shown)
    {
        look.fx(col, z, DREAM_BLUE);
    }
}

fn hungry_look(look: &mut Look, tick: u64) {
    look.eyes = if blinking(tick) {
        ["-", "-"]
    } else {
        ["o", "o"]
    };
    look.gaze = Gaze::Right;
    look.mouth = "~";
    let bubble = if pulse(tick, 6) { "°" } else { "o" };
    look.fx(18, bubble, THOUGHT);
    look.fx(20, "o", THOUGHT);
    look.fx(22, "(food?)", THOUGHT);
}

fn sad_look(look: &mut Look, tick: u64) {
    look.eyes = ["T", "T"];
    look.mouth = "^";
    look.cheeks = match (tick / 4) % 3 {
        0 => [" '", "' "],
        1 => [" ,", ", "],
        _ => ["  ", "  "],
    };
    look.cheek_color = TEAR;
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_MOODS: [Mood; 9] = [
        Mood::Idle,
        Mood::Working,
        Mood::Happy,
        Mood::Loved,
        Mood::Eating,
        Mood::Startled,
        Mood::Sleepy,
        Mood::Hungry,
        Mood::Sad,
    ];

    #[test]
    fn frames_fit_the_art_box() {
        for mood in ALL_MOODS {
            for tick in 0..400 {
                let lines = frame(mood, tick);
                assert_eq!(lines.len(), usize::from(ART_HEIGHT), "{mood:?}");
                for line in &lines {
                    assert!(
                        line.width() <= usize::from(ART_WIDTH),
                        "{mood:?} tick {tick}: {line:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn body_rows_share_a_width() {
        for mood in ALL_MOODS {
            for tick in 0..120 {
                let lines = frame(mood, tick);
                let widths: Vec<usize> = lines[1..4]
                    .iter()
                    .map(|line| line.width() - usize::from(line.spans[0].content == " "))
                    .collect();
                assert!(
                    widths.iter().all(|w| *w == widths[0]),
                    "{mood:?} {widths:?}"
                );
            }
        }
    }
}
