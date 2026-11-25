use ratatui::style::Color;

use super::pet::Mood;

pub const RUST_ORANGE: Color = Color::Rgb(247, 76, 0);
pub const WARM_AMBER: Color = Color::Rgb(255, 176, 64);
pub const MINT_GREEN: Color = Color::Rgb(110, 231, 183);
pub const SOFT_ROSE: Color = Color::Rgb(251, 113, 133);
pub const BLUSH_PINK: Color = Color::Rgb(255, 130, 170);
pub const DREAM_BLUE: Color = Color::Rgb(160, 170, 255);
pub const MUTED_GRAY: Color = Color::DarkGray;

pub const SHELL_HIGHLIGHT: Color = Color::Rgb(255, 146, 72);
pub const CLAW: Color = Color::Rgb(232, 58, 28);
pub const LEG: Color = Color::Rgb(205, 74, 18);
pub const MOUTH: Color = Color::Rgb(255, 178, 128);
pub const TEAR: Color = Color::Rgb(125, 190, 255);
pub const SPARK: Color = Color::Rgb(255, 214, 102);
pub const BYTES_DIM: Color = Color::Rgb(150, 105, 45);
pub const THOUGHT: Color = Color::Gray;
pub const NOTE: Color = Color::Rgb(196, 181, 253);

pub const fn mood_color(mood: Mood) -> Color {
    match mood {
        Mood::Happy | Mood::Eating => MINT_GREEN,
        Mood::Loved => BLUSH_PINK,
        Mood::Working | Mood::Hungry => WARM_AMBER,
        Mood::Startled | Mood::Sad => SOFT_ROSE,
        Mood::Sleepy => DREAM_BLUE,
        Mood::Idle => Color::Reset,
    }
}
