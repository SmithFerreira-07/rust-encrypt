use std::io;
use std::time::Duration;

use crossterm::event::{self, Event};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use ratatui::backend::CrosstermBackend;
use ratatui::{Terminal, TerminalOptions, Viewport};

use crate::error::Result;

mod app;
mod ferris;
mod pet;
mod theme;
mod view;

use app::App;

const TICK_RATE: Duration = Duration::from_millis(80);
const INLINE_HEIGHT: u16 = 15;

struct RawModeGuard;

impl RawModeGuard {
    fn enter() -> io::Result<Self> {
        enable_raw_mode()?;
        Ok(Self)
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
    }
}

// launches the compact inline ferris tamagotchi tui inside the current terminal
pub fn launch() -> Result<()> {
    let _guard = RawModeGuard::enter()?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::with_options(
        backend,
        TerminalOptions {
            viewport: Viewport::Inline(INLINE_HEIGHT),
        },
    )?;

    let mut app = App::new();

    while !app.should_quit {
        terminal.draw(|frame| view::render(frame, &app))?;

        if event::poll(TICK_RATE)?
            && let Event::Key(key) = event::read()?
        {
            app.handle_key(key);
        }
        app.on_tick();
    }

    terminal.clear()?;
    Ok(())
}
