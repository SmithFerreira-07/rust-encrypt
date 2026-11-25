use std::fs;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use zeroize::Zeroizing;

use crate::error::Result;
use crate::{Mode, decrypt_file, encrypt_file};

use super::TICK_RATE;
use super::pet::Pet;

const INITIAL_HINT: &str = "enter file paths & key, then press Enter";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    Mode,
    Input,
    Output,
    Passphrase,
}

impl Focus {
    const fn next(self) -> Self {
        match self {
            Self::Mode => Self::Input,
            Self::Input => Self::Output,
            Self::Output => Self::Passphrase,
            Self::Passphrase => Self::Mode,
        }
    }

    const fn prev(self) -> Self {
        match self {
            Self::Mode => Self::Passphrase,
            Self::Input => Self::Mode,
            Self::Output => Self::Input,
            Self::Passphrase => Self::Output,
        }
    }
}

pub enum Status {
    Hint(&'static str),
    Success(String),
    Error(String),
}

pub struct Form {
    pub mode: Mode,
    pub focus: Focus,
    pub input: String,
    pub output: String,
    output_edited: bool,
    passphrase: Zeroizing<String>,
    pub show_passphrase: bool,
}

impl Form {
    fn new() -> Self {
        Self {
            mode: Mode::Encrypt,
            focus: Focus::Input,
            input: String::new(),
            output: String::new(),
            output_edited: false,
            passphrase: Zeroizing::new(String::new()),
            show_passphrase: false,
        }
    }

    pub fn passphrase(&self) -> &str {
        &self.passphrase
    }

    fn toggle_mode(&mut self) {
        self.mode = match self.mode {
            Mode::Encrypt => Mode::Decrypt,
            Mode::Decrypt => Mode::Encrypt,
        };
        self.sync_suggested_output();
    }

    fn push_char(&mut self, ch: char) {
        match self.focus {
            Focus::Input => {
                self.input.push(ch);
                self.sync_suggested_output();
            }
            Focus::Output => self.edit_output(|out| out.push(ch)),
            Focus::Passphrase => self.passphrase.push(ch),
            Focus::Mode => {}
        }
    }

    fn pop_char(&mut self) {
        match self.focus {
            Focus::Input => {
                self.input.pop();
                self.sync_suggested_output();
            }
            Focus::Output => self.edit_output(|out| {
                out.pop();
            }),
            Focus::Passphrase => {
                self.passphrase.pop();
            }
            Focus::Mode => {}
        }
    }

    fn edit_output(&mut self, edit: impl FnOnce(&mut String)) {
        edit(&mut self.output);
        self.output_edited = !self.output.is_empty();
    }

    fn sync_suggested_output(&mut self) {
        if !self.output_edited {
            self.output = suggest_output_path(&self.input, self.mode);
        }
    }
}

struct ActiveJob {
    rx: Receiver<JobOutcome>,
    started: Instant,
}

struct JobOutcome {
    mode: Mode,
    elapsed: Duration,
    output_path: PathBuf,
    result: Result<u64>,
}

pub struct App {
    pub form: Form,
    pub pet: Pet,
    pub status: Status,
    pub now: Instant,
    pub tick: u64,
    pub should_quit: bool,
    job: Option<ActiveJob>,
    started: Instant,
}

impl App {
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            form: Form::new(),
            pet: Pet::new(now),
            status: Status::Hint(INITIAL_HINT),
            now,
            tick: 0,
            should_quit: false,
            job: None,
            started: now,
        }
    }

    pub const fn is_working(&self) -> bool {
        self.job.is_some()
    }

    pub fn job_elapsed(&self) -> Option<Duration> {
        self.job
            .as_ref()
            .map(|job| self.now.saturating_duration_since(job.started))
    }

    pub fn on_tick(&mut self) {
        let now = Instant::now();
        self.now = now;
        let ticks = now.saturating_duration_since(self.started).as_millis() / TICK_RATE.as_millis();
        self.tick = u64::try_from(ticks).unwrap_or(u64::MAX);

        self.poll_job(now);
        self.pet.update(now, self.tick, self.is_working());
    }

    fn poll_job(&mut self, now: Instant) {
        let Some(job) = &self.job else {
            return;
        };

        match job.rx.try_recv() {
            Ok(outcome) => {
                self.job = None;
                self.finish_job(outcome, now);
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                self.job = None;
                self.set_error("worker thread stopped unexpectedly", now);
            }
        }
    }

    fn finish_job(&mut self, outcome: JobOutcome, now: Instant) {
        let secs = outcome.elapsed.as_secs_f64();
        match outcome.result {
            Ok(bytes) => {
                let verb = match outcome.mode {
                    Mode::Encrypt => "encrypted",
                    Mode::Decrypt => "decrypted",
                };
                self.pet.work_succeeded(outcome.mode, now);
                self.status = Status::Success(format!(
                    "✓ {verb} -> {} ({bytes} B in {secs:.2}s)",
                    outcome.output_path.display()
                ));
            }
            Err(err) => self.set_error(&err.to_string(), now),
        }
    }

    fn set_error(&mut self, msg: &str, now: Instant) {
        self.pet.work_failed(now);
        self.status = Status::Error(format!("✗ {msg}"));
    }

    fn start_job(&mut self, now: Instant) {
        if self.is_working() {
            return;
        }

        let input = self.form.input.trim();
        if input.is_empty() {
            self.set_error("input file path is required", now);
            self.form.focus = Focus::Input;
            return;
        }

        let output = self.form.output.trim();
        if output.is_empty() {
            self.set_error("output file path is required", now);
            self.form.focus = Focus::Output;
            return;
        }

        if self.form.passphrase.is_empty() {
            self.set_error("passphrase cannot be empty", now);
            self.form.focus = Focus::Passphrase;
            return;
        }

        let mode = self.form.mode;
        let input_path = PathBuf::from(input);
        let output_path = PathBuf::from(output);
        let passphrase = Zeroizing::new(self.form.passphrase.as_bytes().to_vec());

        let (tx, rx) = mpsc::channel();
        self.job = Some(ActiveJob { rx, started: now });
        self.pet.start_work(mode);

        thread::spawn(move || {
            let started = Instant::now();
            let op = match mode {
                Mode::Encrypt => encrypt_file(&input_path, &output_path, &passphrase),
                Mode::Decrypt => decrypt_file(&input_path, &output_path, &passphrase),
            };
            drop(passphrase);

            let result = op.and_then(|()| {
                let len = fs::metadata(&output_path)?.len();
                Ok(len)
            });

            let _ = tx.send(JobOutcome {
                mode,
                elapsed: started.elapsed(),
                output_path,
                result,
            });
        });
    }

    pub fn handle_key(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return;
        }

        let now = Instant::now();
        self.now = now;
        self.pet.notice_input(now);

        if key.modifiers.contains(KeyModifiers::CONTROL) {
            self.handle_control_key(key.code, now);
            return;
        }

        if key.code == KeyCode::Esc {
            self.should_quit = true;
            return;
        }

        if self.is_working() || key.modifiers.contains(KeyModifiers::ALT) {
            return;
        }

        match key.code {
            KeyCode::Tab | KeyCode::Down => self.form.focus = self.form.focus.next(),
            KeyCode::BackTab | KeyCode::Up => self.form.focus = self.form.focus.prev(),
            KeyCode::Enter => match self.form.focus {
                Focus::Mode => self.form.toggle_mode(),
                Focus::Input | Focus::Output | Focus::Passphrase => self.start_job(now),
            },
            KeyCode::Left | KeyCode::Right | KeyCode::Char(' ')
                if self.form.focus == Focus::Mode =>
            {
                self.form.toggle_mode();
            }
            KeyCode::Backspace => self.form.pop_char(),
            KeyCode::Char(ch) => self.form.push_char(ch),
            _ => {}
        }
    }

    fn handle_control_key(&mut self, code: KeyCode, now: Instant) {
        match code {
            KeyCode::Char('c' | 'q') => self.should_quit = true,
            KeyCode::Char('f') if !self.is_working() => self.pet.feed(now),
            KeyCode::Char('p') if !self.is_working() => self.pet.pet(now),
            KeyCode::Char('m') if !self.is_working() => self.form.toggle_mode(),
            KeyCode::Char('t') => self.form.show_passphrase = !self.form.show_passphrase,
            _ => {}
        }
    }
}

fn suggest_output_path(input: &str, mode: Mode) -> String {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    match mode {
        Mode::Encrypt => format!("{trimmed}.renc"),
        Mode::Decrypt => trimmed
            .strip_suffix(".renc")
            .map_or_else(|| format!("{trimmed}.dec"), ToString::to_string),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::pet::Mood;

    fn press(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, modifiers)
    }

    #[test]
    fn suggests_output_paths() {
        assert_eq!(
            suggest_output_path("notes.txt", Mode::Encrypt),
            "notes.txt.renc"
        );
        assert_eq!(
            suggest_output_path("notes.txt.renc", Mode::Decrypt),
            "notes.txt"
        );
        assert_eq!(
            suggest_output_path("archive.bin", Mode::Decrypt),
            "archive.bin.dec"
        );
        assert_eq!(suggest_output_path("   ", Mode::Encrypt), "");
    }

    #[test]
    fn tamagotchi_interactions_update_state() {
        let mut app = App::new();
        let initial_energy = app.pet.energy().get();
        let initial_happiness = app.pet.happiness().get();

        app.handle_key(press(KeyCode::Char('f'), KeyModifiers::CONTROL));
        assert_eq!(app.pet.mood(), Mood::Eating);
        assert!(app.pet.energy().get() > initial_energy);

        app.handle_key(press(KeyCode::Char('p'), KeyModifiers::CONTROL));
        assert_eq!(app.pet.mood(), Mood::Loved);
        assert!(app.pet.happiness().get() > initial_happiness);
    }

    #[test]
    fn unbound_control_and_alt_keys_do_not_type_into_inputs() {
        let mut app = App::new();
        app.handle_key(press(KeyCode::Char('x'), KeyModifiers::CONTROL));
        app.handle_key(press(KeyCode::Char('y'), KeyModifiers::ALT));
        assert_eq!(app.form.input, "");
    }

    #[test]
    fn typing_input_auto_suggests_output_until_manually_edited() {
        let mut app = App::new();
        for ch in "secret.txt".chars() {
            app.handle_key(press(KeyCode::Char(ch), KeyModifiers::NONE));
        }
        assert_eq!(app.form.output, "secret.txt.renc");

        app.handle_key(press(KeyCode::Tab, KeyModifiers::NONE));
        assert_eq!(app.form.focus, Focus::Output);
        app.handle_key(press(KeyCode::Char('2'), KeyModifiers::NONE));
        assert_eq!(app.form.output, "secret.txt.renc2");

        app.handle_key(press(KeyCode::Char('m'), KeyModifiers::CONTROL));
        assert_eq!(app.form.mode, Mode::Decrypt);
        assert_eq!(app.form.output, "secret.txt.renc2");
    }
}
