use std::process::ExitCode;

use rust_encrypt::tui;

// launches the tui and translates errors to exit codes
fn main() -> ExitCode {
    match tui::launch() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}
