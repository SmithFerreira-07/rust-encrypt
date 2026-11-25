use std::env;
use std::process::ExitCode;

use rust_encrypt::cli::{Action, parse_args, usage};
use rust_encrypt::{Mode, decrypt_file, encrypt_file, tui};

// wires process arguments into the library pipeline and translates errors to exit codes
fn main() -> ExitCode {
    let result = match parse_args(env::args_os()) {
        Ok(Action::Help) => {
            println!("{}", usage());
            return ExitCode::SUCCESS;
        }
        Ok(Action::Tui) => tui::launch(),
        Ok(Action::Run(cmd)) => match cmd.mode() {
            Mode::Encrypt => encrypt_file(cmd.input(), cmd.output(), cmd.passphrase().as_bytes()),
            Mode::Decrypt => decrypt_file(cmd.input(), cmd.output(), cmd.passphrase().as_bytes()),
        },
        Err(err) => {
            eprintln!("error: {err}\n\n{}", usage());
            return ExitCode::FAILURE;
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}
