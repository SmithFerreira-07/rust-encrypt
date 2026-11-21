use std::env;
use std::process::ExitCode;

use rust_encrypt::cli::{Action, parse_args, usage};
use rust_encrypt::run;

// wires process arguments into the library pipeline and translates errors to exit codes
fn main() -> ExitCode {
    match parse_args(env::args()) {
        Ok(Action::Help) => {
            println!("{}", usage());
            ExitCode::SUCCESS
        }
        Ok(Action::Run(cmd)) => match run(&cmd) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("error: {err}");
                ExitCode::FAILURE
            }
        },
        Err(err) => {
            eprintln!("error: {err}\n\n{}", usage());
            ExitCode::FAILURE
        }
    }
}
