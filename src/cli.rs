use std::path::PathBuf;

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Encrypt,
    Decrypt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    pub mode: Mode,
    pub input: PathBuf,
    pub output: PathBuf,
    pub passphrase: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Run(Command),
    Help,
}

// translates raw process arguments into a validated action for the pipeline
pub fn parse_args<I, S>(args: I) -> Result<Action>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut iter = args.into_iter().map(Into::into);
    let _program = iter.next();

    let Some(first) = iter.next() else {
        return Ok(Action::Help);
    };

    if first == "-h" || first == "--help" {
        return Ok(Action::Help);
    }

    let mode = parse_mode(&first)?;
    let mut positional = Vec::new();
    let mut passphrase = None;

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-h" | "--help" => return Ok(Action::Help),
            "-k" | "--key" => {
                let value = iter
                    .next()
                    .ok_or_else(|| Error::Usage("missing value for --key".into()))?;
                passphrase = Some(value);
            }
            flag if flag.starts_with('-') => {
                return Err(Error::Usage(format!("unknown flag: {flag}")));
            }
            _ => positional.push(arg),
        }
    }

    if positional.len() != 2 {
        return Err(Error::Usage(
            "expected <input> and <output> file paths".into(),
        ));
    }

    let passphrase = passphrase.ok_or_else(|| Error::Usage("missing --key <passphrase>".into()))?;
    if passphrase.is_empty() {
        return Err(Error::Usage("passphrase cannot be empty".into()));
    }

    let mut paths = positional.into_iter();
    let input = PathBuf::from(paths.next().unwrap());
    let output = PathBuf::from(paths.next().unwrap());

    Ok(Action::Run(Command {
        mode,
        input,
        output,
        passphrase,
    }))
}

// maps the subcommand token onto the internal operation mode
fn parse_mode(token: &str) -> Result<Mode> {
    match token {
        "encrypt" => Ok(Mode::Encrypt),
        "decrypt" => Ok(Mode::Decrypt),
        other => Err(Error::Usage(format!("unknown command: {other}"))),
    }
}

// returns the static help banner rendered by the entrypoint
pub fn usage() -> &'static str {
    "usage:\n  rust-encrypt encrypt <input> <output> --key <passphrase>\n  rust-encrypt decrypt <input> <output> --key <passphrase>"
}

#[cfg(test)]
mod tests {
    use super::*;

    // checks that encrypt subcommand flags populate the command struct
    #[test]
    fn parses_encrypt_command() {
        let action = parse_args([
            "rust-encrypt",
            "encrypt",
            "in.txt",
            "out.renc",
            "--key",
            "secret",
        ])
        .unwrap();

        assert_eq!(
            action,
            Action::Run(Command {
                mode: Mode::Encrypt,
                input: PathBuf::from("in.txt"),
                output: PathBuf::from("out.renc"),
                passphrase: "secret".into(),
            })
        );
    }

    // checks that missing key flags fail at the cli boundary
    #[test]
    fn rejects_missing_key() {
        let err = parse_args(["rust-encrypt", "decrypt", "in.renc", "out.txt"]).unwrap_err();
        assert!(matches!(err, Error::Usage(_)));
    }

    // checks that help flags short-circuit parsing cleanly
    #[test]
    fn returns_help_action() {
        let action = parse_args(["rust-encrypt", "--help"]).unwrap();
        assert_eq!(action, Action::Help);
    }
}
