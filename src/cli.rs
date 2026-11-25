use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::Mode;
use crate::error::{Error, Result};

#[derive(PartialEq, Eq)]
pub struct Command {
    mode: Mode,
    input: PathBuf,
    output: PathBuf,
    passphrase: Zeroizing<String>,
}

impl Command {
    pub fn new(mode: Mode, input: PathBuf, output: PathBuf, passphrase: String) -> Result<Self> {
        if passphrase.is_empty() {
            return Err(Error::EmptyPassphrase);
        }
        Ok(Self {
            mode,
            input,
            output,
            passphrase: Zeroizing::new(passphrase),
        })
    }

    #[must_use]
    pub const fn mode(&self) -> Mode {
        self.mode
    }

    #[must_use]
    pub fn input(&self) -> &Path {
        &self.input
    }

    #[must_use]
    pub fn output(&self) -> &Path {
        &self.output
    }

    #[must_use]
    pub fn passphrase(&self) -> &str {
        &self.passphrase
    }
}

impl fmt::Debug for Command {
    // redacts the passphrase so logging commands never leaks secrets
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Command")
            .field("mode", &self.mode)
            .field("input", &self.input)
            .field("output", &self.output)
            .field("passphrase", &"[redacted]")
            .finish()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    Run(Command),
    Tui,
    Help,
}

// translates raw os arguments into a validated action for the pipeline
pub fn parse_args<I, S>(args: I) -> Result<Action>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let mut iter = args.into_iter().map(Into::into);
    let _program = iter.next();

    let Some(first) = iter.next() else {
        return Ok(Action::Tui);
    };

    if is_help_flag(&first) {
        return Ok(Action::Help);
    }

    if first == "tui" {
        if let Some(extra) = iter.next() {
            if is_help_flag(&extra) {
                return Ok(Action::Help);
            }
            return Err(Error::Usage(format!(
                "unexpected argument for tui: {}",
                extra.to_string_lossy()
            )));
        }
        return Ok(Action::Tui);
    }

    let mode = parse_mode(&first)?;
    let mut positional = Vec::new();
    let mut passphrase = None;

    while let Some(arg) = iter.next() {
        if is_help_flag(&arg) {
            return Ok(Action::Help);
        }

        if arg == "-k" || arg == "--key" {
            let value = iter
                .next()
                .ok_or_else(|| Error::Usage("missing value for --key".into()))?;
            let decoded = value
                .into_string()
                .map_err(|_| Error::Usage("passphrase must be valid utf-8".into()))?;
            passphrase = Some(decoded);
            continue;
        }

        if let Some(text) = arg.to_str()
            && text.starts_with('-')
        {
            return Err(Error::Usage(format!("unknown flag: {text}")));
        }

        positional.push(arg);
    }

    let [input, output]: [OsString; 2] = positional
        .try_into()
        .map_err(|_| Error::Usage("expected <input> and <output> file paths".into()))?;

    let passphrase = passphrase.ok_or_else(|| Error::Usage("missing --key <passphrase>".into()))?;
    let cmd = Command::new(mode, PathBuf::from(input), PathBuf::from(output), passphrase)?;

    Ok(Action::Run(cmd))
}

// checks whether an os argument requests the help banner
fn is_help_flag(arg: &OsStr) -> bool {
    arg == "-h" || arg == "--help"
}

// maps the subcommand token onto the internal operation mode
fn parse_mode(token: &OsStr) -> Result<Mode> {
    match token.to_str() {
        Some("encrypt") => Ok(Mode::Encrypt),
        Some("decrypt") => Ok(Mode::Decrypt),
        Some(other) => Err(Error::Usage(format!("unknown command: {other}"))),
        None => Err(Error::Usage("command must be valid utf-8".into())),
    }
}

// returns the static help banner rendered by the entrypoint
#[must_use]
pub const fn usage() -> &'static str {
    "usage:\n  rust-encrypt [tui]\n  rust-encrypt encrypt <input> <output> --key <passphrase>\n  rust-encrypt decrypt <input> <output> --key <passphrase>"
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
                passphrase: Zeroizing::new("secret".into()),
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

    // checks that running with no arguments or `tui` launches the TUI
    #[test]
    fn launches_tui_for_empty_or_tui_subcommand() {
        assert_eq!(parse_args(["rust-encrypt"]).unwrap(), Action::Tui);
        assert_eq!(parse_args(["rust-encrypt", "tui"]).unwrap(), Action::Tui);
        assert_eq!(
            parse_args(["rust-encrypt", "tui", "--help"]).unwrap(),
            Action::Help
        );
        assert!(matches!(
            parse_args(["rust-encrypt", "tui", "extra"]),
            Err(Error::Usage(_))
        ));
    }

    // checks that debug formatting never exposes the passphrase
    #[test]
    fn redacts_passphrase_in_debug() {
        let cmd = Command {
            mode: Mode::Encrypt,
            input: PathBuf::from("in.txt"),
            output: PathBuf::from("out.renc"),
            passphrase: Zeroizing::new("super-secret-value".into()),
        };

        let formatted = format!("{cmd:?}");
        assert!(!formatted.contains("super-secret-value"));
        assert!(formatted.contains("[redacted]"));
    }
}
