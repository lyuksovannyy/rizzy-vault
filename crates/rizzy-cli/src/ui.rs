//! What `rv` asks the user and what it shows (threat model INV-56: "`rv` never takes secret
//! values from argv or environment variables, and prints a secret to a terminal only when
//! asked to explicitly").
//!
//! [`Ui`] is the one door for both directions, so the commands ([`crate::commands`]) hold no
//! terminal code and the end-to-end tests drive them with scripted answers.
//!
//! # [`Terminal`], the real one
//!
//! - **Secrets in.** When standard input is a terminal, a secret is prompted for on stderr
//!   and read with echo off. `unsafe` is forbidden and rustix is admitted for core dumps only
//!   (ADR 0024 point 3: "Use, and nothing else"), so `rv` cannot call `tcsetattr` itself: it
//!   runs the system's `stty -echo` on the terminal, from a fixed path (`/bin/stty`, then
//!   `/usr/bin/stty`; never `$PATH`), and `stty echo` afterwards. If echo cannot be turned
//!   off (no `stty`, or not Unix), the secret is **not** read from the terminal
//!   ([`CliError::NoTerminal`]): a secret is never typed in clear. When standard input is
//!   not a terminal, secrets are read from it one per line, in the order they are asked for.
//! - **Lines** are at most [`MAX_LINE_LEN`] bytes; a longer one is refused, never truncated.
//! - **The plaintext-export phrase** is read only from a terminal (ADR 0027 §5: "`rv` reads
//!   the phrase from the terminal, so a plaintext export never runs unattended").
//! - **The plaintext-export hold** (owner decision 2026-10-05): after the warning, [`Ui::hold`]
//!   blocks for the whole hold, measured with a monotonic clock, before the phrase is asked
//!   for. No flag or environment variable shortens it. The one seam is this trait: the
//!   end-to-end tests implement [`Ui`] with scripted answers and record the hold instead of
//!   sleeping. What the user types during the hold stays in the terminal's input buffer and
//!   is read by the phrase prompt after it: `rv` cannot flush the terminal's input without
//!   `tcflush`, which needs `unsafe` or a crate not admitted for it (reported).
//! - **Results** go to stdout, notes and prompts to stderr, through `write!` on locked handles
//!   (never `println!`, which panics on a closed pipe). A failed write is an error.
//!
//! Typed secrets are held in zeroizing buffers. Standard input's own buffer (in `std`) is not
//! wiped: it is reused by the next read, and the process is short-lived with core dumps off
//! (INV-60).

use std::io::{self, BufRead as _, IsTerminal as _, Write as _};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::error::{CliError, io_error};

/// The most bytes of one typed or piped line.
pub const MAX_LINE_LEN: usize = 4096;

/// The user's side of a command (module docs).
pub trait Ui {
    /// Asks for a secret: read without echo, or from piped standard input.
    ///
    /// # Errors
    /// [`CliError::NoTerminal`], [`CliError::InputEnded`], [`CliError::Io`].
    fn secret(&mut self, prompt: &str) -> Result<Zeroizing<String>, CliError>;

    /// Asks for a line that is not a secret.
    ///
    /// # Errors
    /// [`CliError::InputEnded`], [`CliError::Io`].
    fn line(&mut self, prompt: &str) -> Result<String, CliError>;

    /// Asks for a phrase that must be typed at a terminal, never piped.
    ///
    /// # Errors
    /// [`CliError::NoTerminal`] when standard input is not a terminal.
    fn typed(&mut self, prompt: &str) -> Result<String, CliError>;

    /// Writes one line of a command's result to standard output.
    ///
    /// # Errors
    /// [`CliError::Io`].
    fn print(&mut self, text: &str) -> Result<(), CliError>;

    /// Writes one line for the user to read (a warning, a progress note) to standard error.
    /// A failure to write a note is not an error.
    fn note(&mut self, text: &str);

    /// Holds the user for `duration` (the plaintext-export hold) and returns how long it held,
    /// never less than `duration` for the terminal.
    fn hold(&mut self, duration: Duration) -> Duration;
}

/// The terminal (module docs).
#[derive(Debug, Default)]
pub struct Terminal {
    /// Nothing to hold: standard input, output and error are the process's.
    _private: (),
}

impl Terminal {
    /// The process's terminal.
    #[must_use]
    pub const fn new() -> Self {
        Self { _private: () }
    }
}

/// Runs the system `stty` with one argument on the inherited terminal. `true` if it ran and
/// succeeded.
#[cfg(unix)]
fn stty(argument: &str) -> bool {
    use std::process::{Command, Stdio};
    ["/bin/stty", "/usr/bin/stty"].iter().any(|path| {
        Command::new(path)
            .arg(argument)
            .stdin(Stdio::inherit())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .env_clear()
            .status()
            .is_ok_and(|status| status.success())
    })
}

/// No `stty` outside Unix: echo cannot be turned off.
#[cfg(not(unix))]
fn stty(_argument: &str) -> bool {
    false
}

/// Echo off for as long as this lives; echo on again when it drops, on every path.
struct EchoOff;

impl EchoOff {
    /// Turns echo off, or fails without having read anything.
    fn new() -> Result<Self, CliError> {
        if stty("-echo") {
            Ok(Self)
        } else {
            Err(CliError::NoTerminal)
        }
    }
}

impl Drop for EchoOff {
    fn drop(&mut self) {
        stty("echo");
        // The user's Return was not echoed: end the prompt's line.
        let _ = writeln!(io::stderr().lock());
    }
}

/// Reads one line of at most [`MAX_LINE_LEN`] bytes from standard input, without its line
/// terminator, into a zeroizing buffer.
fn read_line() -> Result<Zeroizing<String>, CliError> {
    let mut raw = Zeroizing::new(Vec::with_capacity(128));
    let stdin = io::stdin();
    let mut input = stdin.lock();
    loop {
        let available = input
            .fill_buf()
            .map_err(io_error("cannot read standard input"))?;
        if available.is_empty() {
            if raw.is_empty() {
                return Err(CliError::InputEnded);
            }
            break;
        }
        let (take, done) = match available.iter().position(|b| *b == b'\n') {
            Some(at) => (at + 1, true),
            None => (available.len(), false),
        };
        if raw.len() + take > MAX_LINE_LEN + 2 {
            return Err(CliError::BadInput("the line is too long"));
        }
        raw.extend_from_slice(available.get(..take).unwrap_or_default());
        input.consume(take);
        if done {
            break;
        }
    }
    while matches!(raw.last(), Some(b'\n' | b'\r')) {
        raw.pop();
    }
    let text = core::str::from_utf8(&raw).map_err(|_| CliError::BadInput("not valid UTF-8"))?;
    Ok(Zeroizing::new(text.to_owned()))
}

/// Writes a prompt to standard error, without a newline.
fn prompt(text: &str) {
    let mut err = io::stderr().lock();
    let _ = write!(err, "{text}: ");
    let _ = err.flush();
}

impl Ui for Terminal {
    fn secret(&mut self, text: &str) -> Result<Zeroizing<String>, CliError> {
        if io::stdin().is_terminal() {
            prompt(text);
            let _echo = EchoOff::new()?;
            read_line()
        } else {
            read_line()
        }
    }

    fn line(&mut self, text: &str) -> Result<String, CliError> {
        if io::stdin().is_terminal() {
            prompt(text);
        }
        read_line().map(|line| line.as_str().to_owned())
    }

    fn typed(&mut self, text: &str) -> Result<String, CliError> {
        if !io::stdin().is_terminal() {
            return Err(CliError::NoTerminal);
        }
        prompt(text);
        read_line().map(|line| line.as_str().to_owned())
    }

    fn print(&mut self, text: &str) -> Result<(), CliError> {
        writeln!(io::stdout().lock(), "{text}").map_err(io_error("cannot write to standard output"))
    }

    fn note(&mut self, text: &str) {
        let _ = writeln!(io::stderr().lock(), "{text}");
    }

    fn hold(&mut self, duration: Duration) -> Duration {
        let start = Instant::now();
        // `sleep` may wake early on some platforms: sleep again until the monotonic clock
        // has passed the whole hold.
        loop {
            let held = start.elapsed();
            match duration.checked_sub(held) {
                Some(left) if !left.is_zero() => std::thread::sleep(left),
                _ => return held,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_terminal_holds_for_the_whole_duration() {
        let wanted = Duration::from_millis(30);
        let start = Instant::now();
        let held = Terminal::new().hold(wanted);
        assert!(held >= wanted);
        assert!(start.elapsed() >= wanted);
    }
}
