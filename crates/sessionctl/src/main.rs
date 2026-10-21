use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::fmt::Write;
use std::process::ExitCode;

#[zbus::proxy(
    interface = "org.decoupling.sessiond1.Manager",
    default_service = "org.decoupling.sessiond1",
    default_path = "/org/decoupling/sessiond1"
)]
trait Sessiond {
    fn list_sessions(&self) -> zbus::Result<Vec<(String, u32)>>;
    fn close_session(&self, sid: &str) -> zbus::Result<()>;
}

#[derive(Debug, Parser)]
#[command(version, about = "Inspect and close sessiond sessions")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// List managed sessions.
    List,
    /// Request asynchronous, idempotent closure of a session.
    Close {
        #[arg(value_parser = parse_session_id)]
        sid: String,
    },
}

fn parse_session_id(value: &str) -> std::result::Result<String, String> {
    if value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        Ok(value.to_owned())
    } else {
        Err("session ID must be exactly 32 lowercase hexadecimal digits".to_owned())
    }
}

fn main() -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("sessionctl: create async runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(Args::parse())) {
        Ok(output) => {
            print!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("sessionctl: {error:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: Args) -> Result<String> {
    let connection = zbus::Connection::system()
        .await
        .context("connect to the system bus")?;
    let proxy = SessiondProxy::new(&connection)
        .await
        .context("create sessiond D-Bus proxy")?;
    match args.command {
        Command::List => {
            let sessions = proxy
                .list_sessions()
                .await
                .context("call sessiond ListSessions")?;
            Ok(format_sessions(&sessions))
        }
        Command::Close { sid } => {
            proxy
                .close_session(&sid)
                .await
                .with_context(|| format!("call sessiond CloseSession for {sid}"))?;
            Ok(format!("Closure requested for session {sid}.\n"))
        }
    }
}

fn format_sessions(sessions: &[(String, u32)]) -> String {
    if sessions.is_empty() {
        return "No sessions.\n".to_owned();
    }
    let session_width = sessions
        .iter()
        .map(|(sid, _)| sid.len())
        .chain(["SESSION".len()])
        .max()
        .expect("heading provides a width");
    let uid_width = sessions
        .iter()
        .map(|(_, uid)| uid.to_string().len())
        .chain(["UID".len()])
        .max()
        .expect("heading provides a width");
    let mut output = String::new();
    writeln!(
        output,
        "{:<session_width$}  {:>uid_width$}",
        "SESSION", "UID"
    )
    .expect("writing to String cannot fail");
    for (sid, uid) in sessions {
        writeln!(output, "{sid:<session_width$}  {uid:>uid_width$}")
            .expect("writing to String cannot fail");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::error::ErrorKind;

    #[test]
    fn parses_list_and_close_commands() {
        assert!(matches!(
            Args::try_parse_from(["sessionctl", "list"])
                .expect("list parses")
                .command,
            Command::List
        ));
        let sid = "019cff3ece367311bfcf9e696e365fd0";
        let args = Args::try_parse_from(["sessionctl", "close", sid]).expect("close parses");
        assert!(matches!(args.command, Command::Close { sid: parsed } if parsed == sid));
    }

    #[test]
    fn rejects_missing_close_session() {
        let error =
            Args::try_parse_from(["sessionctl", "close"]).expect_err("close requires a session ID");
        assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn rejects_malformed_close_session() {
        let error = Args::try_parse_from(["sessionctl", "close", "NOT-A-SESSION"])
            .expect_err("close validates the session ID");
        assert_eq!(error.kind(), ErrorKind::ValueValidation);
        assert!(error.to_string().contains("32 lowercase hexadecimal"));
    }

    #[test]
    fn renders_empty_state() {
        assert_eq!(format_sessions(&[]), "No sessions.\n");
    }

    #[test]
    fn renders_aligned_table_without_reordering() {
        let output = format_sessions(&[("bbbb".to_owned(), 7), ("a".to_owned(), 1000)]);
        assert_eq!(output, "SESSION   UID\nbbbb        7\na        1000\n");
    }

    #[test]
    fn renders_contextual_dbus_errors() {
        let error = anyhow::anyhow!("org.decoupling.sessiond1.Error.AccessDenied: root only")
            .context("call sessiond CloseSession for abc");
        assert_eq!(
            format!("{error:#}"),
            "call sessiond CloseSession for abc: org.decoupling.sessiond1.Error.AccessDenied: root only"
        );
    }
}
