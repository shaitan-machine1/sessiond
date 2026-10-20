use std::path::PathBuf;

#[zbus::proxy(
    interface = "org.decoupling.sessiond1.Manager",
    default_service = "org.decoupling.sessiond1",
    default_path = "/org/decoupling/sessiond1"
)]
trait Sessiond {
    fn open_session(&self, uid: u32) -> zbus::Result<(String, String)>;
    fn close_session(&self, sid: &str) -> zbus::Result<()>;
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args_os().skip(1);
    let uid: u32 = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("usage: hold-session UID SID_FILE"))?
        .to_string_lossy()
        .parse()?;
    let sid_file = PathBuf::from(
        args.next()
            .ok_or_else(|| anyhow::anyhow!("usage: hold-session UID SID_FILE"))?,
    );
    let connection = zbus::Connection::system().await?;
    let proxy = SessiondProxy::new(&connection).await?;
    let (sid, runtime) = proxy.open_session(uid).await?;
    std::fs::write(&sid_file, format!("{sid}\n{runtime}\n"))?;
    tokio::signal::ctrl_c().await?;
    proxy.close_session(&sid).await?;
    Ok(())
}
