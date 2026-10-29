use lib_sessiond::SessionCore;
use lib_sessiond::bus::{BusLifecycleEvents, Client};
use lib_sessiond::config::Config;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

static STOP: AtomicBool = AtomicBool::new(false);
extern "C" fn stop(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}
fn main() -> anyhow::Result<()> {
    let mut args = std::env::args_os().skip(1);
    let uid = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("usage: hold-session UID [OUTPUT] [CONFIG]"))?
        .to_string_lossy()
        .parse::<u32>()?;
    let output = args.next().map(PathBuf::from);
    let config = match args.next().map(PathBuf::from) {
        Some(path) => Config::load(&path)?,
        None => Config::default(),
    };
    anyhow::ensure!(
        args.next().is_none(),
        "usage: hold-session UID [OUTPUT] [CONFIG]"
    );
    install_signal()?;
    let opened = SessionCore::new(config)?
        .with_events(BusLifecycleEvents::system())
        .open_session(uid)?;
    if let Some(path) = output {
        let mut file = std::fs::File::create(path)?;
        writeln!(file, "{}", opened.id)?;
        writeln!(file, "{}", opened.runtime.display())?;
    } else {
        println!("sid={} runtime={}", opened.id, opened.runtime.display());
    }
    while !STOP.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(100));
    }
    // This process is inside the session being terminated, so it must use the
    // scheduling-only API and may not wait for its own teardown.
    Client::system(Duration::from_secs(30))?.schedule_close_session(&opened.id)?;
    Ok(())
}
fn install_signal() -> std::io::Result<()> {
    // SAFETY: handler only sets a lock-free atomic in this standalone example.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = stop as *const () as usize;
        libc::sigemptyset(&mut action.sa_mask);
        if libc::sigaction(libc::SIGINT, &action, std::ptr::null_mut()) < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}
