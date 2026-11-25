//! Disposable-harness host. Each invocation opens exactly one independent session.
use lib_sessiond::{OpenOptions, bus::Client, open_session_with_options};
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
        .ok_or_else(|| anyhow::anyhow!("usage: hold-session UID [OUTPUT] [CGROUP_ROOT]"))?
        .to_string_lossy()
        .parse::<u32>()?;
    let output = args.next().map(PathBuf::from);
    let root = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| "/sys/fs/cgroup".into());
    anyhow::ensure!(args.next().is_none(), "unexpected argument");
    // SAFETY: process-local handler sets only a lock-free atomic.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = stop as *const () as usize;
        libc::sigemptyset(&mut action.sa_mask);
        if libc::sigaction(libc::SIGINT, &action, std::ptr::null_mut()) < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    let opened = open_session_with_options(uid, &OpenOptions { cgroup_root: root })?;
    let info = Client::system(Duration::from_secs(30))?.ensure_session_ready()?;
    if let Some(path) = output {
        let mut file = std::fs::File::create(path)?;
        writeln!(file, "{}\n{}", opened.sid, info.runtime_dir)?;
    } else {
        println!("sid={} runtime={}", opened.sid, info.runtime_dir);
    }
    while !STOP.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(100));
    }
    Client::system(Duration::from_secs(30))?.schedule_close_session(&opened.sid)?;
    Ok(())
}
