use clap::{Parser, ValueEnum};
use lib_sessiond::SessionCore;
use lib_sessiond::bus::{Bus, BusLifecycleEvents};
use lib_sessiond::config::Config;
use sessiond::scheduler::Scheduler;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;

static STOPPING: AtomicBool = AtomicBool::new(false);
extern "C" fn stop(_: libc::c_int) {
    STOPPING.store(true, Ordering::Relaxed);
}
#[derive(Clone, Copy, Debug, ValueEnum)]
enum BusChoice {
    System,
    Session,
}
impl From<BusChoice> for Bus {
    fn from(value: BusChoice) -> Self {
        match value {
            BusChoice::System => Bus::System,
            BusChoice::Session => Bus::Session,
        }
    }
}
#[derive(Debug, Parser)]
struct Args {
    #[arg(long, default_value = "/etc/sessiond.conf")]
    config: PathBuf,
    #[arg(long, value_enum, default_value = "system", hide = true)]
    bus: BusChoice,
}
fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "sessiond=info".into()),
        )
        .init();
    install_signals()?;
    let args = Args::parse();
    let config = if args.config.exists() {
        Config::load(&args.config)?
    } else {
        Config::default()
    };
    let bus = args.bus.into();
    let core =
        std::sync::Arc::new(SessionCore::new(config)?.with_events(BusLifecycleEvents::new(bus)));
    let scheduler = Scheduler::new(core);
    let (hint_sender, hint_receiver) = mpsc::sync_channel(1);
    let observer = sessiond::observation::start(scheduler.clone(), hint_receiver, &STOPPING)?;
    let result = sessiond::dbus::serve(bus, scheduler, hint_sender, &STOPPING);
    STOPPING.store(true, Ordering::Relaxed);
    let _ = observer.join();
    result
}
fn install_signals() -> std::io::Result<()> {
    // SAFETY: installed handlers only set a lock-free AtomicBool. This daemon
    // owns its process signal policy; no host application is affected.
    unsafe {
        for signal in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = stop as *const () as usize;
            libc::sigemptyset(&mut action.sa_mask);
            if libc::sigaction(signal, &action, std::ptr::null_mut()) < 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
    }
    Ok(())
}
