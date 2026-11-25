use clap::{Parser, ValueEnum};
use sessiond::{SessionCore, config::Config, locking::Singleton, scheduler::Scheduler};
use std::path::PathBuf;
use std::sync::Arc;
#[derive(Clone, Copy, Debug, ValueEnum)]
enum BusChoice {
    System,
    Session,
}
#[derive(Debug, Parser)]
struct Args {
    #[arg(long, default_value = "/etc/sessiond.conf")]
    config: PathBuf,
    #[arg(long, value_enum, default_value = "system", hide = true)]
    bus: BusChoice,
    #[arg(long, hide = true)]
    lookup_gid: Option<u32>,
}
fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    // A fresh exec'd NSS helper never constructs the daemon's runtime, bus or
    // global state and never calls NSS on a Tokio/blocking worker thread.
    if let Some(uid) = args.lookup_gid {
        use nix::unistd::{Uid, User};
        let user =
            User::from_uid(Uid::from_raw(uid))?.ok_or_else(|| anyhow::anyhow!("unknown UID"))?;
        println!("{}", user.gid.as_raw());
        return Ok(());
    }
    // SAFETY: daemon-only policy, before runtime/worker creation. Ignored
    // SIGCHLD survives exec; undo it to retain exclusive direct-child ownership.
    unsafe {
        anyhow::ensure!(libc::geteuid() == 0, "sessiond requires effective UID 0");
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = libc::SIG_DFL;
        libc::sigemptyset(&mut action.sa_mask);
        if libc::sigaction(libc::SIGCHLD, &action, std::ptr::null_mut()) < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "sessiond=info".into()),
        )
        .init();
    // Unexpected panics in any daemon worker are fatal bugs, not silent loss of
    // a fixed worker/UID lane. This changes only this daemon process's policy.
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic| {
        previous(panic);
        std::process::abort();
    }));
    let config = if args.config.exists() {
        Config::load(&args.config)?
    } else {
        Config::default()
    };
    let _lifetime = Singleton::acquire(&config.state_dir)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let (signals, receiver) = tokio::sync::mpsc::channel(128);
        let core = Arc::new(SessionCore::with_signals(config, signals)?);
        let scheduler = Scheduler::new(core);
        let result = sessiond::dbus::serve(
            matches!(args.bus, BusChoice::Session),
            scheduler.clone(),
            receiver,
        )
        .await;
        // Keep the lifetime lock held until every admitted effect has completed.
        // Grace deadlines are not reset; accepted cleanup remains owned here.
        scheduler.shutdown();
        result
    })
}
