use async_trait::async_trait;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use crate::scoped::ScopedApi;

pub const USER_SERVICE_MANAGER: &str = match option_env!("SESSIOND_USER_SERVICE_MANAGER") {
    Some(path) => path,
    None => "/usr/libexec/user-service-manager",
};

#[async_trait]
pub trait UserManagerLauncher: Send + Sync {
    async fn start(&self, uid: u32, runtime: &Path, scope: &str) -> anyhow::Result<()>;
}

pub struct RealLauncher {
    scoped: Arc<dyn ScopedApi>,
    launcher: PathBuf,
    ready_timeout: Duration,
}

impl RealLauncher {
    pub fn new(scoped: Arc<dyn ScopedApi>, launcher: PathBuf, ready_timeout: Duration) -> Self {
        Self {
            scoped,
            launcher,
            ready_timeout,
        }
    }
}

#[async_trait]
impl UserManagerLauncher for RealLauncher {
    async fn start(&self, uid: u32, runtime: &Path, scope: &str) -> anyhow::Result<()> {
        let (mut gate_parent, gate_child) = UnixStream::pair()?;
        let (mut ready_parent, ready_child) = UnixStream::pair()?;
        let gate_fd = gate_child.as_raw_fd();
        let ready_fd = ready_child.as_raw_fd();
        let mut command = Command::new(&self.launcher);
        command
            .arg("--uid")
            .arg(uid.to_string())
            .arg("--runtime-dir")
            .arg(runtime)
            .arg("--entrypoint")
            .arg(USER_SERVICE_MANAGER);
        // SAFETY: this closure invokes only async-signal-safe dup2 between fork
        // and exec. All allocation and argument construction happened above.
        unsafe {
            command.pre_exec(move || {
                if libc::dup2(gate_fd, 3) == -1
                    || libc::fcntl(3, libc::F_SETFD, 0) == -1
                    || libc::dup2(ready_fd, 4) == -1
                    || libc::fcntl(4, libc::F_SETFD, 0) == -1
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn()?;
        drop(gate_child);
        drop(ready_child);
        let pid = child.id();

        if let Err(error) = self.scoped.move_pid(pid, scope, "manager").await {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error.into());
        }
        gate_parent.write_all(&[1])?;
        drop(gate_parent);

        let timeout = self.ready_timeout;
        let ready = tokio::task::spawn_blocking(move || {
            ready_parent.set_read_timeout(Some(timeout))?;
            let mut byte = [0];
            ready_parent.read_exact(&mut byte)?;
            anyhow::ensure!(byte[0] == 1, "invalid launcher readiness byte");
            anyhow::Ok(())
        })
        .await?;
        if let Err(error) = ready {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }

        tokio::task::spawn_blocking(move || match child.wait() {
            Ok(status) if status.success() => {
                tracing::info!(pid, %status, "user manager launcher exited")
            }
            Ok(status) => tracing::warn!(pid, %status, "user manager launcher exited unexpectedly"),
            Err(error) => tracing::warn!(pid, %error, "could not reap user manager launcher"),
        });
        Ok(())
    }
}
