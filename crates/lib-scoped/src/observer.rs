//! Caller-owned, one-shot blocking watches. No library threads or mutation.
use crate::linux::{identity, open_at, pin_identity, read_event_file, read_identity};
use crate::{
    Domain, Error, ProcessHandle, ProcessIdentity, Result, ScopeId, ScopeIdentity, TargetId,
};
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct TargetWatch {
    scope: ScopeId,
    target: TargetId,
    scope_identity: ScopeIdentity,
    process: ProcessIdentity,
    handle: Option<ProcessHandle>,
    // Keep the original cgroup instance pinned even if its path is reused.
    _directory: File,
}

impl TargetWatch {
    pub fn process_identity(&self) -> ProcessIdentity {
        self.process
    }
    pub fn scope_identity(&self) -> ScopeIdentity {
        self.scope_identity
    }
    pub fn exited(&self) -> Result<bool> {
        match &self.handle {
            Some(handle) => handle
                .is_alive()
                .map(|live| !live)
                .map_err(|e| Error::io("query watched process", e)),
            None => Ok(true),
        }
    }
    pub fn wait_timeout(&mut self, timeout: Duration) -> Result<bool> {
        wait_until(timeout, || self.exited(), || self.raw_fd(), libc::POLLIN)
    }
    fn raw_fd(&self) -> Option<RawFd> {
        self.handle
            .as_ref()
            .map(|handle| handle.as_fd().as_raw_fd())
    }
}

#[derive(Debug)]
pub struct ScopeWatch {
    scope: ScopeId,
    instance: ScopeIdentity,
    directory: Option<File>,
    events: Option<File>,
}

impl ScopeWatch {
    pub fn scope_identity(&self) -> ScopeIdentity {
        self.instance
    }
    pub fn empty(&mut self) -> Result<bool> {
        let Some(directory) = &self.directory else {
            return Ok(true);
        };
        if directory
            .metadata()
            .map_err(|e| Error::io("stat watched scope", e))?
            .nlink()
            == 0
        {
            return Ok(true);
        }
        match read_event_file(
            self.events
                .as_mut()
                .expect("directory has event descriptor"),
            "populated",
        ) {
            Ok(populated) => Ok(!populated),
            Err(original) => {
                // Descriptor errors alone do not establish disappearance.
                // An unlinked pinned directory cannot refer to a replacement.
                match directory.metadata() {
                    Ok(stat) if stat.nlink() == 0 => Ok(true),
                    _ => Err(Error::io("read watched cgroup.events", original)),
                }
            }
        }
    }
    pub fn wait_timeout(&mut self, timeout: Duration) -> Result<bool> {
        let deadline = deadline_after(timeout)?;
        loop {
            if self.empty()? {
                return Ok(true);
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return Ok(false);
            };
            let fd = self.events.as_ref().map(AsRawFd::as_raw_fd);
            wait_fd(fd, libc::POLLPRI, remaining)?;
            // Handles spurious/unchanged priority/error readiness without a spin.
            if self.empty()? {
                return Ok(true);
            }
            sleep_bounded(deadline);
        }
    }
}

impl Domain {
    pub fn watch_target(&self, scope: &ScopeId, target: &TargetId) -> Result<TargetWatch> {
        let directory = self.open_scope(scope)?;
        let process = read_identity(&directory, target)
            .map_err(|e| Error::io("read watched target", e))?
            .ok_or_else(|| Error::Untracked {
                scope: scope.clone(),
                target: target.clone(),
            })?;
        let scope_identity =
            identity(&directory).map_err(|e| Error::io("stat watched scope", e))?;
        let handle = pin_identity(process).map_err(|e| Error::io("pin watched process", e))?;
        Ok(TargetWatch {
            scope: scope.clone(),
            target: target.clone(),
            scope_identity,
            process,
            handle,
            _directory: directory,
        })
    }

    pub fn watch_scope(&self, scope: &ScopeId) -> Result<ScopeWatch> {
        let directory = match self.open_scope(scope) {
            Ok(dir) => dir,
            Err(e) if e.is_not_found() => {
                return Ok(ScopeWatch {
                    scope: scope.clone(),
                    instance: ScopeIdentity {
                        device: 0,
                        inode: 0,
                    },
                    directory: None,
                    events: None,
                });
            }
            Err(e) => return Err(e),
        };
        let instance = identity(&directory).map_err(|e| Error::io("stat watched scope", e))?;
        let events = open_at(&directory, "cgroup.events", libc::O_RDONLY)
            .map_err(|e| Error::io("open watched cgroup.events", e))?;
        Ok(ScopeWatch {
            scope: scope.clone(),
            instance,
            directory: Some(directory),
            events: Some(events),
        })
    }
}

#[derive(Debug)]
pub enum Watch {
    Target(TargetWatch),
    Scope(ScopeWatch),
}
impl From<TargetWatch> for Watch {
    fn from(watch: TargetWatch) -> Self {
        Self::Target(watch)
    }
}
impl From<ScopeWatch> for Watch {
    fn from(watch: ScopeWatch) -> Self {
        Self::Scope(watch)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    TargetExited,
    ScopeEmpty,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub token: u64,
    pub kind: EventKind,
    pub scope: ScopeId,
    pub scope_identity: ScopeIdentity,
    pub target: Option<TargetId>,
    pub process_identity: Option<ProcessIdentity>,
}

struct Entry {
    token: u64,
    watch: Watch,
    delivered: bool,
}

/// Multi-watch observer. Callers send commands through their own channels and
/// use ObserverControl to interrupt polling. Watches report their initial state
/// once, then at most one completion; no implicit rearm or garbage collection.
pub struct Observer {
    wake: File,
    entries: Vec<Entry>,
    next_token: u64,
}

pub struct ObserverControl {
    wake: File,
}
impl ObserverControl {
    pub fn wake(&self) -> Result<()> {
        let value: u64 = 1;
        // SAFETY: live eventfd and correctly sized readable integer buffer.
        let n = unsafe { libc::write(self.wake.as_raw_fd(), (&value as *const u64).cast(), 8) };
        if n == 8 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::WouldBlock {
            Ok(())
        } else {
            Err(Error::io("wake observer", error))
        }
    }
}

impl Observer {
    pub fn new() -> Result<Self> {
        // SAFETY: eventfd has no pointer arguments; ownership checked below.
        let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if fd < 0 {
            return Err(Error::io(
                "create observer control",
                io::Error::last_os_error(),
            ));
        }
        // SAFETY: eventfd returned a fresh owned descriptor.
        let wake = unsafe { File::from_raw_fd(fd) };
        Ok(Self {
            wake,
            entries: Vec::new(),
            next_token: 1,
        })
    }
    pub fn control(&self) -> Result<ObserverControl> {
        Ok(ObserverControl {
            wake: self
                .wake
                .try_clone()
                .map_err(|e| Error::io("duplicate observer control", e))?,
        })
    }
    pub fn add(&mut self, watch: impl Into<Watch>) -> u64 {
        let token = self.next_token;
        self.next_token = self
            .next_token
            .checked_add(1)
            .expect("observer token space exhausted");
        self.entries.push(Entry {
            token,
            watch: watch.into(),
            delivered: false,
        });
        token
    }
    pub fn remove(&mut self, token: u64) -> bool {
        let before = self.entries.len();
        self.entries.retain(|e| e.token != token);
        before != self.entries.len()
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn wait(&mut self, timeout: Duration) -> Result<Vec<Event>> {
        let deadline = deadline_after(timeout)?;
        loop {
            let events = self.collect()?;
            if !events.is_empty() {
                return Ok(events);
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return Ok(Vec::new());
            };
            let mut fds = vec![libc::pollfd {
                fd: self.wake.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            }];
            for entry in self.entries.iter().filter(|e| !e.delivered) {
                match &entry.watch {
                    Watch::Target(watch) => {
                        if let Some(fd) = watch.raw_fd() {
                            fds.push(libc::pollfd {
                                fd,
                                events: libc::POLLIN,
                                revents: 0,
                            });
                        }
                    }
                    Watch::Scope(watch) => {
                        if let Some(events) = &watch.events {
                            fds.push(libc::pollfd {
                                fd: events.as_raw_fd(),
                                events: libc::POLLPRI,
                                revents: 0,
                            });
                        }
                    }
                }
            }
            poll(&mut fds, remaining)?;
            if fds[0].revents & libc::POLLIN != 0 {
                let mut value: u64 = 0;
                // SAFETY: live eventfd and correctly sized writable buffer.
                let n = unsafe {
                    libc::read(self.wake.as_raw_fd(), (&mut value as *mut u64).cast(), 8)
                };
                if n < 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() != io::ErrorKind::WouldBlock {
                        return Err(Error::io("read observer control", error));
                    }
                }
                return self.collect();
            }
            let events = self.collect()?;
            if !events.is_empty() {
                return Ok(events);
            }
            sleep_bounded(deadline);
        }
    }

    fn collect(&mut self) -> Result<Vec<Event>> {
        let mut events = Vec::new();
        let mut completed = Vec::new();
        for (index, entry) in self
            .entries
            .iter_mut()
            .enumerate()
            .filter(|(_, e)| !e.delivered)
        {
            let ready = match &mut entry.watch {
                Watch::Target(watch) => watch.exited(),
                Watch::Scope(watch) => watch.empty(),
            }
            .map_err(|source| Error::Watch {
                token: entry.token,
                source: Box::new(source),
            })?;
            if !ready {
                continue;
            }
            let event = match &entry.watch {
                Watch::Target(watch) => Event {
                    token: entry.token,
                    kind: EventKind::TargetExited,
                    scope: watch.scope.clone(),
                    scope_identity: watch.scope_identity,
                    target: Some(watch.target.clone()),
                    process_identity: Some(watch.process),
                },
                Watch::Scope(watch) => Event {
                    token: entry.token,
                    kind: EventKind::ScopeEmpty,
                    scope: watch.scope.clone(),
                    scope_identity: watch.instance,
                    target: None,
                    process_identity: None,
                },
            };
            completed.push(index);
            events.push(event);
        }
        // Commit delivery only once every query succeeded. A failure in one
        // watch must not silently consume another watch's completion. The
        // error identifies the bad token so callers can remove only that watch.
        for index in completed {
            self.entries[index].delivered = true;
        }
        Ok(events)
    }
}

fn deadline_after(timeout: Duration) -> Result<Instant> {
    Instant::now().checked_add(timeout).ok_or_else(|| {
        Error::io(
            "watch deadline",
            io::Error::new(io::ErrorKind::InvalidInput, "deadline overflow"),
        )
    })
}
fn wait_until(
    timeout: Duration,
    ready: impl Fn() -> Result<bool>,
    fd: impl Fn() -> Option<RawFd>,
    flags: i16,
) -> Result<bool> {
    let deadline = deadline_after(timeout)?;
    loop {
        if ready()? {
            return Ok(true);
        }
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return Ok(false);
        };
        wait_fd(fd(), flags, remaining)?;
        if ready()? {
            return Ok(true);
        }
        sleep_bounded(deadline);
    }
}
fn wait_fd(fd: Option<RawFd>, flags: i16, timeout: Duration) -> Result<()> {
    let mut fds = match fd {
        Some(fd) => vec![libc::pollfd {
            fd,
            events: flags,
            revents: 0,
        }],
        None => Vec::new(),
    };
    poll(&mut fds, timeout)
}
fn poll(fds: &mut [libc::pollfd], timeout: Duration) -> Result<()> {
    // Round up sub-millisecond budgets; callers recheck their monotonic deadline.
    let millis = timeout
        .as_millis()
        .saturating_add(u128::from(
            !timeout.subsec_nanos().is_multiple_of(1_000_000),
        ))
        .min(i32::MAX as u128) as i32;
    // SAFETY: poll receives a valid mutable slice and does not retain pointers.
    let result = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, millis) };
    if result < 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(Error::io("poll observation", error));
        }
    }
    if fds.iter().any(|fd| fd.revents & libc::POLLNVAL != 0) {
        return Err(Error::io(
            "poll observation",
            io::Error::new(io::ErrorKind::InvalidInput, "invalid watch descriptor"),
        ));
    }
    Ok(())
}
fn sleep_bounded(deadline: Instant) {
    if let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        std::thread::sleep(remaining.min(Duration::from_millis(5)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::process::Command;

    fn fixture() -> (tempfile::TempDir, Domain, ScopeId) {
        let root = tempfile::tempdir().unwrap();
        let domain = Domain::create(root.path(), "test").unwrap();
        let scope = ScopeId::parse("test/a").unwrap();
        domain.create_scope(&scope).unwrap();
        fs::write(
            root.path().join("test/a/cgroup.events"),
            "populated 0\nfrozen 0\n",
        )
        .unwrap();
        (root, domain, scope)
    }

    #[test]
    fn already_empty_and_missing_return_immediately() {
        let (_root, domain, scope) = fixture();
        assert!(
            domain
                .watch_scope(&scope)
                .unwrap()
                .wait_timeout(Duration::ZERO)
                .unwrap()
        );
        assert!(
            domain
                .watch_scope(&ScopeId::parse("test/missing").unwrap())
                .unwrap()
                .wait_timeout(Duration::ZERO)
                .unwrap()
        );
    }
    #[test]
    fn existing_scope_without_event_file_is_an_error() {
        let (root, domain, scope) = fixture();
        fs::remove_file(root.path().join("test/a/cgroup.events")).unwrap();
        assert!(domain.watch_scope(&scope).is_err());
    }
    #[test]
    fn old_scope_watch_does_not_attach_to_replacement() {
        let (root, domain, scope) = fixture();
        let mut watch = domain.watch_scope(&scope).unwrap();
        let old = watch.scope_identity();
        fs::remove_file(root.path().join("test/a/cgroup.events")).unwrap();
        domain.remove_scope(&scope).unwrap();
        domain.create_scope(&scope).unwrap();
        fs::write(
            root.path().join("test/a/cgroup.events"),
            "populated 1\nfrozen 0\n",
        )
        .unwrap();
        assert_ne!(Some(old), domain.scope_identity(&scope).unwrap());
        assert!(watch.wait_timeout(Duration::ZERO).unwrap());
        assert!(
            !domain
                .watch_scope(&scope)
                .unwrap()
                .wait_timeout(Duration::ZERO)
                .unwrap()
        );
    }
    #[test]
    fn observer_delivers_initial_completion_only_once() {
        let (_root, domain, scope) = fixture();
        let mut observer = Observer::new().unwrap();
        let token = observer.add(domain.watch_scope(&scope).unwrap());
        let events = observer.wait(Duration::ZERO).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, EventKind::ScopeEmpty);
        assert_eq!(events[0].token, token);
        assert!(observer.wait(Duration::from_millis(5)).unwrap().is_empty());
        assert!(observer.remove(token));
        assert!(observer.is_empty());
    }
    #[test]
    fn one_watch_error_does_not_consume_other_completions() {
        let (root, domain, scope) = fixture();
        let other = ScopeId::parse("test/b").unwrap();
        domain.create_scope(&other).unwrap();
        let events_path = root.path().join("test/b/cgroup.events");
        fs::write(&events_path, "invalid\n").unwrap();
        let mut observer = Observer::new().unwrap();
        let good = observer.add(domain.watch_scope(&scope).unwrap());
        let bad = observer.add(domain.watch_scope(&other).unwrap());
        assert!(
            matches!(observer.wait(Duration::ZERO), Err(Error::Watch { token, .. }) if token == bad)
        );
        observer.remove(bad);
        let events = observer.wait(Duration::ZERO).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].token, good);
    }
    #[test]
    fn observer_can_be_woken_by_caller_owned_thread() {
        let mut observer = Observer::new().unwrap();
        let control = observer.control().unwrap();
        let thread = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            control.wake().unwrap();
        });
        let start = Instant::now();
        assert!(observer.wait(Duration::from_secs(5)).unwrap().is_empty());
        assert!(start.elapsed() < Duration::from_secs(1));
        thread.join().unwrap();
    }
    #[test]
    fn process_watch_means_actual_exit_without_membership_rechecks() {
        let (_root, domain, scope) = fixture();
        let mut child = Command::new("sleep").arg("60").spawn().unwrap();
        let handle = ProcessHandle::open(child.id()).unwrap();
        let directory = domain.open_scope(&scope).unwrap();
        let instance = identity(&directory).unwrap();
        let mut watch = TargetWatch {
            scope,
            target: TargetId::parse("leader").unwrap(),
            scope_identity: instance,
            process: handle.identity(),
            handle: Some(handle),
            _directory: directory,
        };
        // The process is outside the fixture's scope; that is not an exit.
        assert!(!watch.wait_timeout(Duration::ZERO).unwrap());
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(watch.wait_timeout(Duration::from_secs(1)).unwrap());
    }
}
