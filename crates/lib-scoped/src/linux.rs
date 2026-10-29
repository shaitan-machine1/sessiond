use crate::{
    Error, Pid, ProcessHandle, ProcessIdentity, Result, ScopeId, TargetId, TargetStatus,
    read_start_time, validate_segment,
};
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

const TARGET_PREFIX: &str = "user.scoped.target.";
const FREEZE_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScopeIdentity {
    pub device: u64,
    pub inode: u64,
}

pub(crate) fn identity(dir: &File) -> io::Result<ScopeIdentity> {
    let stat = dir.metadata()?;
    Ok(ScopeIdentity {
        device: stat.dev(),
        inode: stat.ino(),
    })
}

/// A pinned domain root. Construction never creates it implicitly.
/// Every public scope ID includes this domain's name.
#[derive(Debug, Clone)]
pub struct Domain {
    pub(crate) root: Arc<File>,
    name: String,
    proc_prefix: String,
}

impl Domain {
    pub fn open(cgroup_root: impl AsRef<Path>, name: &str) -> Result<Self> {
        validate_segment(name)?;
        let mount =
            open_directory(cgroup_root.as_ref()).map_err(|e| Error::io("open cgroup root", e))?;
        let root = open_at(&mount, name, libc::O_RDONLY | libc::O_DIRECTORY).map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                Error::DomainNotFound(name.to_owned())
            } else {
                Error::io(format!("open domain {name}"), e)
            }
        })?;
        let prefix = cgroup_prefix(cgroup_root.as_ref())
            .map_err(|e| Error::io("resolve cgroup mount", e))?;
        Ok(Self {
            root: Arc::new(root),
            name: name.to_owned(),
            proc_prefix: format!("{prefix}/{name}"),
        })
    }

    /// Explicitly creates one domain, accepting an existing directory. Does
    /// not create missing ancestors, claim another domain, or remove anything.
    pub fn create(cgroup_root: impl AsRef<Path>, name: &str) -> Result<Self> {
        validate_segment(name)?;
        let mount =
            open_directory(cgroup_root.as_ref()).map_err(|e| Error::io("open cgroup root", e))?;
        match mkdir_at(&mount, name) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(Error::io(format!("create domain {name}"), e)),
        }
        Self::open(cgroup_root, name)
    }

    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn root_id(&self) -> ScopeId {
        ScopeId::parse(&self.name).expect("validated domain")
    }

    fn relative<'a>(&self, scope: &'a ScopeId) -> Result<&'a str> {
        let root = self.root_id();
        scope
            .strip_prefix(&root)
            .ok_or_else(|| Error::OutsideDomain {
                scope: scope.clone(),
                domain: self.name.clone(),
            })
    }

    pub(crate) fn open_scope(&self, scope: &ScopeId) -> Result<File> {
        let relative = self.relative(scope)?;
        ensure_linked(&self.root)?;
        let mut dir = self
            .root
            .try_clone()
            .map_err(|e| Error::io("duplicate domain descriptor", e))?;
        for segment in relative.split('/').filter(|s| !s.is_empty()) {
            dir = open_at(&dir, segment, libc::O_RDONLY | libc::O_DIRECTORY)
                .map_err(|e| Error::io(format!("open scope {scope}"), e))?;
        }
        Ok(dir)
    }

    fn parent(&self, scope: &ScopeId) -> Result<(File, String)> {
        self.relative(scope)?;
        if scope == &self.root_id() {
            return Err(Error::DomainRoot);
        }
        let parent = scope.parent().ok_or(Error::DomainRoot)?;
        Ok((
            self.open_scope(&parent)?,
            scope
                .segments()
                .next_back()
                .expect("nonempty ID")
                .to_owned(),
        ))
    }

    pub fn scope_identity(&self, scope: &ScopeId) -> Result<Option<ScopeIdentity>> {
        match self.open_scope(scope) {
            Ok(dir) => identity(&dir)
                .map(Some)
                .map_err(|e| Error::io("stat scope", e)),
            Err(e) if e.is_not_found() => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn create_scope(&self, scope: &ScopeId) -> Result<()> {
        let (parent, name) = self.parent(scope)?;
        mkdir_at(&parent, &name).map_err(|e| Error::io(format!("create scope {scope}"), e))
    }

    /// Exactly one rmdir. The kernel rejects populated/non-leaf cgroups.
    pub fn remove_scope(&self, scope: &ScopeId) -> Result<()> {
        let (parent, name) = match self.parent(scope) {
            Ok(v) => v,
            Err(e) if e.is_not_found() => return Ok(()),
            Err(e) => return Err(e),
        };
        let name = cstring(&name).map_err(|e| Error::io("scope name", e))?;
        // SAFETY: valid pinned directory descriptor and NUL-terminated name.
        let result =
            unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) };
        if result == 0 {
            return Ok(());
        }
        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::NotFound {
            Ok(())
        } else {
            Err(Error::io(format!("remove scope {scope}"), e))
        }
    }

    /// Pin a scope generation across coordination or other caller-owned steps.
    /// This is a descriptor, not a transaction lock; it never follows a
    /// replacement at the same path. No process handle is acquired.
    pub fn pin_scope(&self, scope: &ScopeId) -> Result<ScopeHandle> {
        let directory = self.open_scope(scope)?;
        let instance = identity_of(&directory)?;
        Ok(ScopeHandle {
            domain: self.clone(),
            scope: scope.clone(),
            directory,
            instance,
        })
    }

    /// Numeric-PID movement only. Caller controls lifetime/PID-reuse races.
    pub fn move_process(&self, scope: &ScopeId, pid: Pid) -> Result<()> {
        self.pin_scope(scope)?.move_process(pid)
    }

    pub fn scope_of(&self, pid: Pid) -> Result<Option<ScopeId>> {
        valid_pid(pid).map_err(|e| Error::io("scope_of", e))?;
        let path = format!("/proc/{pid}/cgroup");
        let content =
            fs::read_to_string(&path).map_err(|e| Error::io(format!("read {path}"), e))?;
        let path = content
            .lines()
            .find_map(|s| s.strip_prefix("0::"))
            .ok_or_else(|| {
                Error::io(
                    "read unified cgroup membership",
                    io::Error::new(io::ErrorKind::Unsupported, "no cgroup v2 membership"),
                )
            })?;
        if path == self.proc_prefix {
            return Ok(Some(self.root_id()));
        }
        let Some(relative) = path.strip_prefix(&format!("{}/", self.proc_prefix)) else {
            return Ok(None);
        };
        Ok(Some(ScopeId::parse(format!("{}/{relative}", self.name))?))
    }

    pub fn list_scopes(&self, prefix: &ScopeId) -> Result<Vec<ScopeId>> {
        let dir = match self.open_scope(prefix) {
            Ok(dir) => dir,
            Err(e) if e.is_not_found() => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let mut out = Vec::new();
        walk(&dir, prefix, &mut out)?;
        out.sort();
        Ok(out)
    }

    /// Enumerate one level without traversing session/service descendants.
    pub fn list_children(&self, prefix: &ScopeId) -> Result<Vec<ScopeId>> {
        let dir = match self.open_scope(prefix) {
            Ok(dir) => dir,
            Err(e) if e.is_not_found() => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        child_dirs(&dir)?
            .into_iter()
            .map(|name| prefix.join(name).map_err(Error::from))
            .collect()
    }

    /// Read-only, without pidfds or liveness probes.
    pub fn read_target_identity(
        &self,
        scope: &ScopeId,
        target: &TargetId,
    ) -> Result<Option<ProcessIdentity>> {
        let dir = match self.open_scope(scope) {
            Ok(dir) => dir,
            Err(e) if e.is_not_found() => return Ok(None),
            Err(e) => return Err(e),
        };
        read_identity(&dir, target)
            .map_err(|e| Error::io(format!("read target {target} in {scope}"), e))
    }

    /// Capture identity without a pidfd and publish via kernel XATTR_CREATE.
    /// Caller controls process lifetime across move/assignment.
    pub fn assign_target(&self, scope: &ScopeId, target: &TargetId, pid: Pid) -> Result<()> {
        self.pin_scope(scope)?.assign_target(target, pid)
    }

    fn assign_in(&self, dir: &File, scope: &ScopeId, target: &TargetId, pid: Pid) -> Result<()> {
        ensure_linked(dir)?;
        let start_time =
            read_start_time(pid).map_err(|e| Error::io("capture target identity", e))?;
        if self.scope_of(pid)?.as_ref() != Some(scope) {
            return Err(Error::Membership {
                scope: scope.clone(),
                pid,
            });
        }
        if read_start_time(pid).map_err(|e| Error::io("recheck target identity", e))? != start_time
        {
            return Err(Error::io(
                "assign target",
                io::Error::new(io::ErrorKind::NotFound, "process instance changed"),
            ));
        }
        let record = encode_identity(ProcessIdentity { pid, start_time });
        let name = target_name(target);
        // SAFETY: descriptor, C name and byte buffer remain live for the call.
        let result = unsafe {
            libc::fsetxattr(
                dir.as_raw_fd(),
                name.as_ptr(),
                record.as_ptr().cast(),
                record.len(),
                libc::XATTR_CREATE,
            )
        };
        if result == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::AlreadyExists {
            Err(Error::TargetExists {
                scope: scope.clone(),
                target: target.clone(),
            })
        } else {
            Err(Error::io(
                format!("assign target {target} in {scope}"),
                error,
            ))
        }
    }

    pub fn remove_target(&self, scope: &ScopeId, target: &TargetId) -> Result<()> {
        let dir = match self.open_scope(scope) {
            Ok(dir) => dir,
            Err(e) if e.is_not_found() => return Ok(()),
            Err(e) => return Err(e),
        };
        let name = target_name(target);
        // SAFETY: pinned descriptor and valid C name.
        if unsafe { libc::fremovexattr(dir.as_raw_fd(), name.as_ptr()) } == 0 {
            return Ok(());
        }
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ENODATA) {
            Ok(())
        } else {
            Err(Error::io(format!("remove target {target} in {scope}"), e))
        }
    }

    pub fn list_targets(&self, scope: &ScopeId) -> Result<Vec<TargetId>> {
        let dir = self.open_scope(scope)?;
        let bytes = read_xattr_names(&dir).map_err(|e| Error::io("list target records", e))?;
        let mut targets = Vec::new();
        for raw in bytes.split(|b| *b == 0).filter(|s| !s.is_empty()) {
            let raw = std::str::from_utf8(raw).map_err(|e| {
                Error::io(
                    "decode xattr name",
                    io::Error::new(io::ErrorKind::InvalidData, e),
                )
            })?;
            if let Some(name) = raw.strip_prefix(TARGET_PREFIX) {
                targets.push(TargetId::parse(name)?);
            }
        }
        targets.sort();
        Ok(targets)
    }

    /// Process existence only. Membership is checked separately for signalling.
    pub fn target_status(&self, scope: &ScopeId, target: &TargetId) -> Result<TargetStatus> {
        let Some(identity) = self.read_target_identity(scope, target)? else {
            return Ok(TargetStatus::Untracked);
        };
        Ok(
            match pin_identity(identity).map_err(|e| Error::io("query tracked process", e))? {
                Some(_) => TargetStatus::Running(identity),
                None => TargetStatus::Exited(identity),
            },
        )
    }

    pub fn target_exists(&self, scope: &ScopeId, target: &TargetId) -> Result<bool> {
        let Some(expected) = self.read_target_identity(scope, target)? else {
            return Ok(false);
        };
        let Some(handle) = pin_identity(expected).map_err(|e| Error::io("pin target query", e))?
        else {
            return Ok(false);
        };
        match self.scope_of(expected.pid) {
            Ok(Some(actual)) if actual == *scope => handle
                .is_alive()
                .map_err(|e| Error::io("recheck target query", e)),
            Ok(_) => Ok(false),
            Err(e) if e.is_not_found() => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn signal_target(&self, scope: &ScopeId, target: &TargetId, kill: bool) -> Result<()> {
        let dir = self.open_scope(scope)?;
        let identity = read_identity(&dir, target)
            .map_err(|e| Error::io("read signal target", e))?
            .ok_or_else(|| Error::Untracked {
                scope: scope.clone(),
                target: target.clone(),
            })?;
        let Some(handle) = pin_identity(identity).map_err(|e| Error::io("pin signal target", e))?
        else {
            return Ok(());
        };
        match self.scope_of(identity.pid) {
            Ok(Some(actual)) if actual == *scope => {}
            Err(e) if e.is_not_found() => return Ok(()),
            Err(e) => return Err(e),
            _ => {
                return Err(Error::Membership {
                    scope: scope.clone(),
                    pid: identity.pid,
                });
            }
        }
        // If the path was replaced while checking membership, do not signal a
        // process associated with a different scope generation.
        if self.scope_identity(scope)? != Some(identity_of(&dir)?) {
            return Err(Error::io(
                "validate signal scope instance",
                io::Error::new(io::ErrorKind::NotFound, "scope instance changed"),
            ));
        }
        let result = if kill {
            handle.send_kill()
        } else {
            handle.send_terminate()
        };
        match result {
            Err(e) if e.raw_os_error() == Some(libc::ESRCH) => Ok(()),
            result => result.map_err(|e| Error::io("signal tracked process", e)),
        }
    }

    pub fn terminate_target(&self, scope: &ScopeId, target: &TargetId) -> Result<()> {
        self.signal_target(scope, target, false)
    }
    pub fn kill_target(&self, scope: &ScopeId, target: &TargetId) -> Result<()> {
        self.signal_target(scope, target, true)
    }

    pub fn scope_populated(&self, scope: &ScopeId) -> Result<bool> {
        let dir = match self.open_scope(scope) {
            Ok(dir) => dir,
            Err(e) if e.is_not_found() => return Ok(false),
            Err(e) => return Err(e),
        };
        // A missing control file on an existing scope is NOT an absent scope.
        read_event(&dir, "populated")
            .map_err(|e| Error::io(format!("query population of {scope}"), e))
    }

    pub fn kill_scope(&self, scope: &ScopeId) -> Result<()> {
        let dir = match self.open_scope(scope) {
            Ok(dir) => dir,
            Err(e) if e.is_not_found() => return Ok(()),
            Err(e) => return Err(e),
        };
        write_control(&dir, "cgroup.kill", "1")
            .map_err(|e| Error::io(format!("kill scope {scope}"), e))
    }

    pub fn terminate_scope(&self, scope: &ScopeId) -> Result<()> {
        if self
            .scope_of(std::process::id())?
            .is_some_and(|s| s.is_or_is_under(scope))
        {
            return Err(Error::SelfFreeze);
        }
        let root = match self.open_scope(scope) {
            Ok(dir) => dir,
            Err(e) if e.is_not_found() => return Ok(()),
            Err(e) => return Err(e),
        };
        let operation = (|| {
            write_control(&root, "cgroup.freeze", "1")
                .map_err(|e| Error::io("request freeze", e))?;
            let deadline = Instant::now() + FREEZE_TIMEOUT;
            while !read_event(&root, "frozen").map_err(|e| Error::io("confirm freeze", e))? {
                if Instant::now() >= deadline {
                    return Err(Error::io(
                        "confirm freeze",
                        io::Error::new(
                            io::ErrorKind::TimedOut,
                            "one-second freeze deadline exceeded",
                        ),
                    ));
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            let mut scopes = vec![(
                scope.clone(),
                root.try_clone()
                    .map_err(|e| Error::io("duplicate scope descriptor", e))?,
            )];
            collect_dirs(&root, scope, &mut scopes)?;
            let mut handles = Vec::new();
            for (_, dir) in scopes {
                let contents = read_control(&dir, "cgroup.procs")
                    .map_err(|e| Error::io("read frozen members", e))?;
                for raw in contents.split_whitespace() {
                    let pid: Pid = raw.parse().map_err(|e| {
                        Error::io(
                            "parse frozen member PID",
                            io::Error::new(io::ErrorKind::InvalidData, e),
                        )
                    })?;
                    let handle = match ProcessHandle::open(pid) {
                        Ok(handle) => handle,
                        Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                        Err(e) => return Err(Error::io("pin frozen member", e)),
                    };
                    // Frozen tasks can still be killed externally. A PID read
                    // before exit must never authorize signalling its reuse.
                    match self.scope_of(pid) {
                        Ok(Some(actual)) if actual.is_or_is_under(scope) => handles.push(handle),
                        Err(e) if e.is_not_found() => {}
                        Err(e) => return Err(e),
                        _ => {
                            return Err(Error::Membership {
                                scope: scope.clone(),
                                pid,
                            });
                        }
                    }
                }
            }
            for handle in handles {
                match handle.send_terminate() {
                    Ok(()) => {}
                    Err(e) if e.raw_os_error() == Some(libc::ESRCH) => {}
                    Err(e) => return Err(Error::io("terminate frozen member", e)),
                }
            }
            Ok(())
        })();
        // Ordinary errors, including a failed freeze request, always attempt
        // thaw. Process death is intentionally not recoverable by an RAII promise.
        let thaw =
            write_control(&root, "cgroup.freeze", "0").map_err(|e| Error::io("thaw scope", e));
        match (operation, thaw) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(e), Ok(())) | (Ok(()), Err(e)) => Err(e),
            (Err(primary), Err(thaw)) => Err(Error::Thaw {
                operation: format!("terminate {scope}"),
                primary: Box::new(primary),
                thaw: Box::new(thaw),
            }),
        }
    }
}

/// One opened scope instance. Move/assignment have the same semantics as on
/// Domain, but retain this generation instead of resolving a path again.
#[derive(Debug)]
pub struct ScopeHandle {
    domain: Domain,
    scope: ScopeId,
    directory: File,
    instance: ScopeIdentity,
}
impl ScopeHandle {
    pub fn id(&self) -> &ScopeId {
        &self.scope
    }
    pub fn identity(&self) -> ScopeIdentity {
        self.instance
    }
    pub fn move_process(&self, pid: Pid) -> Result<()> {
        valid_pid(pid).map_err(|e| Error::io("move process", e))?;
        ensure_linked(&self.directory)?;
        write_control(&self.directory, "cgroup.procs", &format!("{pid}\n"))
            .map_err(|e| Error::io(format!("move process {pid} into {}", self.scope), e))
    }
    pub fn assign_target(&self, target: &TargetId, pid: Pid) -> Result<()> {
        self.domain
            .assign_in(&self.directory, &self.scope, target, pid)
    }
}
fn ensure_linked(dir: &File) -> Result<()> {
    let metadata = dir
        .metadata()
        .map_err(|e| Error::io("stat scope instance", e))?;
    if metadata.nlink() == 0 {
        Err(Error::io(
            "access removed scope instance",
            io::Error::new(io::ErrorKind::NotFound, "scope instance was removed"),
        ))
    } else {
        Ok(())
    }
}

fn identity_of(dir: &File) -> Result<ScopeIdentity> {
    identity(dir).map_err(|e| Error::io("stat scope instance", e))
}

pub(crate) fn pin_identity(expected: ProcessIdentity) -> io::Result<Option<ProcessHandle>> {
    match ProcessHandle::open(expected.pid) {
        Ok(handle) if handle.identity() == expected => Ok(Some(handle)),
        Ok(_) => Ok(None),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

pub(crate) fn open_at(dir: &File, name: &str, flags: i32) -> io::Result<File> {
    let name = cstring(name)?;
    // SAFETY: pinned directory, valid C name, no O_CREAT, checked return value.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful openat transferred ownership of this descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn open_directory(path: &Path) -> io::Result<File> {
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

fn cstring(value: &str) -> io::Result<CString> {
    CString::new(value).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
}
fn valid_pid(pid: Pid) -> io::Result<()> {
    if pid == 0 || pid > i32::MAX as u32 {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "PID must be positive and fit pid_t",
        ))
    } else {
        Ok(())
    }
}
fn mkdir_at(dir: &File, name: &str) -> io::Result<()> {
    let name = cstring(name)?;
    // SAFETY: valid directory descriptor and name.
    if unsafe { libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), 0o755) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
pub(crate) fn read_control(dir: &File, name: &str) -> io::Result<String> {
    let mut file = open_at(dir, name, libc::O_RDONLY)?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    Ok(content)
}
fn write_control(dir: &File, name: &str, value: &str) -> io::Result<()> {
    let mut file = open_at(dir, name, libc::O_WRONLY)?;
    loop {
        match file.write(value.as_bytes()) {
            Ok(n) if n == value.len() => return Ok(()),
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "partial cgroup control write",
                ));
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}

pub(crate) fn read_event_file(file: &mut File, key: &str) -> io::Result<bool> {
    file.seek(SeekFrom::Start(0))?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    parse_event(&content, key)
}
fn read_event(dir: &File, key: &str) -> io::Result<bool> {
    read_event_file(&mut open_at(dir, "cgroup.events", libc::O_RDONLY)?, key)
}
fn parse_event(content: &str, key: &str) -> io::Result<bool> {
    for line in content.lines() {
        let mut fields = line.split_whitespace();
        if fields.next() == Some(key) {
            return match (fields.next(), fields.next()) {
                (Some("0"), None) => Ok(false),
                (Some("1"), None) => Ok(true),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid cgroup.events {key}"),
                )),
            };
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("missing cgroup.events {key}"),
    ))
}

fn child_dirs(dir: &File) -> Result<Vec<String>> {
    let mut names = Vec::new();
    // /proc/self/fd refers to the pinned directory, not a replaceable scope path.
    for entry in fs::read_dir(format!("/proc/self/fd/{}", dir.as_raw_fd()))
        .map_err(|e| Error::io("enumerate scope", e))?
    {
        let entry = entry.map_err(|e| Error::io("read scope entry", e))?;
        let kind = match entry.file_type() {
            Ok(kind) => kind,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(Error::io("stat scope entry", error)),
        };
        if kind.is_dir() {
            let name = entry.file_name().into_string().map_err(|_| {
                Error::io(
                    "scope directory name",
                    io::Error::new(io::ErrorKind::InvalidData, "non-UTF8 scope name"),
                )
            })?;
            validate_segment(&name)?;
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}
fn walk(dir: &File, scope: &ScopeId, out: &mut Vec<ScopeId>) -> Result<()> {
    for name in child_dirs(dir)? {
        let child = scope.join(&name)?;
        let child_dir = match open_at(dir, &name, libc::O_RDONLY | libc::O_DIRECTORY) {
            Ok(dir) => dir,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(Error::io("open descendant", e)),
        };
        out.push(child.clone());
        walk(&child_dir, &child, out)?;
    }
    Ok(())
}
fn collect_dirs(dir: &File, scope: &ScopeId, out: &mut Vec<(ScopeId, File)>) -> Result<()> {
    for name in child_dirs(dir)? {
        let child = scope.join(&name)?;
        let child_dir = match open_at(dir, &name, libc::O_RDONLY | libc::O_DIRECTORY) {
            Ok(dir) => dir,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(Error::io("open frozen descendant", e)),
        };
        collect_dirs(&child_dir, &child, out)?;
        out.push((child, child_dir));
    }
    Ok(())
}
fn target_name(target: &TargetId) -> CString {
    CString::new(format!("{TARGET_PREFIX}{target}")).expect("validated target")
}
fn encode_identity(identity: ProcessIdentity) -> String {
    format!("v2:{}:{}", identity.pid, identity.start_time)
}
fn decode_identity(bytes: &[u8]) -> io::Result<ProcessIdentity> {
    let bad = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid or unsupported scoped target record",
        )
    };
    let raw = std::str::from_utf8(bytes).map_err(|_| bad())?;
    let mut fields = raw.split(':');
    if fields.next() != Some("v2") {
        return Err(bad());
    }
    let pid = fields.next().ok_or_else(bad)?.parse().map_err(|_| bad())?;
    let start_time = fields.next().ok_or_else(bad)?.parse().map_err(|_| bad())?;
    if fields.next().is_some() {
        return Err(bad());
    }
    valid_pid(pid).map_err(|_| bad())?;
    Ok(ProcessIdentity { pid, start_time })
}
pub(crate) fn read_identity(dir: &File, target: &TargetId) -> io::Result<Option<ProcessIdentity>> {
    let name = target_name(target);
    let mut bytes = [0u8; 128];
    // The complete record has a small fixed upper bound. No size/read race.
    // SAFETY: live descriptor, C name and writable buffer.
    let n = unsafe {
        libc::fgetxattr(
            dir.as_raw_fd(),
            name.as_ptr(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
        )
    };
    if n < 0 {
        let error = io::Error::last_os_error();
        return if error.raw_os_error() == Some(libc::ENODATA) {
            Ok(None)
        } else {
            Err(error)
        };
    }
    decode_identity(&bytes[..n as usize]).map(Some)
}
fn read_xattr_names(dir: &File) -> io::Result<Vec<u8>> {
    // Linux bounds the complete list at 64 KiB. One syscall avoids size races.
    let mut bytes = vec![0u8; 65536];
    // SAFETY: valid descriptor and writable buffer.
    let n = unsafe { libc::flistxattr(dir.as_raw_fd(), bytes.as_mut_ptr().cast(), bytes.len()) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    bytes.truncate(n as usize);
    Ok(bytes)
}

fn cgroup_prefix(root: &Path) -> io::Result<String> {
    let root = fs::canonicalize(root)?;
    let mounts = fs::read_to_string("/proc/self/mountinfo")?;
    let mut selected: Option<(PathBuf, String)> = None;
    for line in mounts.lines() {
        let Some((left, right)) = line.split_once(" - ") else {
            continue;
        };
        if right.split_whitespace().next() != Some("cgroup2") {
            continue;
        }
        let fields: Vec<_> = left.split_whitespace().collect();
        if fields.len() < 5 {
            continue;
        }
        let mount = PathBuf::from(unescape_mount(fields[4]));
        if root.starts_with(&mount)
            && selected
                .as_ref()
                .is_none_or(|(previous, _)| mount.as_os_str().len() > previous.as_os_str().len())
        {
            selected = Some((mount, unescape_mount(fields[3])));
        }
    }
    // Plain-directory fixtures intentionally exercise structure, not cgroups.
    let Some((mount, mounted_root)) = selected else {
        return Ok(String::new());
    };
    let relative = root.strip_prefix(mount).expect("checked mount prefix");
    Ok(format!(
        "{}/{}",
        mounted_root.trim_end_matches('/'),
        relative.display()
    )
    .trim_end_matches('/')
    .to_owned())
}
fn unescape_mount(value: &str) -> String {
    value
        .replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn fixture() -> (tempfile::TempDir, Domain) {
        let root = tempfile::tempdir().unwrap();
        let domain = Domain::create(root.path(), "test").unwrap();
        (root, domain)
    }
    fn id(raw: &str) -> ScopeId {
        ScopeId::parse(raw).unwrap()
    }

    #[test]
    fn domain_is_explicit_and_constrains_ids() {
        let root = tempfile::tempdir().unwrap();
        assert!(Domain::open(root.path(), "test").is_err());
        let domain = Domain::create(root.path(), "test").unwrap();
        assert!(matches!(
            domain.create_scope(&id("other/child")),
            Err(Error::OutsideDomain { .. })
        ));
        assert!(matches!(
            domain.remove_scope(&id("test")),
            Err(Error::DomainRoot)
        ));
    }
    #[test]
    fn create_is_single_node_remove_is_nonrecursive_and_missing_idempotent() {
        let (_root, domain) = fixture();
        assert!(
            domain
                .create_scope(&id("test/a/b"))
                .unwrap_err()
                .is_not_found()
        );
        domain.create_scope(&id("test/a")).unwrap();
        assert!(
            domain
                .create_scope(&id("test/a"))
                .unwrap_err()
                .is_already_exists()
        );
        domain.create_scope(&id("test/a/b")).unwrap();
        assert!(domain.remove_scope(&id("test/a")).is_err());
        domain.remove_scope(&id("test/a/b")).unwrap();
        domain.remove_scope(&id("test/a")).unwrap();
        domain.remove_scope(&id("test/a/b")).unwrap();
    }
    #[test]
    fn listing_includes_unknown_descendants() {
        let (_root, domain) = fixture();
        for raw in ["test/a", "test/a/b", "test/a/b/c"] {
            domain.create_scope(&id(raw)).unwrap();
        }
        assert_eq!(
            domain.list_scopes(&id("test/a")).unwrap(),
            vec![id("test/a/b"), id("test/a/b/c")]
        );
    }
    #[test]
    fn direct_children_do_not_traverse_nested_scopes() {
        let (_root, domain) = fixture();
        for raw in ["test/a", "test/a/b", "test/a/b/c"] {
            domain.create_scope(&id(raw)).unwrap();
        }
        assert_eq!(
            domain.list_children(&id("test/a")).unwrap(),
            vec![id("test/a/b")]
        );
        assert!(
            domain
                .list_children(&id("test/missing"))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn scope_components_do_not_follow_symlinks() {
        let (root, domain) = fixture();
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), root.path().join("test/escape")).unwrap();
        assert!(domain.create_scope(&id("test/escape/child")).is_err());
        assert!(!outside.path().join("child").exists());
    }
    #[test]
    fn existing_scope_with_missing_events_is_not_drained() {
        let (_root, domain) = fixture();
        domain.create_scope(&id("test/a")).unwrap();
        assert!(domain.scope_populated(&id("test/a")).is_err());
        assert!(!domain.scope_populated(&id("test/missing")).unwrap());
        assert!(domain.kill_scope(&id("test/a")).is_err());
        domain.kill_scope(&id("test/missing")).unwrap();
    }
    #[test]
    fn pinned_scope_does_not_follow_a_replacement_generation() {
        let (root, domain) = fixture();
        let scope = id("test/a");
        domain.create_scope(&scope).unwrap();
        let pinned = domain.pin_scope(&scope).unwrap();
        let old = pinned.identity();
        domain.remove_scope(&scope).unwrap();
        domain.create_scope(&scope).unwrap();
        fs::write(root.path().join("test/a/cgroup.procs"), "untouched").unwrap();
        assert_ne!(domain.scope_identity(&scope).unwrap(), Some(old));
        assert!(
            pinned
                .move_process(std::process::id())
                .unwrap_err()
                .is_not_found()
        );
        assert!(
            pinned
                .assign_target(&TargetId::parse("manager").unwrap(), std::process::id())
                .unwrap_err()
                .is_not_found()
        );
        assert_eq!(
            fs::read_to_string(root.path().join("test/a/cgroup.procs")).unwrap(),
            "untouched"
        );
    }

    #[test]
    fn move_does_not_assign_or_open_process_handles() {
        let (root, domain) = fixture();
        domain.create_scope(&id("test/a")).unwrap();
        fs::write(root.path().join("test/a/cgroup.procs"), "").unwrap();
        domain.move_process(&id("test/a"), 2_000_000_000).unwrap();
        assert_eq!(
            fs::read_to_string(root.path().join("test/a/cgroup.procs")).unwrap(),
            "2000000000\n"
        );
        assert!(domain.list_targets(&id("test/a")).unwrap().is_empty());
        assert!(domain.move_process(&id("test/a"), 0).is_err());
    }
    fn set_record(dir: &File, target: &TargetId, bytes: &[u8]) {
        let name = target_name(target);
        // SAFETY: valid descriptor, C name, and readable byte buffer.
        assert_eq!(
            unsafe {
                libc::fsetxattr(
                    dir.as_raw_fd(),
                    name.as_ptr(),
                    bytes.as_ptr().cast(),
                    bytes.len(),
                    0,
                )
            },
            0
        );
    }
    #[test]
    fn inventory_reads_stale_identity_without_liveness_filtering() {
        let (_root, domain) = fixture();
        let scope = id("test/a");
        domain.create_scope(&scope).unwrap();
        let target = TargetId::parse("leader").unwrap();
        let dir = domain.open_scope(&scope).unwrap();
        let stale = ProcessIdentity {
            pid: i32::MAX as u32,
            start_time: 1,
        };
        set_record(&dir, &target, encode_identity(stale).as_bytes());
        assert_eq!(
            domain.read_target_identity(&scope, &target).unwrap(),
            Some(stale)
        );
        assert_eq!(
            domain.target_status(&scope, &target).unwrap(),
            TargetStatus::Exited(stale)
        );
        assert!(
            domain
                .watch_target(&scope, &target)
                .unwrap()
                .exited()
                .unwrap()
        );
        assert_eq!(domain.list_targets(&scope).unwrap(), vec![target.clone()]);
        domain.remove_target(&scope, &target).unwrap();
        domain.remove_target(&scope, &target).unwrap();
        assert_eq!(
            domain.target_status(&scope, &target).unwrap(),
            TargetStatus::Untracked
        );
    }
    #[test]
    fn running_status_does_not_require_membership_but_signalling_does() {
        let (_root, domain) = fixture();
        let scope = id("test/a");
        domain.create_scope(&scope).unwrap();
        let target = TargetId::parse("leader").unwrap();
        let dir = domain.open_scope(&scope).unwrap();
        let process = ProcessIdentity {
            pid: std::process::id(),
            start_time: read_start_time(std::process::id()).unwrap(),
        };
        set_record(&dir, &target, encode_identity(process).as_bytes());
        assert_eq!(
            domain.target_status(&scope, &target).unwrap(),
            TargetStatus::Running(process)
        );
        assert!(!domain.target_exists(&scope, &target).unwrap());
        assert!(matches!(
            domain.terminate_target(&scope, &target),
            Err(Error::Membership { .. })
        ));
        assert!(matches!(
            domain.kill_target(&scope, &target),
            Err(Error::Membership { .. })
        ));
        assert!(
            !domain
                .watch_target(&scope, &target)
                .unwrap()
                .exited()
                .unwrap()
        );
    }
    #[test]
    fn corrupt_tracking_does_not_disable_whole_scope_operations() {
        let (root, domain) = fixture();
        let scope = id("test/a");
        domain.create_scope(&scope).unwrap();
        let target = TargetId::parse("leader").unwrap();
        let dir = domain.open_scope(&scope).unwrap();
        set_record(&dir, &target, b"broken");
        assert!(domain.read_target_identity(&scope, &target).is_err());
        assert!(domain.target_status(&scope, &target).is_err());
        let path = root.path().join("test/a");
        fs::write(path.join("cgroup.events"), "populated 0\nfrozen 1\n").unwrap();
        fs::write(path.join("cgroup.procs"), "").unwrap();
        fs::write(path.join("cgroup.freeze"), "0").unwrap();
        fs::write(path.join("cgroup.kill"), "0").unwrap();
        assert!(!domain.scope_populated(&scope).unwrap());
        domain.terminate_scope(&scope).unwrap();
        domain.kill_scope(&scope).unwrap();
        for name in [
            "cgroup.events",
            "cgroup.procs",
            "cgroup.freeze",
            "cgroup.kill",
        ] {
            fs::remove_file(path.join(name)).unwrap();
        }
        domain.remove_scope(&scope).unwrap();
    }
    #[test]
    fn records_are_complete_and_old_pending_protocol_is_rejected() {
        let expected = ProcessIdentity {
            pid: 123,
            start_time: 987,
        };
        assert_eq!(
            decode_identity(encode_identity(expected).as_bytes()).unwrap(),
            expected
        );
        for bad in [
            "v1:pending:1:2",
            "v1:active:1:2",
            "v2:0:1",
            "v2:1",
            "v2:1:2:extra",
            "garbage",
        ] {
            assert!(decode_identity(bad.as_bytes()).is_err(), "{bad}");
        }
    }
    #[test]
    fn event_parser_rejects_missing_and_malformed_state() {
        assert!(parse_event("populated 1\nfrozen 0\n", "populated").unwrap());
        for raw in [
            "frozen 0\n",
            "populated 2\n",
            "populated\n",
            "populated 0 extra\n",
        ] {
            assert!(parse_event(raw, "populated").is_err());
        }
    }
    #[test]
    fn termination_thaws_after_freeze_query_error_and_accepts_already_frozen() {
        let (root, domain) = fixture();
        domain.create_scope(&id("test/a")).unwrap();
        let path = root.path().join("test/a");
        fs::write(path.join("cgroup.freeze"), "0").unwrap();
        fs::write(path.join("cgroup.events"), "populated 1\n").unwrap();
        assert!(domain.terminate_scope(&id("test/a")).is_err());
        assert_eq!(fs::read_to_string(path.join("cgroup.freeze")).unwrap(), "0");
        fs::write(path.join("cgroup.events"), "populated 0\nfrozen 1\n").unwrap();
        fs::write(path.join("cgroup.procs"), "").unwrap();
        domain.terminate_scope(&id("test/a")).unwrap();
        assert_eq!(fs::read_to_string(path.join("cgroup.freeze")).unwrap(), "0");
    }
    #[test]
    fn freeze_timeout_is_bounded_and_thaws() {
        let (root, domain) = fixture();
        domain.create_scope(&id("test/a")).unwrap();
        let path = root.path().join("test/a");
        fs::write(path.join("cgroup.freeze"), "0").unwrap();
        fs::write(path.join("cgroup.events"), "populated 1\nfrozen 0\n").unwrap();
        let start = Instant::now();
        assert!(domain.terminate_scope(&id("test/a")).is_err());
        assert!(start.elapsed() >= FREEZE_TIMEOUT);
        assert!(start.elapsed() < Duration::from_secs(3));
        assert_eq!(fs::read_to_string(path.join("cgroup.freeze")).unwrap(), "0");
    }
}
