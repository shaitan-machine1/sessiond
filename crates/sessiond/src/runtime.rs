use async_trait::async_trait;
use nix::unistd::{Uid, User, chown};
use std::fs;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

#[async_trait]
pub trait RuntimeStore: Send + Sync {
    async fn ensure_runtime(&self, uid: u32) -> anyhow::Result<PathBuf>;
    async fn remove_runtime(&self, uid: u32) -> anyhow::Result<()>;
    async fn mark_closing(&self, sid: &str, uid: u32) -> anyhow::Result<()>;
    async fn unmark_closing(&self, sid: &str) -> anyhow::Result<()>;
    async fn closing_markers(&self) -> anyhow::Result<Vec<(String, u32)>>;
    async fn runtime_uids(&self) -> anyhow::Result<Vec<u32>>;
}

pub struct FsRuntimeStore {
    runtime_parent: PathBuf,
    state_dir: PathBuf,
}

impl FsRuntimeStore {
    pub fn new(runtime_parent: PathBuf, state_dir: PathBuf) -> Self {
        Self {
            runtime_parent,
            state_dir,
        }
    }

    fn runtime(&self, uid: u32) -> PathBuf {
        self.runtime_parent.join(uid.to_string())
    }

    fn markers(&self) -> PathBuf {
        self.state_dir.join("closing")
    }
}

#[async_trait]
impl RuntimeStore for FsRuntimeStore {
    async fn ensure_runtime(&self, uid: u32) -> anyhow::Result<PathBuf> {
        let path = self.runtime(uid);
        match fs::symlink_metadata(&path) {
            Ok(metadata) => validate_runtime(&path, &metadata, uid)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir_all(&self.runtime_parent)?;
                let mut builder = fs::DirBuilder::new();
                builder.mode(0o700);
                match builder.create(&path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        validate_runtime(&path, &fs::symlink_metadata(&path)?, uid)?;
                        return Ok(path);
                    }
                    Err(error) => return Err(error.into()),
                }
                let gid = User::from_uid(Uid::from_raw(uid))?
                    .ok_or_else(|| anyhow::anyhow!("uid {uid} has no passwd entry"))?
                    .gid;
                chown(&path, Some(Uid::from_raw(uid)), Some(gid))?;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
            }
            Err(error) => return Err(error.into()),
        }
        Ok(path)
    }

    async fn remove_runtime(&self, uid: u32) -> anyhow::Result<()> {
        let path = self.runtime(uid);
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                validate_runtime(&path, &metadata, uid)?;
                fs::remove_dir_all(path)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    async fn mark_closing(&self, sid: &str, uid: u32) -> anyhow::Result<()> {
        validate_sid(sid)?;
        let directory = self.markers();
        fs::create_dir_all(&directory)?;
        let final_path = directory.join(sid);
        if final_path.exists() {
            return Ok(());
        }
        let temporary = directory.join(format!(".{sid}.{}.tmp", std::process::id()));
        fs::write(&temporary, format!("{uid}\n"))?;
        fs::rename(&temporary, &final_path)?;
        sync_directory(&directory)?;
        Ok(())
    }

    async fn unmark_closing(&self, sid: &str) -> anyhow::Result<()> {
        validate_sid(sid)?;
        match fs::remove_file(self.markers().join(sid)) {
            Ok(()) => sync_directory(&self.markers())?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    async fn closing_markers(&self) -> anyhow::Result<Vec<(String, u32)>> {
        let mut markers = Vec::new();
        let entries = match fs::read_dir(self.markers()) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(markers),
            Err(error) => return Err(error.into()),
        };
        for entry in entries {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let sid = entry.file_name().to_string_lossy().into_owned();
            if validate_sid(&sid).is_err() {
                continue;
            }
            let uid = fs::read_to_string(entry.path())?.trim().parse()?;
            markers.push((sid, uid));
        }
        Ok(markers)
    }

    async fn runtime_uids(&self) -> anyhow::Result<Vec<u32>> {
        let entries = match fs::read_dir(&self.runtime_parent) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        let mut uids = Vec::new();
        for entry in entries {
            let entry = entry?;
            if let Ok(uid) = entry.file_name().to_string_lossy().parse() {
                uids.push(uid);
            }
        }
        Ok(uids)
    }
}

fn validate_runtime(path: &Path, metadata: &fs::Metadata, uid: u32) -> anyhow::Result<()> {
    anyhow::ensure!(
        metadata.file_type().is_dir() && !metadata.file_type().is_symlink(),
        "unsafe runtime path {} is not a directory",
        path.display()
    );
    anyhow::ensure!(
        metadata.uid() == uid,
        "unsafe runtime path {} is owned by uid {}, expected {uid}",
        path.display(),
        metadata.uid()
    );
    anyhow::ensure!(
        metadata.mode() & 0o077 == 0,
        "unsafe runtime path {} has mode {:o}",
        path.display(),
        metadata.mode() & 0o777
    );
    Ok(())
}

fn validate_sid(sid: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        sid.len() == 32
            && sid
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "invalid session id"
    );
    Ok(())
}

fn sync_directory(path: &Path) -> std::io::Result<()> {
    std::fs::File::open(path)?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[tokio::test]
    async fn rejects_a_symlink_runtime() {
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("user");
        fs::create_dir(&parent).unwrap();
        symlink(root.path(), parent.join("1000")).unwrap();
        let store = FsRuntimeStore::new(parent, root.path().join("state"));
        assert!(store.ensure_runtime(1000).await.is_err());
    }

    #[tokio::test]
    async fn markers_round_trip_atomically() {
        let root = tempfile::tempdir().unwrap();
        let store = FsRuntimeStore::new(root.path().join("user"), root.path().join("state"));
        let sid = "019a0000000070008000000000000000";
        store.mark_closing(sid, 42).await.unwrap();
        assert_eq!(store.closing_markers().await.unwrap(), [(sid.into(), 42)]);
        store.unmark_closing(sid).await.unwrap();
        assert!(store.closing_markers().await.unwrap().is_empty());
    }
}
