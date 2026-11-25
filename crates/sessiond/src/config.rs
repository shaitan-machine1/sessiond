use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ShutdownMode {
    Scope,
    Master,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ShutdownConfig {
    pub mode: ShutdownMode,
    #[serde(deserialize_with = "duration")]
    pub master_timeout: Duration,
    #[serde(deserialize_with = "duration")]
    pub scope_timeout: Duration,
}
impl Default for ShutdownConfig {
    fn default() -> Self {
        Self {
            mode: ShutdownMode::Scope,
            master_timeout: Duration::from_secs(10),
            scope_timeout: Duration::from_secs(10),
        }
    }
}
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SessionConfig {
    #[serde(deserialize_with = "duration")]
    pub close_grace: Duration,
    pub shutdown: ShutdownConfig,
}
impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            close_grace: Duration::from_secs(10),
            shutdown: ShutdownConfig::default(),
        }
    }
}
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ManagerConfig {
    pub min_uid: u32,
    pub shutdown: ShutdownConfig,
    pub launcher: PathBuf,
    pub pam_service: String,
    #[serde(deserialize_with = "duration")]
    pub ready_timeout: Duration,
}
impl Default for ManagerConfig {
    fn default() -> Self {
        Self {
            min_uid: 1000,
            shutdown: ShutdownConfig {
                mode: ShutdownMode::Master,
                ..ShutdownConfig::default()
            },
            launcher: "/usr/libexec/sessiond/sessiond-user-launcher".into(),
            pam_service: "sessiond-user".into(),
            ready_timeout: Duration::from_secs(30),
        }
    }
}
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub session: SessionConfig,
    pub user_service_manager: ManagerConfig,
    pub cgroup_root: PathBuf,
    pub runtime_parent: PathBuf,
    pub state_dir: PathBuf,
    pub linger: bool,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            session: SessionConfig::default(),
            user_service_manager: ManagerConfig::default(),
            cgroup_root: "/sys/fs/cgroup".into(),
            runtime_parent: "/run/user".into(),
            state_dir: "/run/sessiond".into(),
            linger: false,
        }
    }
}
impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let config: Self = toml::from_str(&std::fs::read_to_string(path)?)?;
        config.validate()?;
        Ok(config)
    }
    pub fn validate(&self) -> anyhow::Result<()> {
        for (name, value) in [
            (
                "session.shutdown.master_timeout",
                self.session.shutdown.master_timeout,
            ),
            (
                "session.shutdown.scope_timeout",
                self.session.shutdown.scope_timeout,
            ),
            (
                "user_service_manager.shutdown.master_timeout",
                self.user_service_manager.shutdown.master_timeout,
            ),
            (
                "user_service_manager.shutdown.scope_timeout",
                self.user_service_manager.shutdown.scope_timeout,
            ),
            (
                "user_service_manager.ready_timeout",
                self.user_service_manager.ready_timeout,
            ),
        ] {
            anyhow::ensure!(
                !value.is_zero() && std::time::Instant::now().checked_add(value).is_some(),
                "{name} must be a finite nonzero duration"
            );
        }
        anyhow::ensure!(
            std::time::Instant::now()
                .checked_add(self.session.close_grace)
                .is_some(),
            "close_grace deadline overflow"
        );
        for (name, path) in [
            ("cgroup_root", &self.cgroup_root),
            ("runtime_parent", &self.runtime_parent),
            ("state_dir", &self.state_dir),
            ("launcher", &self.user_service_manager.launcher),
        ] {
            anyhow::ensure!(path.is_absolute(), "{name} must be absolute");
        }
        let service = &self.user_service_manager.pam_service;
        anyhow::ensure!(
            !service.is_empty() && !service.contains('/') && !service.contains('\0'),
            "private PAM service must be a nonempty service name"
        );
        Ok(())
    }
}
fn duration<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Duration, D::Error> {
    humantime::parse_duration(&String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn defaults_and_new_vocabulary_are_explicit() {
        let config: Config = toml::from_str("").unwrap();
        config.validate().unwrap();
        assert_eq!(config.user_service_manager.min_uid, 1000);
        assert_eq!(config.session.close_grace, Duration::from_secs(10));
        let config: Config = toml::from_str("[session]\nclose_grace = '0s'\n[session.shutdown]\nmode = 'master'\nmaster_timeout = '2s'\n[user_service_manager]\nmin_uid = 0").unwrap();
        config.validate().unwrap();
        assert_eq!(config.session.close_grace, Duration::ZERO);
        assert_eq!(config.session.shutdown.mode, ShutdownMode::Master);
        for old in [
            "[session.shutdown]\nmode='leader'",
            "[session.shutdown]\nleader_timeout='1s'",
            "[session]\nopen_timeout='1s'",
            "[session]\nclose_grace='nonsense'",
            "[user_service_manager]\nmin_uid=-1",
        ] {
            assert!(toml::from_str::<Config>(old).is_err(), "{old}");
        }
    }
}
