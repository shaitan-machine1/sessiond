use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ShutdownMode {
    Scope,
    Leader,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ShutdownConfig {
    pub mode: ShutdownMode,
    #[serde(deserialize_with = "duration")]
    pub leader_timeout: Duration,
    #[serde(deserialize_with = "duration")]
    pub scope_timeout: Duration,
}

impl Default for ShutdownConfig {
    fn default() -> Self {
        Self {
            mode: ShutdownMode::Scope,
            leader_timeout: Duration::from_secs(10),
            scope_timeout: Duration::from_secs(10),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SessionConfig {
    #[serde(deserialize_with = "duration")]
    pub open_timeout: Duration,
    pub shutdown: ShutdownConfig,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            open_timeout: Duration::from_secs(30),
            shutdown: ShutdownConfig::default(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ManagerConfig {
    pub shutdown: ShutdownConfig,
    pub launcher: PathBuf,
    #[serde(deserialize_with = "duration")]
    pub ready_timeout: Duration,
}

impl Default for ManagerConfig {
    fn default() -> Self {
        let shutdown = ShutdownConfig {
            mode: ShutdownMode::Leader,
            leader_timeout: Duration::from_secs(30),
            ..ShutdownConfig::default()
        };
        Self {
            shutdown,
            launcher: "/usr/libexec/sessiond/sessiond-user-launcher".into(),
            ready_timeout: Duration::from_secs(30),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub session: SessionConfig,
    pub user_service_manager: ManagerConfig,
    pub runtime_parent: PathBuf,
    pub state_dir: PathBuf,
    pub linger: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            session: SessionConfig::default(),
            user_service_manager: ManagerConfig::default(),
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
        let nonzero = [
            ("session.open_timeout", self.session.open_timeout),
            (
                "session.shutdown.scope_timeout",
                self.session.shutdown.scope_timeout,
            ),
            (
                "user_service_manager.shutdown.leader_timeout",
                self.user_service_manager.shutdown.leader_timeout,
            ),
            (
                "user_service_manager.shutdown.scope_timeout",
                self.user_service_manager.shutdown.scope_timeout,
            ),
            (
                "user_service_manager.ready_timeout",
                self.user_service_manager.ready_timeout,
            ),
        ];
        for (name, value) in nonzero {
            anyhow::ensure!(!value.is_zero(), "{name} must be non-zero");
        }
        anyhow::ensure!(
            self.runtime_parent.is_absolute(),
            "runtime_parent must be absolute"
        );
        anyhow::ensure!(self.state_dir.is_absolute(), "state_dir must be absolute");
        anyhow::ensure!(
            self.user_service_manager.launcher.is_absolute(),
            "user manager launcher must be absolute"
        );
        Ok(())
    }
}

fn duration<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = String::deserialize(deserializer)?;
    humantime::parse_duration(&raw).map_err(serde::de::Error::custom)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_independent_shutdown_budgets() {
        let config: Config = toml::from_str(
            r#"
            [session]
            open_timeout = "3s"
            [session.shutdown]
            mode = "scope"
            leader_timeout = "1s"
            scope_timeout = "2s"
            [user_service_manager.shutdown]
            mode = "leader"
            leader_timeout = "4s"
            scope_timeout = "5s"
            "#,
        )
        .unwrap();
        config.validate().unwrap();
        assert_eq!(config.session.open_timeout, Duration::from_secs(3));
        assert_eq!(
            config.user_service_manager.shutdown.leader_timeout,
            Duration::from_secs(4)
        );
    }

    #[test]
    fn rejects_removed_manager_entrypoint_setting() {
        let error = toml::from_str::<Config>(
            r#"
            [user_service_manager]
            entrypoint = "/tmp/manager"
            "#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("entrypoint"));
    }
}
