use serde::Deserialize;
use std::time::Duration;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub session: SessionConfig,
    pub log: LogConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SessionConfig {
    pub timeout_seconds: u64,
    pub cleanup_interval_seconds: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LogConfig {
    pub level: String,
}

impl Config {
    pub fn load() -> Result<Self, config::ConfigError> {
        config::Config::builder()
            .set_default("server.host", "0.0.0.0")?
            .set_default("server.port", 3000)?
            .set_default("session.timeout_seconds", 1800)?
            .set_default("session.cleanup_interval_seconds", 60)?
            .set_default("log.level", "info")?
            .add_source(config::File::with_name("config").required(false))
            .add_source(config::Environment::with_prefix("KDBX"))
            .build()?
            .try_deserialize()
    }

    pub fn session_timeout(&self) -> Duration {
        Duration::from_secs(self.session.timeout_seconds)
    }

    pub fn cleanup_interval(&self) -> Duration {
        Duration::from_secs(self.session.cleanup_interval_seconds)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig { host: "0.0.0.0".into(), port: 3000 },
            session: SessionConfig { timeout_seconds: 1800, cleanup_interval_seconds: 60 },
            log: LogConfig { level: "info".into() },
        }
    }
}
