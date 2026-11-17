use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default)]
    pub outbounds: OutboundConfig,
    #[serde(default)]
    pub inbounds: InboundConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogConfig {
    #[serde(default = "default_true")]
    pub enable: bool,
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default)]
    pub output: String,
    #[serde(default = "default_true")]
    pub timestamp: bool,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            enable: true,
            level: default_log_level(),
            output: String::new(),
            timestamp: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct OutboundConfig {
    #[serde(default)]
    pub socks_listen: String,
    #[serde(default)]
    pub socks_listen_port: u16,
    #[serde(default)]
    pub server: String,
    #[serde(default = "default_port")]
    pub server_port: u16,
    #[serde(default)]
    pub dest: String,
    #[serde(default)]
    pub dest_port: u16,
    #[serde(default)]
    pub public_key: String,
    /// Local test-only switch. Upstream does not expose this field.
    #[serde(default)]
    pub insecure: bool,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct InboundConfig {
    #[serde(default)]
    pub listen: String,
    #[serde(default = "default_port")]
    pub listen_port: u16,
    #[serde(default)]
    pub dest: String,
    #[serde(default)]
    pub dest_port: u16,
    #[serde(default)]
    pub private_key: String,
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = fs::read_to_string(path)
            .with_context(|| format!("read configuration {}", path.display()))?;
        let cfg: Config = toml::from_str(&text)
            .with_context(|| format!("parse configuration {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn has_server(&self) -> bool {
        !self.inbounds.listen.trim().is_empty()
            || self.inbounds.listen_port != 0
            || !self.inbounds.dest.trim().is_empty()
            || !self.inbounds.private_key.is_empty()
    }

    pub fn has_client(&self) -> bool {
        !self.outbounds.socks_listen.trim().is_empty()
            || self.outbounds.socks_listen_port != 0
            || !self.outbounds.server.trim().is_empty()
            || !self.outbounds.public_key.is_empty()
    }

    pub fn is_server(&self) -> bool {
        self.has_server()
    }

    pub fn validate(&self) -> Result<()> {
        validate_log_level(&self.log.level)?;
        if !self.has_server() && !self.has_client() {
            bail!("configuration must set [outbounds] (client), [inbounds] (server), or both");
        }
        if self.has_server() {
            self.validate_server()?;
        }
        if self.has_client() {
            self.validate_client()?;
        }
        Ok(())
    }

    fn validate_server(&self) -> Result<()> {
        let inbound = &self.inbounds;
        if inbound.listen.trim().is_empty() {
            bail!("configuration must set [inbounds].listen");
        }
        if inbound.listen_port == 0 {
            bail!("[inbounds].listen_port must be between 1 and 65535");
        }
        if inbound.dest.trim().is_empty() {
            bail!("configuration must set [inbounds].dest");
        }
        // Zero (omitted or explicit) means "use listen_port"; see server::run.
        if inbound.private_key.is_empty() {
            bail!("configuration must set [inbounds].private_key (run `mio keygen`)");
        }
        crate::crypto::parse_private_key(&inbound.private_key).context("[inbounds].private_key")?;
        Ok(())
    }

    fn validate_client(&self) -> Result<()> {
        let outbound = &self.outbounds;
        if outbound.socks_listen.trim().is_empty() {
            bail!("configuration must set [outbounds].socks_listen");
        }
        if outbound.socks_listen_port == 0 {
            bail!("[outbounds].socks_listen_port must be between 1 and 65535");
        }
        if outbound.server.trim().is_empty() {
            bail!("configuration must set [outbounds].server");
        }
        if outbound.server_port == 0 {
            bail!("[outbounds].server_port must be between 1 and 65535");
        }
        if outbound.dest.trim().is_empty() {
            bail!("configuration must set [outbounds].dest");
        }
        // `dest_port` is optional for clients and is not used by the client
        // protocol; accept its zero default for configuration parity.
        if outbound.public_key.is_empty() {
            bail!("configuration must set [outbounds].public_key (run `mio keygen`)");
        }
        crate::crypto::parse_public_key(&outbound.public_key).context("[outbounds].public_key")?;
        Ok(())
    }
}

fn default_true() -> bool {
    true
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_port() -> u16 {
    443
}

pub fn validate_log_level(level: &str) -> Result<()> {
    match level.to_ascii_lowercase().as_str() {
        "off" | "error" | "warn" | "info" | "debug" | "trace" => Ok(()),
        _ => bail!("invalid log level {level:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_and_server_can_coexist() {
        let config: Config = toml::from_str(
            r#"
            [outbounds]
            socks_listen = "127.0.0.1"
            socks_listen_port = 1080
            server = "127.0.0.1"
            dest = "example.com"
            public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

            [inbounds]
            listen = "127.0.0.1"
            listen_port = 1443
            dest = "example.com"
            private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            "#,
        )
        .unwrap();
        config.validate().unwrap();
        assert!(config.has_client());
        assert!(config.has_server());
    }

    #[test]
    fn client_config_validation() {
        let config: Config = toml::from_str(
            r#"
            [outbounds]
            socks_listen = "127.0.0.1"
            socks_listen_port = 1080
            server = "example.com"
            dest = "www.example.com"
            public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            "#,
        )
        .unwrap();
        assert!(!config.is_server());
        assert_eq!(config.outbounds.server_port, 443);
        assert_eq!(config.outbounds.dest_port, 0);
    }

    #[test]
    fn omitted_dest_port_uses_listen_port_for_server() {
        let config: Config = toml::from_str(
            r#"
            [inbounds]
            listen = "127.0.0.1"
            listen_port = 8443
            dest = "www.example.com"
            private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            "#,
        )
        .unwrap();
        config.validate().unwrap();
        assert_eq!(config.inbounds.dest_port, 0);
        let effective = if config.inbounds.dest_port == 0 {
            config.inbounds.listen_port
        } else {
            config.inbounds.dest_port
        };
        assert_eq!(effective, 8443);
    }
}
