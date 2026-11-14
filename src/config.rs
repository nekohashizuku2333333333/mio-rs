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
    #[serde(default = "default_port")]
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
    #[serde(default = "default_port")]
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

    pub fn is_server(&self) -> bool {
        !self.inbounds.listen.trim().is_empty()
    }

    pub fn validate(&self) -> Result<()> {
        validate_log_level(&self.log.level)?;
        if self.is_server() {
            if !self.outbounds.socks_listen.trim().is_empty()
                || !self.outbounds.server.trim().is_empty()
            {
                bail!("configure either a server ([inbounds]) or a client ([outbounds]), not both");
            }
            let inbound = &self.inbounds;
            if inbound.listen_port == 0 {
                bail!("[inbounds].listen_port must be between 1 and 65535");
            }
            if inbound.dest.trim().is_empty() {
                bail!("configuration must set [inbounds].dest");
            }
            if inbound.dest_port == 0 {
                bail!("[inbounds].dest_port must be between 1 and 65535");
            }
            if inbound.private_key.is_empty() {
                bail!("configuration must set [inbounds].private_key (run `mio keygen`)");
            }
            crate::crypto::parse_private_key(&inbound.private_key)
                .context("[inbounds].private_key")?;
            return Ok(());
        }

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
        if outbound.dest_port == 0 {
            bail!("[outbounds].dest_port must be between 1 and 65535");
        }
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
    }
}
