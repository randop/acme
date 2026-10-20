//! Modern TOML configuration and state directory handling for `acme`.
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub ca: CaConfig,
    pub defaults: DefaultsConfig,
    pub store: StoreConfig,
    pub dns: DnsConfig,
    pub hooks: HooksConfig,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CaConfig {
    pub default: String,
}
impl Default for CaConfig {
    fn default() -> Self {
        Self {
            default: "zerossl".into(),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DefaultsConfig {
    pub key_type: String,
}
impl Default for DefaultsConfig {
    fn default() -> Self {
        Self {
            key_type: "ec-256".into(),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StoreConfig {
    pub path: Option<PathBuf>,
    pub enabled: bool,
    pub required: bool,
}
impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            path: None,
            enabled: true,
            required: false,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsConfig {
    pub wait_initial_seconds: u64,
    pub wait_interval_seconds: u64,
    pub wait_timeout_seconds: u64,
    pub settle_seconds: u64,
    pub quorum: String,
    pub wait_timeout_action: String,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct HooksConfig {
    pub notify: Vec<NotifyHook>,
    pub deploy: Vec<DeployHook>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotifyHook {
    pub url: String,
    pub token_env: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployHook {
    pub key_path: PathBuf,
    pub fullchain_path: PathBuf,
}
impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            wait_initial_seconds: 10,
            wait_interval_seconds: 10,
            wait_timeout_seconds: 300,
            settle_seconds: 5,
            quorum: "all".into(),
            wait_timeout_action: "continue".into(),
        }
    }
}

pub fn home_dir() -> Result<PathBuf> {
    if let Some(v) = std::env::var_os("ACME_HOME") {
        return Ok(expand_tilde(PathBuf::from(v))?);
    }
    dirs::home_dir()
        .map(|p| p.join(".acme"))
        .context("could not determine home directory")
}
pub fn config_path(cli: Option<&Path>) -> Result<PathBuf> {
    if let Some(p) = cli {
        return Ok(expand_tilde(p.to_path_buf())?);
    }
    if let Some(p) = std::env::var_os("ACME_CONFIG") {
        return Ok(expand_tilde(PathBuf::from(p))?);
    }
    Ok(home_dir()?.join("config.toml"))
}
pub fn load(path: &Path) -> Result<Config> {
    match fs::read_to_string(path) {
        Ok(s) => toml::from_str(&s).with_context(|| format!("parsing config {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
        Err(e) => Err(e).with_context(|| format!("reading config {}", path.display())),
    }
}
pub fn initialize(home: &Path) -> Result<()> {
    fs::create_dir_all(home)?;
    fs::set_permissions(home, fs::Permissions::from_mode(0o700))?;
    for dir in ["account", "certs", "dnsapi.d"] {
        let p = home.join(dir);
        fs::create_dir_all(&p)?;
        fs::set_permissions(p, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
pub fn expand_tilde(path: PathBuf) -> Result<PathBuf> {
    let s = path.to_string_lossy();
    if s == "~" || s.starts_with("~/") {
        let home = dirs::home_dir().context("could not determine home directory")?;
        return Ok(if s == "~" { home } else { home.join(&s[2..]) });
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_config_defaults() {
        let cfg = Config::default();
        assert_eq!(cfg.ca.default, "zerossl");
        assert_eq!(cfg.defaults.key_type, "ec-256");
        assert!(cfg.store.enabled);
        assert!(!cfg.store.required);
        assert_eq!(cfg.dns.wait_initial_seconds, 10);
        assert_eq!(cfg.dns.wait_interval_seconds, 10);
        assert_eq!(cfg.dns.wait_timeout_seconds, 300);
        assert_eq!(cfg.dns.settle_seconds, 5);
        assert_eq!(cfg.dns.quorum, "all");
        assert_eq!(cfg.dns.wait_timeout_action, "continue");
    }

    #[test]
    fn test_load_default_config() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let cfg = load(&config_path).unwrap();
        assert_eq!(cfg.ca.default, "zerossl");
    }

    #[test]
    fn test_load_custom_config() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        fs::write(&config_path, r#"
            [ca]
            default = "letsencrypt"
            [defaults]
            key_type = "ec-384"
        "#).unwrap();
        let cfg = load(&config_path).unwrap();
        assert_eq!(cfg.ca.default, "letsencrypt");
        assert_eq!(cfg.defaults.key_type, "ec-384");
    }

    #[test]
    fn test_expand_tilde() {
        let result = expand_tilde(PathBuf::from("~/test")).unwrap();
        assert!(result.ends_with("test"));
    }

    #[test]
    fn test_initialize() {
        let dir = tempdir().unwrap();
        let home = dir.path().join("acme");
        initialize(&home).unwrap();
        assert!(home.join("account").exists());
        assert!(home.join("certs").exists());
        assert!(home.join("dnsapi.d").exists());
    }
}
