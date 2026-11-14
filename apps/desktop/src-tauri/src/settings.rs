//! Where the shell looks for the core.
//!
//! There is one rule, and it is the same rule `internal/datadir` applies on the
//! Go side: an explicit setting wins, otherwise the platform configuration
//! directory plus the product name. The shell cannot read the core's
//! configuration file — it has no INI parser and does not want one — so the API
//! address is an explicit setting with the documented default. Both are
//! environment variables here because a desktop shortcut has nowhere to put a
//! flag.

use std::env;
use std::path::PathBuf;

/// Same default as `defaultAPIListen` in the core.
pub const DEFAULT_API_ADDRESS: &str = "127.0.0.1:7946";

/// Same name as `datadir.DefaultDirName`.
pub const DEFAULT_DIR_NAME: &str = "melonarc";

/// Same name as `datadir.TokenFile`.
pub const TOKEN_FILE: &str = "api-token";

#[derive(Clone, Debug)]
pub struct Settings {
    pub data_dir: PathBuf,
    pub api_host: String,
    pub api_port: u16,
    /// `host:port` as it should be shown to the user.
    pub api_label: String,
}

impl Settings {
    /// `<data-dir>/api-token`, the only credential this process ever reads.
    pub fn token_path(&self) -> PathBuf {
        self.data_dir.join(TOKEN_FILE)
    }
}

/// Read the settings, refusing anything that would send the token off the machine.
pub fn load() -> Result<Settings, String> {
    let data_dir = match env::var("MELONARC_DATA_DIR") {
        Ok(value) if !value.trim().is_empty() => PathBuf::from(value.trim()),
        _ => config_home()?.join(DEFAULT_DIR_NAME),
    };

    let raw = env::var("MELONARC_API_ADDR").unwrap_or_else(|_| DEFAULT_API_ADDRESS.to_string());
    let (host, port) = parse_address(&raw)?;

    // The token is a plain bearer value over a plaintext connection. The core
    // only listens on loopback, so an address that is not loopback would mean
    // shipping the credential to another machine by accident: refuse it.
    if !is_loopback(&host) {
        return Err(format!(
            "api address {host}:{port} is not a loopback address; the token never leaves this machine"
        ));
    }

    let api_label = format!("{host}:{port}");
    Ok(Settings {
        data_dir,
        api_host: host,
        api_port: port,
        api_label,
    })
}

fn parse_address(raw: &str) -> Result<(String, u16), String> {
    let value = raw.trim();
    let (host, port) = value
        .rsplit_once(':')
        .ok_or_else(|| format!("api address {value:?} is not host:port"))?;
    let host = host.trim().trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return Err(format!("api address {value:?} has no host"));
    }
    let port: u16 = port
        .trim()
        .parse()
        .map_err(|_| format!("api address {value:?} has no usable port"))?;
    Ok((host.to_string(), port))
}

fn is_loopback(host: &str) -> bool {
    host == "localhost" || host == "::1" || host.starts_with("127.")
}

#[cfg(target_os = "windows")]
fn config_home() -> Result<PathBuf, String> {
    if let Some(appdata) = env::var_os("APPDATA") {
        if !appdata.is_empty() {
            return Ok(PathBuf::from(appdata));
        }
    }
    Ok(home_dir()?.join("AppData").join("Roaming"))
}

#[cfg(target_os = "macos")]
fn config_home() -> Result<PathBuf, String> {
    Ok(home_dir()?.join("Library").join("Application Support"))
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn config_home() -> Result<PathBuf, String> {
    if let Some(xdg) = env::var_os("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            return Ok(PathBuf::from(xdg));
        }
    }
    Ok(home_dir()?.join(".config"))
}

fn home_dir() -> Result<PathBuf, String> {
    if let Some(home) = env::var_os("HOME") {
        if !home.is_empty() {
            return Ok(PathBuf::from(home));
        }
    }
    if let Some(profile) = env::var_os("USERPROFILE") {
        if !profile.is_empty() {
            return Ok(PathBuf::from(profile));
        }
    }
    Err(String::from(
        "no home directory in the environment; set MELONARC_DATA_DIR to say where the core keeps its state",
    ))
}
