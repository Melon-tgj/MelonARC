//! Where the shell looks for the core.
//!
//! There is one rule, and it is the same rule `internal/datadir` applies on the
//! Go side: an explicit setting wins, otherwise the platform configuration
//! directory plus the product name. The shell cannot read the core's
//! configuration file — it has no INI parser and does not want one — so the API
//! address is an explicit setting with the documented default. Both are
//! environment variables here because a desktop shortcut has nowhere to put a
//! flag.
//!
//! The address is validated once, at startup. Loopback is an IP-type property,
//! never a string prefix: `127.example.com` is not a loopback address. The name
//! `localhost` is resolved once and every answer must be loopback. Only those
//! verified addresses are ever dialled, so the bearer token cannot be moved off
//! this machine by a later DNS answer.

use std::env;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
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
    /// Loopback endpoints verified when the settings were read. The API client
    /// dials only these: a name is never resolved again at connect time.
    pub api_addrs: Vec<SocketAddr>,
    /// Canonical `host:port` for the Host header and the UI. An IPv6 host is
    /// bracketed, as `SocketAddr::to_string` produces.
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
    let (api_addrs, api_label) = resolve_api_address(&raw)?;
    Ok(Settings {
        data_dir,
        api_addrs,
        api_label,
    })
}

/// Loopback is decided by the address family and its bytes, not by a textual
/// prefix. 127.0.0.0/8, `::1` and IPv4-mapped `::ffff:127.0.0.0/8` qualify.
pub fn is_loopback_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            let is_v6_loopback = octets[..15].iter().all(|&byte| byte == 0) && octets[15] == 1;
            let is_mapped_loopback = octets[..10].iter().all(|&byte| byte == 0)
                && octets[10] == 0xff
                && octets[11] == 0xff
                && octets[12] == 127;
            is_v6_loopback || is_mapped_loopback
        }
    }
}

/// Validate `host:port` and return the exact addresses the client may dial.
fn resolve_api_address(raw: &str) -> Result<(Vec<SocketAddr>, String), String> {
    let (host, port) = parse_address(raw)?;

    if let Ok(ip) = host.parse::<IpAddr>() {
        if !is_loopback_ip(ip) {
            return Err(format!(
                "api address {raw:?} is not a loopback address; the token never leaves this machine"
            ));
        }
        let addr = SocketAddr::new(ip, port);
        return Ok((vec![addr], addr.to_string()));
    }

    if !host.eq_ignore_ascii_case("localhost") {
        return Err(format!(
            "api address {raw:?} is neither a loopback IP nor localhost; the token never leaves this machine"
        ));
    }

    // Resolve once and verify every answer. An answer that is not loopback is a
    // refusal, not a warning: a mixed result could otherwise be re-resolved to
    // the remote address at connect time.
    let resolved = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|error| format!("cannot resolve localhost: {error}"))?;
    let mut addrs: Vec<SocketAddr> = Vec::new();
    for addr in resolved {
        if !is_loopback_ip(addr.ip()) {
            return Err(format!(
                "localhost resolved to {}, which is not loopback; refusing to send the token",
                addr.ip()
            ));
        }
        addrs.push(addr);
    }
    if addrs.is_empty() {
        return Err(String::from("localhost resolved to no address"));
    }
    // Prefer IPv4: the core binds 127.0.0.1 by default.
    addrs.sort_by_key(|addr| if addr.is_ipv4() { 0 } else { 1 });
    let label = addrs[0].to_string();
    Ok((addrs, label))
}

/// Split `host:port`. IPv6 must be bracketed; an unbracketed literal is
/// ambiguous with the port separator and is refused rather than guessed at.
fn parse_address(raw: &str) -> Result<(String, u16), String> {
    let value = raw.trim();
    let (host, port_text) = if value.starts_with('[') {
        let close = value
            .find(']')
            .ok_or_else(|| format!("api address {value:?} has no closing bracket"))?;
        let rest = &value[close + 1..];
        let port = rest
            .strip_prefix(':')
            .ok_or_else(|| format!("api address {value:?} has no port after the bracket"))?;
        (&value[1..close], port)
    } else {
        let (host, port) = value
            .rsplit_once(':')
            .ok_or_else(|| format!("api address {value:?} is not host:port"))?;
        if host.contains(':') {
            return Err(format!(
                "api address {value:?} must bracket its IPv6 host, e.g. [::1]:7946"
            ));
        }
        (host, port)
    };
    if host.is_empty() {
        return Err(format!("api address {value:?} has no host"));
    }
    let port: u16 = port_text
        .trim()
        .parse()
        .map_err(|_| format!("api address {value:?} has no usable port"))?;
    if port == 0 {
        return Err(format!("api address {value:?} has no usable port"));
    }
    Ok((host.to_string(), port))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_is_decided_by_ip_type() {
        assert!(is_loopback_ip("127.0.0.1".parse().unwrap()));
        assert!(is_loopback_ip("127.9.8.7".parse().unwrap()));
        assert!(is_loopback_ip("::1".parse().unwrap()));
        assert!(is_loopback_ip("::ffff:127.0.0.1".parse().unwrap()));
        assert!(!is_loopback_ip("128.0.0.1".parse().unwrap()));
        assert!(!is_loopback_ip("192.168.1.1".parse().unwrap()));
        assert!(!is_loopback_ip("::2".parse().unwrap()));
        assert!(!is_loopback_ip("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn a_literal_must_be_loopback_and_is_canonicalised() {
        let (addrs, label) = resolve_api_address("127.0.0.1:7946").unwrap();
        assert_eq!(addrs.len(), 1);
        assert_eq!(label, "127.0.0.1:7946");

        let (_, label_v6) = resolve_api_address("[0:0:0:0:0:0:0:1]:7946").unwrap();
        assert_eq!(label_v6, "[::1]:7946");

        for bad in [
            "192.168.1.10:7946",
            "10.0.0.1:7946",
            "[2001:db8::1]:7946",
            "core.example:7946",
            "127.example.com:7946",
            "::1:7946",
            "127.0.0.1:0",
        ] {
            assert!(resolve_api_address(bad).is_err(), "{bad} was accepted");
        }
    }

    #[test]
    fn localhost_resolves_only_to_verified_loopback_addresses() {
        let (addrs, label) = resolve_api_address("localHOST:7946").unwrap();
        assert!(!addrs.is_empty());
        assert!(addrs.iter().all(|addr| is_loopback_ip(addr.ip())));
        assert!(label.starts_with("127.") || label.starts_with("[::1]"), "{label}");
    }
}
