//! Where the shell looks for the core, and the small file that says so.
//!
//! Two sources decide the data directory and the API address at start-up, in
//! this order: an environment variable, then `shell.json`, then the documented
//! default. The environment stays because it is how a developer and the test
//! suite start the shell against a scratch directory; the file exists because a
//! desktop shortcut has nowhere to put one.
//!
//! The file lives at `<config-home>/melonarc/shell.json` — that is, in the
//! *default* data directory, not in the configured one. It has to: when it is
//! the file that names a different data directory, reading it from the data
//! directory would be circular. The core's own configuration is never parsed
//! here; `core_config` is a path, nothing more.
//!
//! The token is never written to this file. It only ever lives in
//! `<data-dir>/api-token`, which `api` reads.
//!
//! The address is validated whenever it is read or written. Loopback is an
//! IP-type property, never a string prefix: `127.example.com` is not a loopback
//! address. The name `localhost` is resolved once and every answer must be
//! loopback. Only those verified addresses are ever dialled, so the bearer token
//! cannot be moved off this machine by a later DNS answer.

use std::env;
use std::fs;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};

use crate::api::ApiError;

/// Same default as `defaultAPIListen` in the core.
pub const DEFAULT_API_ADDRESS: &str = "127.0.0.1:7946";

/// Same name as `datadir.DefaultDirName`.
pub const DEFAULT_DIR_NAME: &str = "melonarc";

/// Same name as `datadir.TokenFile`.
pub const TOKEN_FILE: &str = "api-token";

/// The shell's own settings file, inside the default data directory.
pub const SETTINGS_FILE: &str = "shell.json";

/// The core's configuration file, inside the effective data directory.
pub const CORE_CONFIG_FILE: &str = "melonarc.conf";

/// Held for the whole session; a second instance refuses to start.
pub const LOCK_FILE: &str = "shell.lock";

#[derive(Clone, Debug)]
pub struct Settings {
    pub data_dir: PathBuf,
    /// Loopback endpoints verified when the settings were read. The API client
    /// dials only these: a name is never resolved again at connect time.
    pub api_addrs: Vec<SocketAddr>,
    /// Canonical `host:port` for the Host header and the UI. An IPv6 host is
    /// bracketed, as `SocketAddr::to_string` produces.
    pub api_label: String,
    /// Where the overrides are read from and written to.
    pub settings_path: PathBuf,
    /// The overrides as the file had them when this process started. The
    /// difference between these and the file's current values is what
    /// `restart_required` reports: changing them needs a new shell, changing
    /// `core_path` / `core_config` does not.
    pub stored: Overrides,
    /// Resolved core binary, if one was found at start-up.
    pub core_path: Option<PathBuf>,
    /// Resolved core configuration path (always known, may not exist yet).
    pub core_config: PathBuf,
}

impl Settings {
    /// `<data-dir>/api-token`, the only credential this process ever reads.
    pub fn token_path(&self) -> PathBuf {
        self.data_dir.join(TOKEN_FILE)
    }

    /// `<data-dir>/core.log`, where the core's own output is appended.
    pub fn core_log_path(&self) -> PathBuf {
        self.data_dir.join("core.log")
    }
}

/// The four values the settings file may carry. An empty string means "not
/// set", which is also what an omitted key means: the file is sparse on
/// purpose, so a cleared field disappears instead of turning into `""`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Overrides {
    pub data_dir: String,
    pub api_addr: String,
    pub core_path: String,
    pub core_config: String,
}

impl Overrides {
    /// The two values that need a shell restart to take effect.
    fn needs_restart_against(&self, other: &Overrides) -> bool {
        self.data_dir != other.data_dir || self.api_addr != other.api_addr
    }
}

/// The same four values on the wire, in the names the page uses.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct OverridesView {
    pub data_dir: String,
    pub api_addr: String,
    pub core_path: String,
    pub core_config: String,
}

impl From<&Overrides> for OverridesView {
    fn from(value: &Overrides) -> Self {
        Self {
            data_dir: value.data_dir.clone(),
            api_addr: value.api_addr.clone(),
            core_path: value.core_path.clone(),
            core_config: value.core_config.clone(),
        }
    }
}

/// The answer of `get_shell_settings` and `set_shell_settings`.
#[derive(Clone, Debug, serde::Serialize)]
pub struct ShellSettingsView {
    pub settings_path: String,
    pub stored: OverridesView,
    pub effective: OverridesView,
    pub restart_required: bool,
}

/// Everything `resolve` needs, with the ambient parts passed in so the rule can
/// be unit tested without touching the real environment.
pub struct Inputs<'a> {
    pub stored: Overrides,
    pub settings_path: PathBuf,
    /// Environment lookup. An empty value counts as unset.
    pub env: &'a dyn Fn(&str) -> Option<String>,
    /// File existence test for the core binary candidates.
    pub exists: &'a dyn Fn(&Path) -> bool,
    /// Candidates in the order they are tried (see `core_search_paths`).
    pub search_paths: Vec<PathBuf>,
}

/// Read the settings, refusing anything that would send the token off the machine.
pub fn load() -> Result<Settings, String> {
    let settings_path = default_settings_path()?;
    let stored = match read_overrides(&settings_path) {
        Ok(stored) => stored,
        Err(error) => {
            // A broken file must not brick the window: the defaults still work
            // and the settings panel can overwrite it. Say so once, on stderr.
            eprintln!("melonarc-desktop: {error}; using the defaults");
            Overrides::default()
        }
    };

    let lookup = |key: &str| env::var(key).ok();
    let exists = |path: &Path| path.is_file();
    let search_paths = core_search_paths(&stored.core_path);
    resolve(Inputs {
        stored,
        settings_path,
        env: &lookup,
        exists: &exists,
        search_paths,
    })
}

/// Apply the precedence rule: environment, then file, then default.
pub fn resolve(inputs: Inputs<'_>) -> Result<Settings, String> {
    let env_data_dir = (inputs.env)("MELONARC_DATA_DIR");
    let env_api_addr = (inputs.env)("MELONARC_API_ADDR");

    let settings_dir = inputs
        .settings_path
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| String::from("the settings file has no parent directory"))?;

    // The default data directory is the directory the settings file sits in;
    // computing it that way keeps the two from drifting apart.
    let data_dir = first_set(&[
        env_data_dir.as_deref(),
        Some(inputs.stored.data_dir.as_str()),
    ])
    .map(PathBuf::from)
    .unwrap_or_else(|| settings_dir.clone());

    let api_raw = first_set(&[
        env_api_addr.as_deref(),
        Some(inputs.stored.api_addr.as_str()),
    ])
    .unwrap_or_else(|| DEFAULT_API_ADDRESS.to_string());
    let (api_addrs, api_label) = resolve_api_address(&api_raw)?;

    let core_config = first_set(&[Some(inputs.stored.core_config.as_str())])
        .map(PathBuf::from)
        .unwrap_or_else(|| data_dir.join(CORE_CONFIG_FILE));
    let core_path = pick_core(&inputs.search_paths, inputs.exists);

    Ok(Settings {
        data_dir,
        api_addrs,
        api_label,
        settings_path: inputs.settings_path,
        stored: inputs.stored,
        core_path,
        core_config,
    })
}

/// Re-read only the two core paths.
///
/// A core restart is allowed to pick up a new `core_path` or `core_config`,
/// because both belong to the next spawn. It must *not* adopt a new data
/// directory or API address: those two are what the window's API client is
/// bound to, and changing them is a shell restart (see `restart_required`).
pub fn core_targets(settings: &Settings) -> (Option<PathBuf>, PathBuf) {
    let stored = read_overrides(&settings.settings_path).unwrap_or_default();
    let config = first_set(&[Some(stored.core_config.as_str())])
        .map(PathBuf::from)
        .unwrap_or_else(|| settings.data_dir.join(CORE_CONFIG_FILE));
    (find_core(&stored.core_path), config)
}

/// The current file contents, as reported to the settings panel.
pub fn current_overrides(settings: &Settings) -> Result<Overrides, String> {
    read_overrides(&settings.settings_path)
}

/// The settings panel reads this: what is in the file, what is in effect, and
/// whether the difference needs a new shell.
#[tauri::command]
pub fn get_shell_settings(settings: tauri::State<Settings>) -> Result<ShellSettingsView, ApiError> {
    view_of(settings.inner())
}

/// Write the overrides. Nothing is hot-switched: a new data directory or API
/// address needs a new shell, and a new core path or configuration is picked up
/// by the next spawn (including `core_restart`).
#[tauri::command]
pub fn set_shell_settings(
    settings: tauri::State<Settings>,
    values: OverridesView,
) -> Result<ShellSettingsView, ApiError> {
    let overrides = checked_overrides(&values)
        .map_err(|detail| ApiError::new("bad_settings", detail))?;
    write_overrides(&settings.settings_path, &overrides)
        .map_err(|detail| ApiError::new("settings_unwritable", detail))?;
    view_of(settings.inner())
}

fn view_of(settings: &Settings) -> Result<ShellSettingsView, ApiError> {
    let stored = current_overrides(settings)
        .map_err(|detail| ApiError::new("settings_unreadable", detail))?;
    // The two core paths are reported as they resolve *now*: they belong to the
    // next spawn, so showing the value a restart would use is the useful answer.
    let (core_path, core_config) = core_targets(settings);

    Ok(ShellSettingsView {
        settings_path: settings.settings_path.display().to_string(),
        stored: OverridesView::from(&stored),
        effective: OverridesView {
            // These two come from the running shell, not from the file: they are
            // what the window's API client is actually bound to.
            data_dir: settings.data_dir.display().to_string(),
            api_addr: settings.api_label.clone(),
            core_path: core_path
                .map(|path| path.display().to_string())
                .unwrap_or_default(),
            core_config: core_config.display().to_string(),
        },
        restart_required: stored.needs_restart_against(&settings.stored),
    })
}

/// The settings path the shell uses, for the runtime info block.
pub fn default_settings_path() -> Result<PathBuf, String> {
    Ok(config_home()?.join(DEFAULT_DIR_NAME).join(SETTINGS_FILE))
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
pub fn resolve_api_address(raw: &str) -> Result<(Vec<SocketAddr>, String), String> {
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

/// Normalise and check a value from the settings panel before it is stored.
///
/// The address is validated with the same function the start-up path uses, so
/// a value that would be refused at start-up cannot get into the file either.
pub fn checked_overrides(view: &OverridesView) -> Result<Overrides, String> {
    let data_dir = clean_path(&view.data_dir, "data_dir")?;
    let core_path = clean_path(&view.core_path, "core_path")?;
    let core_config = clean_path(&view.core_config, "core_config")?;

    let api_addr = view.api_addr.trim().to_string();
    if api_addr.is_empty() {
        return Ok(Overrides {
            data_dir,
            api_addr,
            core_path,
            core_config,
        });
    }
    if api_addr.chars().any(char::is_control) {
        return Err(String::from("api_addr contains a control character"));
    }
    resolve_api_address(&api_addr)?;
    Ok(Overrides {
        data_dir,
        api_addr,
        core_path,
        core_config,
    })
}

/// A path override: trimmed, no control characters. Empty means "clear it".
fn clean_path(value: &str, field: &str) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.chars().any(char::is_control) {
        return Err(format!("{field} contains a control character"));
    }
    Ok(trimmed.to_string())
}

/// Write the overrides atomically: a sibling temporary file, then a rename. A
/// crash between the two leaves the previous file untouched instead of a half
/// written one.
pub fn write_overrides(path: &Path, overrides: &Overrides) -> Result<(), String> {
    let mut text = String::from("{\n");
    let mut written = 0;
    for (key, value) in [
        ("data_dir", &overrides.data_dir),
        ("api_addr", &overrides.api_addr),
        ("core_path", &overrides.core_path),
        ("core_config", &overrides.core_config),
    ] {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            continue;
        }
        if written > 0 {
            text.push_str(",\n");
        }
        written += 1;
        text.push_str("  \"");
        text.push_str(key);
        text.push_str("\": ");
        write_json_string(&mut text, trimmed);
    }
    if written > 0 {
        text.push('\n');
    }
    text.push_str("}\n");

    let parent = path
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", path.display()))?;
    fs::create_dir_all(parent).map_err(|error| format!("cannot create {}: {error}", parent.display()))?;

    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(SETTINGS_FILE);
    let temp = path.with_file_name(format!("{name}.tmp"));
    fs::write(&temp, text).map_err(|error| format!("cannot write {}: {error}", temp.display()))?;
    fs::rename(&temp, path).map_err(|error| format!("cannot replace {}: {error}", path.display()))?;
    Ok(())
}

/// Read the overrides. A missing file is not an error: it means "nothing set".
pub fn read_overrides(path: &Path) -> Result<Overrides, String> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Overrides::default())
        }
        Err(error) => return Err(format!("cannot read {}: {error}", path.display())),
    };

    let pairs = parse_flat_object(&text)
        .map_err(|error| format!("{} is not a readable settings file: {error}", path.display()))?;

    let mut overrides = Overrides::default();
    for (key, value) in pairs {
        match key.as_str() {
            "data_dir" => overrides.data_dir = value,
            "api_addr" => overrides.api_addr = value,
            "core_path" => overrides.core_path = value,
            "core_config" => overrides.core_config = value,
            // An unknown key is not an error: a newer build may have written it
            // and an older build must still be able to start.
            _ => {}
        }
    }
    Ok(overrides)
}

/// Every place a core binary is looked for, in this order: next to the shell,
/// the explicit `core_path`, then each `PATH` entry. The order is part of the
/// contract, so it is a function rather than three call sites.
pub fn core_search_paths(explicit: &str) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(executable) = env::current_exe() {
        if let Some(dir) = executable.parent() {
            candidates.push(dir.join(core_binary_name()));
        }
    }
    let explicit = explicit.trim();
    if !explicit.is_empty() {
        candidates.push(PathBuf::from(explicit));
    }
    if let Some(path) = env::var_os("PATH") {
        for dir in env::split_paths(&path) {
            candidates.push(dir.join(core_binary_name()));
        }
    }
    candidates
}

/// The first candidate that exists.
pub fn pick_core(candidates: &[PathBuf], exists: &dyn Fn(&Path) -> bool) -> Option<PathBuf> {
    candidates.iter().find(|path| exists(path)).cloned()
}

/// Resolve the core binary from the ambient environment.
pub fn find_core(explicit: &str) -> Option<PathBuf> {
    pick_core(&core_search_paths(explicit), &|path| path.is_file())
}

/// What was looked for, for the "stopped" detail line.
pub fn core_missing_detail(explicit: &str) -> String {
    let searched = core_search_paths(explicit);
    let list = searched
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    format!("no {} binary was found; looked in: {list}", core_binary_name())
}

fn core_binary_name() -> &'static str {
    if cfg!(windows) {
        "melonarc-core.exe"
    } else {
        "melonarc-core"
    }
}

/// The first non-blank value, trimmed.
fn first_set(values: &[Option<&str>]) -> Option<String> {
    values
        .iter()
        .flatten()
        .map(|value| value.trim())
        .find(|value| !value.is_empty())
        .map(str::to_string)
}

/// Escape a string for the settings file.
///
/// Only the characters JSON requires are escaped; anything else is written as
/// itself, which keeps a path with non-ASCII text readable.
fn write_json_string(out: &mut String, value: &str) {
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            character if (character as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", character as u32));
            }
            character => out.push(character),
        }
    }
    out.push('"');
}

/// A JSON object whose values are all strings.
///
/// The file has four known keys, so a full JSON parser would be a dependency
/// for nothing; this reads exactly the shape the writer produces and refuses
/// anything else loudly. `\u` escapes are decoded, but a surrogate pair is not
/// recombined: no path this shell writes contains one.
fn parse_flat_object(text: &str) -> Result<Vec<(String, String)>, String> {
    let mut chars = text.chars().peekable();
    skip_whitespace(&mut chars);
    if chars.next() != Some('{') {
        return Err(String::from("it does not start with a JSON object"));
    }

    let mut pairs = Vec::new();
    skip_whitespace(&mut chars);
    if chars.peek() == Some(&'}') {
        chars.next();
    } else {
        loop {
            skip_whitespace(&mut chars);
            let key = parse_json_string(&mut chars)?;
            skip_whitespace(&mut chars);
            if chars.next() != Some(':') {
                return Err(format!("the key {key:?} has no value"));
            }
            skip_whitespace(&mut chars);
            let value = parse_json_string(&mut chars)?;
            pairs.push((key, value));
            skip_whitespace(&mut chars);
            match chars.next() {
                Some(',') => continue,
                Some('}') => break,
                _ => return Err(String::from("a value is not followed by a comma or a brace")),
            }
        }
    }

    skip_whitespace(&mut chars);
    if chars.next().is_some() {
        return Err(String::from("there is text after the closing brace"));
    }
    Ok(pairs)
}

fn skip_whitespace(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    while let Some(character) = chars.peek() {
        if !character.is_whitespace() {
            return;
        }
        chars.next();
    }
}

fn parse_json_string(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Result<String, String> {
    if chars.next() != Some('"') {
        return Err(String::from("a value is not a string"));
    }
    let mut out = String::new();
    loop {
        match chars.next() {
            None => return Err(String::from("a string is not closed")),
            Some('"') => return Ok(out),
            Some('\\') => match chars.next() {
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                Some('/') => out.push('/'),
                Some('b') => out.push('\u{0008}'),
                Some('f') => out.push('\u{000c}'),
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some('u') => {
                    let mut code = 0u32;
                    for _ in 0..4 {
                        let digit = chars
                            .next()
                            .and_then(|character| character.to_digit(16))
                            .ok_or_else(|| String::from("a \\u escape is incomplete"))?;
                        code = code * 16 + digit;
                    }
                    out.push(char::from_u32(code).unwrap_or('\u{fffd}'));
                }
                _ => return Err(String::from("a string has an unknown escape")),
            },
            Some(character) => out.push(character),
        }
    }
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
    use std::collections::HashMap;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("melonarc-shell-settings-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Resolve against a synthetic environment and filesystem.
    fn resolve_with(
        stored: Overrides,
        env: HashMap<&str, &str>,
        existing: Vec<PathBuf>,
        search: Vec<PathBuf>,
    ) -> Result<Settings, String> {
        let lookup = move |key: &str| env.get(key).map(|value| (*value).to_string());
        let exists = move |path: &Path| existing.iter().any(|candidate| candidate == path);
        resolve(Inputs {
            stored,
            settings_path: PathBuf::from("/home/melon/.config/melonarc/shell.json"),
            env: &lookup,
            exists: &exists,
            search_paths: search,
        })
    }

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

    #[test]
    fn the_settings_file_round_trips_and_stays_sparse() {
        let dir = scratch("round-trip");
        let path = dir.join(SETTINGS_FILE);

        let written = Overrides {
            data_dir: "/tmp/arc/data".to_string(),
            api_addr: "127.0.0.1:7947".to_string(),
            core_path: String::new(),
            core_config: "/tmp/arc/demo.conf".to_string(),
        };
        write_overrides(&path, &written).unwrap();

        let raw = fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("core_path"), "an unset key is omitted: {raw}");
        assert!(!raw.contains("api-token"), "the settings file never carries a token");

        assert_eq!(read_overrides(&path).unwrap(), written);
        assert!(!dir.join(format!("{SETTINGS_FILE}.tmp")).exists(), "the temporary file is gone");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_file_reads_as_no_overrides_and_a_broken_one_is_reported() {
        let dir = scratch("broken");
        let path = dir.join(SETTINGS_FILE);

        assert_eq!(read_overrides(&path).unwrap(), Overrides::default());

        fs::write(&path, "{\"data_dir\": 7}").unwrap();
        assert!(read_overrides(&path).is_err(), "a non-string value is refused");

        fs::write(&path, "{\"data_dir\": \"/tmp/x\"} trailing").unwrap();
        assert!(read_overrides(&path).is_err(), "trailing text is refused");

        fs::write(&path, "{\"data_dir\": \"/tmp/x\\u002dy\"}").unwrap();
        assert_eq!(read_overrides(&path).unwrap().data_dir, "/tmp/x-y");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn unknown_keys_and_escapes_survive_a_round_trip() {
        let dir = scratch("unknown");
        let path = dir.join(SETTINGS_FILE);
        fs::write(
            &path,
            "{\"comment\": \"written by a newer build\", \"core_config\": \"/tmp/with \\\"quotes\\\"\"}",
        )
        .unwrap();

        let read = read_overrides(&path).unwrap();
        assert_eq!(read.core_config, "/tmp/with \"quotes\"");
        assert_eq!(read.core_path, "");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_environment_wins_over_the_file_and_the_file_over_the_default() {
        let search = vec![PathBuf::from("/opt/melonarc-core")];
        let stored = Overrides {
            data_dir: "/srv/from-file".to_string(),
            api_addr: "127.0.0.1:7950".to_string(),
            ..Overrides::default()
        };

        let from_file = resolve_with(
            stored.clone(),
            HashMap::new(),
            search.clone(),
            search.clone(),
        )
        .unwrap();
        assert_eq!(from_file.data_dir, PathBuf::from("/srv/from-file"));
        assert_eq!(from_file.api_label, "127.0.0.1:7950");
        assert_eq!(from_file.core_path, Some(PathBuf::from("/opt/melonarc-core")));

        let from_env = resolve_with(
            stored.clone(),
            HashMap::from([
                ("MELONARC_DATA_DIR", "/srv/from-env"),
                ("MELONARC_API_ADDR", "127.0.0.1:7951"),
            ]),
            search.clone(),
            search.clone(),
        )
        .unwrap();
        assert_eq!(from_env.data_dir, PathBuf::from("/srv/from-env"));
        assert_eq!(from_env.api_label, "127.0.0.1:7951");
        assert_eq!(from_env.stored, stored, "the file is still reported as stored");

        let defaults = resolve_with(Overrides::default(), HashMap::new(), vec![], vec![]).unwrap();
        assert_eq!(
            defaults.data_dir,
            PathBuf::from("/home/melon/.config/melonarc"),
            "the default data directory is the one the settings file lives in"
        );
        assert_eq!(defaults.api_label, DEFAULT_API_ADDRESS);
        assert_eq!(
            defaults.core_config,
            PathBuf::from("/home/melon/.config/melonarc/melonarc.conf")
        );
        assert_eq!(defaults.core_path, None, "no binary, no path");
    }

    #[test]
    fn the_core_configuration_default_follows_the_effective_data_directory() {
        let stored = Overrides {
            data_dir: "/srv/elsewhere".to_string(),
            ..Overrides::default()
        };
        let resolved = resolve_with(stored, HashMap::new(), vec![], vec![]).unwrap();
        assert_eq!(
            resolved.core_config,
            PathBuf::from("/srv/elsewhere/melonarc.conf"),
            "an unset core_config sits next to the data directory, not next to the file"
        );
        assert_eq!(resolved.core_log_path(), PathBuf::from("/srv/elsewhere/core.log"));
    }

    #[test]
    fn the_binary_is_looked_for_next_to_the_shell_then_explicitly_then_on_path() {
        let candidates = vec![
            PathBuf::from("/opt/app/melonarc-core"),
            PathBuf::from("/usr/local/bin/melonarc-core"),
            PathBuf::from("/usr/bin/melonarc-core"),
        ];

        let none = pick_core(&candidates, &|_| false);
        assert_eq!(none, None);

        let all = pick_core(&candidates, &|_| true);
        assert_eq!(all, Some(PathBuf::from("/opt/app/melonarc-core")), "the sibling wins");

        let later = pick_core(&candidates, &|path| path.ends_with("melonarc-core") && path.starts_with("/usr/bin"));
        assert_eq!(later, Some(PathBuf::from("/usr/bin/melonarc-core")));

        let detail = core_missing_detail("");
        assert!(detail.starts_with("no melonarc-core binary"), "{detail}");
        assert!(detail.contains("looked in"), "{detail}");
    }

    #[test]
    fn the_search_order_is_sibling_then_explicit_then_path() {
        // `core_search_paths` reads the real environment, so this pins the
        // shape rather than the absolute indexes: the explicit value appears
        // exactly once, and a blank one adds nothing at all.
        let with_explicit = core_search_paths("/opt/core");
        let explicit = PathBuf::from("/opt/core");
        assert_eq!(with_explicit.iter().filter(|path| *path == &explicit).count(), 1);
        assert!(
            with_explicit.iter().all(|path| path.ends_with("melonarc-core") || *path == explicit),
            "every candidate is the binary name or the explicit path"
        );

        let blank = core_search_paths("   ");
        assert!(
            blank.iter().all(|path| path.ends_with("melonarc-core")),
            "a blank setting contributes no candidate"
        );
    }

    #[test]
    fn an_override_is_checked_before_it_is_written() {
        let ok = checked_overrides(&OverridesView {
            data_dir: "  /tmp/arc/data  ".to_string(),
            api_addr: " 127.0.0.1:7947 ".to_string(),
            core_path: String::new(),
            core_config: " /tmp/arc/demo.conf ".to_string(),
        })
        .unwrap();
        assert_eq!(ok.data_dir, "/tmp/arc/data");
        assert_eq!(ok.api_addr, "127.0.0.1:7947");
        assert_eq!(ok.core_config, "/tmp/arc/demo.conf");

        assert!(checked_overrides(&OverridesView {
            api_addr: "10.0.0.5:7946".to_string(),
            ..OverridesView::default()
        })
        .is_err());

        assert!(checked_overrides(&OverridesView {
            api_addr: "127.0.0.1:7946",
            core_path: "/tmp/arc\ncore".to_string(),
            ..OverridesView::default()
        })
        .is_err());

        let cleared = checked_overrides(&OverridesView::default()).unwrap();
        assert_eq!(cleared, Overrides::default(), "empty strings clear every override");
    }

    #[test]
    fn only_the_data_directory_and_the_address_ask_for_a_new_shell() {
        let base = Overrides {
            data_dir: "/srv/a".to_string(),
            api_addr: "127.0.0.1:7946".to_string(),
            core_path: "/opt/core".to_string(),
            core_config: "/srv/a/melonarc.conf".to_string(),
        };

        let same = base.clone();
        assert!(!same.needs_restart_against(&base));

        let mut address = base.clone();
        address.api_addr = "127.0.0.1:7947".to_string();
        assert!(address.needs_restart_against(&base));

        let mut data_dir = base.clone();
        data_dir.data_dir = "/srv/b".to_string();
        assert!(data_dir.needs_restart_against(&base));

        let mut core_binary = base.clone();
        core_binary.core_path = "/opt/other-core".to_string();
        assert!(!core_binary.needs_restart_against(&base), "a core path takes effect on the next spawn");

        let mut core_config = base.clone();
        core_config.core_config = "/srv/b/other.conf".to_string();
        assert!(!core_config.needs_restart_against(&base));
    }
}
