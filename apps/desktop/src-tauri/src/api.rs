//! The only place the API token is used.
//!
//! The window asks for a path; this module reads `<data-dir>/api-token`, opens a
//! connection to the loopback API, adds the `Authorization` header and returns
//! the raw answer. The page never receives the token, cannot ask for it, and
//! never learns it exists beyond the path that is shown in the offline notice.
//!
//! The client is hand written on top of `std::net` on purpose: the traffic is
//! loopback HTTP/1.1 with JSON bodies, so a full HTTP stack would add a
//! dependency tree and a TLS configuration that cannot ever be used here. What
//! is needed instead is strictness — a short allow list of methods, one
//! validated request target, `Connection: close`, bounded reads.

use crate::settings::Settings;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_BODY: usize = 4 * 1024 * 1024;
const MAX_TOKEN: usize = 512;
const MAX_PATH: usize = 2048;

/// The answer of the core, whatever its status: a 401 is an answer, not a
/// transport failure, and the UI decides what to say about it.
#[derive(serde::Serialize)]
pub struct ApiReply {
    pub status: u16,
    pub body: String,
}

/// A request that could not be made at all. `code` is part of the UI contract.
#[derive(serde::Serialize)]
pub struct ApiError {
    pub code: String,
    pub detail: String,
}

impl ApiError {
    fn new(code: &str, detail: impl Into<String>) -> Self {
        Self {
            code: code.to_string(),
            detail: detail.into(),
        }
    }
}

/// Where the shell thinks the core is; no secret is part of it.
#[derive(serde::Serialize)]
pub struct RuntimeInfo {
    pub api_address: String,
    pub data_dir: String,
    pub token_path: String,
}

#[tauri::command]
pub fn api_request(
    settings: tauri::State<Settings>,
    method: String,
    path: String,
    body: Option<String>,
) -> Result<ApiReply, ApiError> {
    send(settings.inner(), &method, &path, body.as_deref())
}

#[tauri::command]
pub fn runtime_info(settings: tauri::State<Settings>) -> RuntimeInfo {
    RuntimeInfo {
        api_address: settings.api_label.clone(),
        data_dir: settings.data_dir.display().to_string(),
        token_path: settings.token_path().display().to_string(),
    }
}

fn send(
    settings: &Settings,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> Result<ApiReply, ApiError> {
    let method = method.trim().to_ascii_uppercase();
    if method != "GET" && method != "POST" {
        return Err(ApiError::new(
            "bad_request",
            format!("method {method} is not used by this shell"),
        ));
    }
    validate_path(path)?;

    let token = read_token(settings)?;
    let mut stream = connect(settings)?;

    let request = build_request(&method, path, settings, &token, body);
    stream
        .write_all(request.as_bytes())
        .and_then(|()| stream.flush())
        .map_err(|error| {
            ApiError::new(
                "core_unreachable",
                format!("sending the request to {} failed: {error}", settings.api_label),
            )
        })?;

    let raw = read_all(&mut stream)?;
    let (status, body) = parse_response(&raw)?;
    Ok(ApiReply { status, body })
}

/// A request target must stay a request target: no scheme, no whitespace, no
/// control characters that could end the request line early.
fn validate_path(path: &str) -> Result<(), ApiError> {
    if !path.starts_with('/') {
        return Err(ApiError::new("bad_request", "the path must start with /"));
    }
    if path.len() > MAX_PATH {
        return Err(ApiError::new("bad_request", "the path is too long"));
    }
    let forbidden = path
        .bytes()
        .any(|byte| byte < 0x20 || byte == 0x7f || byte == b' ' || byte == b'#');
    if forbidden {
        return Err(ApiError::new("bad_request", "the path contains a character that is not allowed"));
    }
    Ok(())
}

fn read_token(settings: &Settings) -> Result<String, ApiError> {
    let path = settings.token_path();
    let raw = fs::read_to_string(&path).map_err(|_| {
        ApiError::new(
            "token_missing",
            format!("no token file at {}", path.display()),
        )
    })?;
    let token = raw.trim().to_string();
    if token.is_empty() {
        return Err(ApiError::new(
            "token_missing",
            format!("the token file at {} is empty", path.display()),
        ));
    }
    if token.len() > MAX_TOKEN {
        return Err(ApiError::new(
            "bad_response",
            format!("the token file at {} is larger than a token", path.display()),
        ));
    }
    Ok(token)
}

fn connect(settings: &Settings) -> Result<TcpStream, ApiError> {
    let addresses = (settings.api_host.as_str(), settings.api_port)
        .to_socket_addrs()
        .map_err(|error| {
            ApiError::new(
                "core_unreachable",
                format!("cannot resolve {}: {error}", settings.api_label),
            )
        })?;

    let mut last = String::from("no address resolved");
    for address in addresses {
        match TcpStream::connect_timeout(&address, CONNECT_TIMEOUT) {
            Ok(stream) => {
                let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
                let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
                return Ok(stream);
            }
            Err(error) => last = error.to_string(),
        }
    }

    Err(ApiError::new(
        "core_unreachable",
        format!("cannot connect to {}: {last}", settings.api_label),
    ))
}

fn build_request(
    method: &str,
    path: &str,
    settings: &Settings,
    token: &str,
    body: Option<&str>,
) -> String {
    let mut request = String::with_capacity(256 + path.len() + body.map_or(0, str::len));
    request.push_str(method);
    request.push(' ');
    request.push_str(path);
    request.push_str(" HTTP/1.1\r\nHost: ");
    request.push_str(&settings.api_label);
    request.push_str("\r\nAuthorization: Bearer ");
    request.push_str(token);
    request.push_str("\r\nAccept: application/json\r\nConnection: close\r\n");
    if let Some(payload) = body {
        request.push_str("Content-Type: application/json\r\nContent-Length: ");
        request.push_str(&payload.len().to_string());
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    if let Some(payload) = body {
        request.push_str(payload);
    }
    request
}

fn read_all(stream: &mut TcpStream) -> Result<Vec<u8>, ApiError> {
    let mut collected = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                collected.extend_from_slice(&buffer[..read]);
                if collected.len() > MAX_BODY {
                    return Err(ApiError::new(
                        "bad_response",
                        "the answer is larger than this shell accepts",
                    ));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(ApiError::new(
                    "core_unreachable",
                    format!("reading the answer failed: {error}"),
                ))
            }
        }
    }
    Ok(collected)
}

/// Split a raw HTTP/1.1 answer into its status and its body.
///
/// The core answers with `Content-Length`; chunked framing is decoded anyway so
/// a future handler that streams does not silently corrupt the JSON.
fn parse_response(raw: &[u8]) -> Result<(u16, String), ApiError> {
    let split = find(raw, b"\r\n\r\n").ok_or_else(|| {
        ApiError::new("bad_response", "the answer has no header block")
    })?;
    let head = String::from_utf8_lossy(&raw[..split]);
    let mut body = raw[split + 4..].to_vec();

    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| ApiError::new("bad_response", format!("unreadable status line: {status_line:?}")))?;

    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        if name == "content-length" {
            content_length = value.parse().ok();
        } else if name == "transfer-encoding" && value.to_ascii_lowercase().contains("chunked") {
            chunked = true;
        }
    }

    if chunked {
        body = dechunk(&body);
    } else if let Some(length) = content_length {
        if body.len() > length {
            body.truncate(length);
        }
    }

    Ok((status, String::from_utf8_lossy(&body).into_owned()))
}

fn dechunk(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut rest = input;
    loop {
        let Some(end) = find(rest, b"\r\n") else { break };
        let line = String::from_utf8_lossy(&rest[..end]);
        let size_text = line.split(';').next().unwrap_or("").trim();
        let Ok(size) = usize::from_str_radix(size_text, 16) else {
            break;
        };
        rest = &rest[end + 2..];
        if size == 0 {
            break;
        }
        if rest.len() < size {
            out.extend_from_slice(rest);
            break;
        }
        out.extend_from_slice(&rest[..size]);
        rest = &rest[size..];
        if rest.starts_with(b"\r\n") {
            rest = &rest[2..];
        }
    }
    out
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|window| window == needle)
}
