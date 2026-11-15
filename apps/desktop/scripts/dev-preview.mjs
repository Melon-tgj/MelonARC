/**
 * Local preview server: the stand-in for the desktop shell.
 *
 * It serves the built frontend and adds a `/bridge` prefix that forwards to the
 * core's loopback API with the token read from `<data-dir>/api-token`. The token
 * never reaches the page — the same property the Rust shell provides — which is
 * what makes this a usable way to look at the real data without building the
 * native window.
 *
 * It also stands in for the parts of the shell that are not about HTTP: the
 * settings file (`/bridge/shell/settings`) and, when given `--core`, the child
 * process (`/bridge/shell/status`, `/bridge/shell/restart`). Without `--core`
 * nothing is hosted, and the status is a real probe of the core a developer
 * started by hand — never an invented pid.
 *
 * Development only. Nothing here is part of a distribution.
 *
 *   node scripts/dev-preview.mjs [--port 5173] [--api 127.0.0.1:7946]
 *        [--data-dir PATH] [--root dist] [--core PATH] [--core-config PATH]
 */

import { existsSync } from "node:fs";
import http from "node:http";
import { readFile, stat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { resolveDataDir, tokenPath } from "./lib/paths.mjs";
import {
  assertDevelopmentOnly,
  resolveAddress,
  upstreamRequestOptions,
  validateBridgeRequest,
  validateBridgeTarget,
} from "./lib/address.mjs";
import {
  coreConfigFor,
  readShellSettings,
  resolveShell,
  settingsPath,
  writeShellSettings,
} from "./lib/shell-settings.mjs";
import { createSupervisor, probeCore } from "./lib/supervisor.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(here, "..");

assertDevelopmentOnly();
const options = parseArgs(process.argv.slice(2));

/**
 * The shell settings file, read once so the bridge starts with what the shell
 * would start with. A damaged file is reported and ignored, like the shell does:
 * the preview must come up even when a hand edit went wrong.
 */
const settingsFile = settingsPath();
let storedAtStart;
try {
  storedAtStart = readShellSettings(settingsFile);
} catch (error) {
  console.warn(`preview: ${error.message}; using the defaults`);
  storedAtStart = { dataDir: "", apiAddr: "", corePath: "", coreConfig: "" };
}

// `--data-dir` / `--api` (and the environment variables they default to) are
// the bridge's equivalent of the shell's environment layer: they win over the
// file, and the file wins over the platform default.
const shell = resolveShell({
  stored: storedAtStart,
  explicit: { dataDir: options.dataDir, apiAddr: options.api },
  defaults: { dataDir: resolveDataDir({}), apiAddr: "127.0.0.1:7946" },
});

const dataDir = path.resolve(shell.dataDir);
const tokenFile = tokenPath(dataDir);
// Resolve once, at startup: the upstream request then dials this verified IP
// literal and never re-resolves a name that might answer differently later.
const api = await resolveAddress(shell.apiAddr);

const coreConfig = path.resolve(options.coreConfig || coreConfigFor(storedAtStart, dataDir));

/** Only a bridge that was told which binary to run hosts one. */
const supervisor = options.core
  ? createSupervisor({
      corePath: path.resolve(options.core),
      coreConfig,
      api,
      tokenPath: tokenFile,
      logPath: path.join(dataDir, "core.log"),
    })
  : null;

if (supervisor) supervisor.start();

const MIME = new Map([
  [".html", "text/html; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"],
  [".mjs", "text/javascript; charset=utf-8"],
  [".css", "text/css; charset=utf-8"],
  [".json", "application/json; charset=utf-8"],
  [".png", "image/png"],
  [".webp", "image/webp"],
  [".svg", "image/svg+xml"],
  [".ico", "image/x-icon"],
]);

const server = http.createServer((req, res) => {
  const url = new URL(req.url ?? "/", "http://127.0.0.1");

  if (url.pathname.startsWith("/bridge")) {
    // The page is served from this same loopback origin. Reject a Host that
    // names anything else (DNS rebinding) and an Origin that is not ours
    // (a cross-site write); a browser's same-origin POST always carries one.
    const port = server.address()?.port ?? options.port;
    const check = validateBridgeRequest({
      hostHeader: req.headers.host,
      originHeader: req.headers.origin,
      method: req.method,
      port,
    });
    if (!check.ok) {
      sendJson(res, 403, { error: { code: check.code, message: "the preview bridge only accepts local requests" }, proxied: false });
      return;
    }
  }

  if (url.pathname === "/bridge/runtime") {
    sendJson(res, 200, {
      mode: "preview",
      api_address: api.label,
      data_dir: dataDir,
      token_path: tokenFile,
      settings_path: settingsFile,
      supervised: supervisor !== null,
      development_only: true,
    });
    return;
  }

  if (url.pathname.startsWith("/bridge/shell/")) {
    handleShell(req, res, url.pathname).catch((error) => {
      sendJson(res, 500, { error: { code: "internal", message: String(error?.message ?? error) } });
    });
    return;
  }

  if (url.pathname.startsWith("/bridge/")) {
    const apiPath = url.pathname.slice("/bridge".length);
    const target = validateBridgeTarget({ method: req.method, path: apiPath });
    if (!target.ok) {
      sendJson(res, 403, { error: { code: target.code, message: "the preview bridge does not forward that request" }, proxied: false });
      return;
    }
    proxy(req, res, apiPath);
    return;
  }

  serveStatic(res, url.pathname);
});

/**
 * The process, the settings file, and the restart button.
 *
 * @param {http.IncomingMessage} req
 * @param {http.ServerResponse} res
 * @param {string} pathname
 */
async function handleShell(req, res, pathname) {
  const method = String(req.method ?? "GET").toUpperCase();

  if (pathname === "/bridge/shell/status") {
    if (method !== "GET") return methodNotAllowed(res, "GET");
    sendJson(res, 200, supervisor ? supervisor.status() : await probeStatus());
    return;
  }

  if (pathname === "/bridge/shell/restart") {
    if (method !== "POST") return methodNotAllowed(res, "POST");
    if (!supervisor) {
      // Nothing to restart: the core was started by hand, and the bridge will
      // not kill a process it does not own.
      sendJson(res, 409, {
        error: { code: "not_managed", message: "this bridge does not host a core; start it with --core" },
      });
      return;
    }
    sendJson(res, 200, await supervisor.restart());
    return;
  }

  if (pathname === "/bridge/shell/settings") {
    if (method === "GET") {
      let view;
      try {
        view = shellSettingsView();
      } catch (error) {
        // Same refusal as the shell: a file nobody can read is reported, not
        // silently replaced by an empty set of values.
        sendJson(res, 500, { error: { code: "settings_unreadable", message: error.message } });
        return;
      }
      sendJson(res, 200, view);
      return;
    }
    if (method !== "POST") return methodNotAllowed(res, "GET, POST");

    const body = await readJsonBody(req);
    if (!body || typeof body !== "object") {
      sendJson(res, 400, { error: { code: "bad_request", message: "a JSON object is expected" } });
      return;
    }
    try {
      writeShellSettings(settingsFile, {
        dataDir: body.data_dir,
        apiAddr: body.api_addr,
        corePath: body.core_path,
        coreConfig: body.core_config,
      });
    } catch (error) {
      // The same refusal the shell gives: a value that would send the token off
      // this machine never reaches the file.
      sendJson(res, 400, { error: { code: "bad_settings", message: error.message } });
      return;
    }
    sendJson(res, 200, shellSettingsView());
    return;
  }

  sendJson(res, 404, { error: { code: "not_found", message: pathname } });
}

/**
 * The answer when this bridge hosts nothing: a real probe of the core that is
 * running, with no pid and no start time — those are only known to whoever
 * started it.
 *
 * @returns {Promise<any>}
 */
async function probeStatus() {
  const reachable = await probeCore({ api, tokenPath: tokenFile });
  return {
    state: reachable ? "running" : "stopped",
    pid: null,
    started_at_unix_ms: null,
    restarts: 0,
    detail: reachable
      ? `the core at ${api.label} answers but was not started by this bridge`
      : `no core answers /v1/status at ${api.label}`,
  };
}

/**
 * What the settings panel reads: the file, the values in effect, and whether the
 * two differ in a way that needs a restart.
 *
 * Throws when the file cannot be read, so the caller can answer with an error
 * instead of a picture of settings that are not there.
 */
function shellSettingsView() {
  const current = readShellSettings(settingsFile);

  // The path this bridge would actually run, or nothing at all: a
  // `--core` that points at a missing file is a stop reason, not an effective
  // setting. Same rule as the shell, which reports the binary it found.
  const requested = supervisor ? path.resolve(options.core) : current.corePath;
  const corePath = requested && existsSync(requested) ? requested : "";

  return {
    settings_path: settingsFile,
    stored: {
      data_dir: current.dataDir,
      api_addr: current.apiAddr,
      core_path: current.corePath,
      core_config: current.coreConfig,
    },
    effective: {
      data_dir: dataDir,
      api_addr: api.label,
      core_path: corePath,
      core_config: supervisor ? coreConfig : coreConfigFor(current, dataDir),
    },
    // Same rule as the shell: the two values the bridge read at start-up.
    restart_required:
      current.dataDir !== storedAtStart.dataDir || current.apiAddr !== storedAtStart.apiAddr,
  };
}

/**
 * Forward one request to the core, adding the bearer token and nothing else.
 *
 * @param {http.IncomingMessage} req
 * @param {http.ServerResponse} res
 * @param {string} apiPath
 */
function proxy(req, res, apiPath) {
  readToken()
    .then((token) => {
      const requestOptions = upstreamRequestOptions({
        api,
        method: req.method ?? "GET",
        path: apiPath,
        contentType: req.headers["content-type"],
        contentLength: req.headers["content-length"],
      });
      requestOptions.headers.authorization = `Bearer ${token}`;

      const upstream = http.request(
        requestOptions,
        (answer) => {
          // Only the body type is forwarded. A Location or Set-Cookie from the
          // core must not become a redirect that carries the browser elsewhere.
          res.writeHead(answer.statusCode ?? 502, {
            "content-type": answer.headers["content-type"] ?? "application/octet-stream",
            "cache-control": "no-store",
          });
          answer.pipe(res);
        },
      );

      upstream.setTimeout(10_000, () => upstream.destroy(new Error("the core did not answer in time")));
      upstream.on("error", (error) => sendProxyFailure(res, "core_unreachable", error.message));
      req.pipe(upstream);
    })
    .catch(() => sendProxyFailure(res, "token_missing", `no token file at ${tokenFile}`));
}

/** @returns {Promise<string>} */
async function readToken() {
  const raw = await readFile(tokenFile, "utf8");
  const token = raw.trim();
  if (token === "") throw new Error("empty token file");
  return token;
}

/**
 * @param {http.IncomingMessage} req
 * @param {number} [limit]
 * @returns {Promise<any>}
 */
function readJsonBody(req, limit = 64 * 1024) {
  return new Promise((resolve) => {
    let size = 0;
    const chunks = [];
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > limit) {
        resolve(null);
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      const text = Buffer.concat(chunks).toString("utf8");
      if (text.trim() === "") {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(text));
      } catch {
        resolve(null);
      }
    });
    req.on("error", () => resolve(null));
  });
}

/**
 * @param {http.ServerResponse} res
 * @param {string} allowed
 */
function methodNotAllowed(res, allowed) {
  res.setHeader("allow", allowed);
  sendJson(res, 405, { error: { code: "bad_method", message: `use ${allowed}` } });
}

/**
 * @param {http.ServerResponse} res
 * @param {string} code
 * @param {string} message
 */
function sendProxyFailure(res, code, message) {
  if (res.headersSent) {
    res.destroy();
    return;
  }
  sendJson(res, 502, { error: { code, message }, proxied: false });
}

/**
 * @param {http.ServerResponse} res
 * @param {string} pathname
 */
async function serveStatic(res, pathname) {
  const relative = pathname === "/" ? "/index.html" : decodeURIComponent(pathname);
  const target = path.resolve(options.root, `.${relative}`);

  if (!target.startsWith(options.root)) {
    sendText(res, 403, "forbidden");
    return;
  }

  try {
    const info = await stat(target);
    if (info.isDirectory()) throw new Error("directory");
    const body = await readFile(target);
    res.writeHead(200, {
      "content-type": MIME.get(path.extname(target)) ?? "application/octet-stream",
      "cache-control": "no-store",
    });
    res.end(body);
  } catch {
    sendText(res, 404, "not found");
  }
}

function sendJson(res, status, value) {
  const body = Buffer.from(JSON.stringify(value), "utf8");
  res.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
  res.end(body);
}

function sendText(res, status, text) {
  res.writeHead(status, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" });
  res.end(text);
}

function parseArgs(argv) {
  const parsed = {
    port: 5173,
    // Kept apart from the file on purpose: `resolveShell` decides the order,
    // and an empty string here means "not given on the command line".
    api: process.env.MELONARC_API_ADDR ?? "",
    dataDir: process.env.MELONARC_DATA_DIR ?? "",
    root: path.join(appRoot, "dist"),
    core: "",
    coreConfig: "",
  };

  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    const next = () => {
      const value = argv[index + 1];
      if (value === undefined) throw new Error(`${flag} needs a value`);
      index += 1;
      return value;
    };
    if (flag === "--port") parsed.port = Number(next());
    else if (flag === "--api") parsed.api = next();
    else if (flag === "--data-dir") parsed.dataDir = next();
    else if (flag === "--root") parsed.root = path.resolve(next());
    else if (flag === "--core") parsed.core = next();
    else if (flag === "--core-config") parsed.coreConfig = next();
    else if (flag === "--help" || flag === "-h") {
      console.log(
        "usage: node scripts/dev-preview.mjs [--port 5173] [--api 127.0.0.1:7946] [--data-dir PATH] [--root dist] [--core PATH] [--core-config PATH]",
      );
      process.exit(0);
    } else throw new Error(`unknown flag: ${flag}`);
  }

  parsed.root = path.resolve(parsed.root);
  return parsed;
}

server.listen(options.port, "127.0.0.1", () => {
  const { port } = server.address();
  console.log(`preview          http://127.0.0.1:${port}/`);
  console.log(`  frontend       ${path.relative(appRoot, options.root) || "."}/`);
  console.log(`  core api       ${api.label}`);
  console.log(`  data dir       ${dataDir}`);
  console.log(`  token file     ${tokenFile}`);
  console.log(`  settings file  ${settingsFile}`);
  console.log(`  core process   ${supervisor ? `supervised (${path.resolve(options.core)})` : "not hosted"}`);
});

/**
 * Stop the child before the bridge goes away, so a development session does not
 * leave a core listening on the API port with nobody watching it.
 */
let closing = false;
async function shutdown() {
  if (closing) return;
  closing = true;
  server.close();
  if (supervisor) await supervisor.shutdown();
  process.exit(0);
}

process.on("SIGINT", () => void shutdown());
process.on("SIGTERM", () => void shutdown());
