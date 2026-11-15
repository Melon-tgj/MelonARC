/**
 * Local preview server: the stand-in for the desktop shell.
 *
 * It serves the built frontend and adds a `/bridge` prefix that forwards to the
 * core's loopback API with the token read from `<data-dir>/api-token`. The token
 * never reaches the page — the same property the Rust shell provides — which is
 * what makes this a usable way to look at the real data without building the
 * native window.
 *
 * Development only. Nothing here is part of a distribution.
 *
 *   node scripts/dev-preview.mjs [--port 5173] [--api 127.0.0.1:7946] [--data-dir PATH] [--root dist]
 */

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

const here = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(here, "..");

assertDevelopmentOnly();
const options = parseArgs(process.argv.slice(2));
const dataDir = resolveDataDir({ explicit: options.dataDir });
const tokenFile = tokenPath(dataDir);
// Resolve once, at startup: the upstream request then dials this verified IP
// literal and never re-resolves a name that might answer differently later.
const api = await resolveAddress(options.api);

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
      development_only: true,
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
    api: process.env.MELONARC_API_ADDR ?? "127.0.0.1:7946",
    dataDir: process.env.MELONARC_DATA_DIR ?? null,
    root: path.join(appRoot, "dist"),
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
    else if (flag === "--help" || flag === "-h") {
      console.log("usage: node scripts/dev-preview.mjs [--port 5173] [--api 127.0.0.1:7946] [--data-dir PATH] [--root dist]");
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
});
