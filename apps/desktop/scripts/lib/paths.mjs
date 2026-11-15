/**
 * Where the core keeps its state, mirrored from `internal/datadir`.
 *
 * The desktop shell (Rust) and the preview proxy (this script) must agree with
 * the Go implementation, because there is exactly one rule: an explicit setting
 * wins, otherwise the platform configuration directory plus the product name.
 * `test/paths.test.mjs` pins the rule; the Go side is the source of truth.
 */

import { isIP } from "node:net";
import os from "node:os";
import path from "node:path";

/** Same string as `datadir.DefaultDirName`. */
export const DEFAULT_DIR_NAME = "melonarc";

/** Same string as `datadir.TokenFile`. */
export const TOKEN_FILE = "api-token";

/**
 * The platform configuration directory, the way `os.UserConfigDir` defines it.
 *
 * @param {{ env?: NodeJS.ProcessEnv, platform?: NodeJS.Platform, home?: string }} [options]
 * @returns {string}
 */
export function configHome({ env = process.env, platform = process.platform, home = os.homedir() } = {}) {
  if (platform === "win32") {
    const appData = env.APPDATA;
    return appData && appData !== "" ? appData : path.join(home, "AppData", "Roaming");
  }
  if (platform === "darwin") return path.join(home, "Library", "Application Support");
  const xdg = env.XDG_CONFIG_HOME;
  if (xdg && xdg !== "") return xdg;
  return path.join(home, ".config");
}

/**
 * @param {{ explicit?: string | null, env?: NodeJS.ProcessEnv, platform?: NodeJS.Platform, home?: string }} [options]
 * @returns {string}
 */
export function resolveDataDir({ explicit = null, env = process.env, platform = process.platform, home = os.homedir() } = {}) {
  const configured = typeof explicit === "string" ? explicit.trim() : "";
  const dir = configured !== "" ? configured : path.join(configHome({ env, platform, home }), DEFAULT_DIR_NAME);
  return path.resolve(dir);
}

/**
 * @param {string} dataDir
 * @returns {string}
 */
export function tokenPath(dataDir) {
  return path.join(dataDir, TOKEN_FILE);
}

/**
 * Split `host:port` into its parts. IPv6 must be bracketed and is canonicalised
 * through the URL parser (so `0:0:0:0:0:0:0:1` becomes `::1`); the label is
 * always the canonical bracket form. Loopback validation lives in
 * `address.mjs`, which also decides whether the host may be used at all.
 *
 * @param {string} address
 * @returns {{ host: string, port: number, label: string }}
 */
export function parseAddress(address) {
  const value = String(address ?? "").trim();
  const match = /^(\[[^\]]+\]|[^:\[\]]+):(\d+)$/.exec(value);
  if (!match) throw new Error(`not an address: ${value}`);
  const port = Number(match[2]);
  if (!Number.isInteger(port) || port <= 0 || port > 65535) throw new Error(`not a port: ${value}`);

  const bracketed = match[1].startsWith("[");
  let host = bracketed ? match[1].slice(1, -1) : match[1];
  const family = isIP(host);
  if (family === 6) {
    if (!bracketed) throw new Error(`not an address: ${value}`);
    host = new URL(`http://[${host}]:${port}/`).hostname.slice(1, -1);
  } else if (bracketed) {
    throw new Error(`not an address: ${value}`);
  }
  const label = family === 6 ? `[${host}]:${port}` : `${host}:${port}`;
  return { host, port, label };
}
