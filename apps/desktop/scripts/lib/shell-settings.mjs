/**
 * The shell settings file, for the preview bridge.
 *
 * This mirrors `src-tauri/src/settings.rs`: the same path
 * (`<config-home>/melonarc/shell.json`), the same four optional keys, the same
 * precedence (environment / command line, then the file, then the default) and
 * the same checks before a value is written. The bridge is the shell's stand-in
 * during development, so it has to read and write exactly what the shell does —
 * otherwise a value saved in the browser would not be the value the shell uses.
 *
 * The file never carries the token.
 *
 * Development only. None of this is part of a distribution.
 */

import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import path from "node:path";

import { isLoopbackIP } from "./address.mjs";
import { DEFAULT_DIR_NAME, configHome, parseAddress } from "./paths.mjs";

/** Same name as `SETTINGS_FILE` in the Rust shell. */
export const SETTINGS_FILE = "shell.json";

/** Same name as `CORE_CONFIG_FILE` in the Rust shell. */
export const CORE_CONFIG_FILE = "melonarc.conf";

/** The four keys, in the order the file is written. */
const KEYS = [
  ["data_dir", "dataDir"],
  ["api_addr", "apiAddr"],
  ["core_path", "corePath"],
  ["core_config", "coreConfig"],
];

/** @param {{ env?: NodeJS.ProcessEnv, platform?: NodeJS.Platform, home?: string }} [options] */
export function settingsPath({ env = process.env, platform = process.platform, home } = {}) {
  return path.join(configHome({ env, platform, home }), DEFAULT_DIR_NAME, SETTINGS_FILE);
}

/**
 * Read the file. A missing file is "nothing set", not an error; anything that
 * parses to something other than an object of strings is an error, so a damaged
 * file is reported instead of silently ignored.
 *
 * @param {string} file
 * @returns {{ dataDir: string, apiAddr: string, corePath: string, coreConfig: string }}
 */
export function readShellSettings(file) {
  const blank = { dataDir: "", apiAddr: "", corePath: "", coreConfig: "" };
  if (!existsSync(file)) return blank;

  const raw = readFileSync(file, "utf8");
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new Error(`${file} is not valid JSON: ${error.message}`);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`${file} is not a JSON object`);
  }

  const out = { ...blank };
  for (const [wire, local] of KEYS) {
    const value = parsed[wire];
    if (value === undefined) continue;
    if (typeof value !== "string") throw new Error(`${file}: ${wire} is not a string`);
    out[local] = value;
  }
  return out;
}

/**
 * Write the file atomically: a sibling temporary file, then a rename.
 *
 * Empty values are omitted, exactly like the Rust writer, so clearing a field
 * removes the key instead of storing `""`.
 *
 * @param {string} file
 * @param {{ dataDir?: string, apiAddr?: string, corePath?: string, coreConfig?: string }} overrides
 * @returns {{ dataDir: string, apiAddr: string, corePath: string, coreConfig: string }}
 */
export function writeShellSettings(file, overrides) {
  const cleaned = cleanOverrides(overrides);
  const body = {};
  for (const [wire, local] of KEYS) {
    if (cleaned[local] !== "") body[wire] = cleaned[local];
  }

  mkdirSync(path.dirname(file), { recursive: true });
  const temp = path.join(path.dirname(file), `${path.basename(file)}.tmp`);
  writeFileSync(temp, `${JSON.stringify(body, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  renameSync(temp, file);
  return cleaned;
}

/**
 * Trim and check a set of overrides before they are written.
 *
 * @param {{ dataDir?: string, apiAddr?: string, corePath?: string, coreConfig?: string }} input
 * @returns {{ dataDir: string, apiAddr: string, corePath: string, coreConfig: string }}
 */
export function cleanOverrides(input) {
  const values = {
    dataDir: String(input?.dataDir ?? "").trim(),
    apiAddr: String(input?.apiAddr ?? "").trim(),
    corePath: String(input?.corePath ?? "").trim(),
    coreConfig: String(input?.coreConfig ?? "").trim(),
  };

  for (const [field, value] of Object.entries(values)) {
    if (/[\u0000-\u001f\u007f]/.test(value)) {
      throw new Error(`${field} contains a control character`);
    }
  }
  if (values.apiAddr !== "" && !isLoopbackText(values.apiAddr)) {
    throw new Error(
      `api address ${values.apiAddr} is not a loopback address; the token never leaves this machine`,
    );
  }
  return values;
}

/**
 * Is this `host:port` a loopback endpoint the bridge may use?
 *
 * A literal is decided by IP type. `localhost` is accepted here and verified by
 * `resolveAddress` at start-up, which is where the resolution actually happens.
 *
 * @param {string} text
 * @returns {boolean}
 */
export function isLoopbackText(text) {
  let parsed;
  try {
    parsed = parseAddress(text);
  } catch {
    return false;
  }
  return isLoopbackIP(parsed.host) || parsed.host.toLowerCase() === "localhost";
}

/**
 * Apply the precedence rule the shell uses: an explicit start-up value wins,
 * then the file, then the default.
 *
 * `explicit` is what the bridge was started with (`--data-dir`, `--api`, or the
 * environment variables, which `dev-preview.mjs` folds into the same layer).
 *
 * @param {{
 *   stored: { dataDir: string, apiAddr: string, corePath: string, coreConfig: string },
 *   explicit?: { dataDir?: string | null, apiAddr?: string | null },
 *   defaults: { dataDir: string, apiAddr: string },
 * }} input
 * @returns {{ dataDir: string, apiAddr: string }}
 */
export function resolveShell({ stored, explicit = {}, defaults }) {
  return {
    dataDir: firstSet(explicit.dataDir, stored?.dataDir) ?? defaults.dataDir,
    apiAddr: firstSet(explicit.apiAddr, stored?.apiAddr) ?? defaults.apiAddr,
  };
}

/**
 * The value the core would use if it were started now: the file's `core_config`
 * or the default next to the data directory.
 *
 * @param {{ coreConfig: string }} stored
 * @param {string} dataDir
 */
export function coreConfigFor(stored, dataDir) {
  return firstSet(stored?.coreConfig) ?? path.join(dataDir, CORE_CONFIG_FILE);
}

/** @param {...(string | null | undefined)} values */
function firstSet(...values) {
  for (const value of values) {
    if (typeof value !== "string") continue;
    const trimmed = value.trim();
    if (trimmed !== "") return trimmed;
  }
  return null;
}
