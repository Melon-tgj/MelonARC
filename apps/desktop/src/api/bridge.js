/**
 * The two transports the client can use, and how one is chosen.
 *
 * Tauri: the shell reads <data-dir>/api-token and performs the request, so the
 * credential stays in the native process. The command returns `{status, body}`
 * for any HTTP answer and rejects with `{code, detail}` only when the request
 * could not be made at all.
 *
 * Browser preview: `scripts/dev-preview.mjs` serves the built files and stands
 * in for the shell at `/bridge`, reading the same token file. This exists so the
 * UI can be iterated on and screenshotted without rebuilding the native shell;
 * it is a development tool, never a distribution path.
 *
 * Both also answer the four questions about the process the shell hosts —
 * `coreStatus`, `coreRestart`, `shellSettings`, `saveShellSettings` — with the
 * same shape. The wire form is snake_case on both sides (the Rust command and
 * the preview route), so the conversion lives here and nowhere else: a panel
 * only ever sees camelCase and never has to know which transport is in use.
 */

import { ApiFailure, ErrorCode, asApiFailure } from "./errors.js";

/**
 * The shell's process status, in the names the panels use.
 *
 * `pid` and `startedAtUnixMs` are null when no child exists. They are never
 * guessed: "the core answers on this address" and "the shell has a child" are
 * different facts, and this object only carries the second one.
 *
 * @param {any} raw
 * @returns {any}
 */
export function coreStatusFromWire(raw) {
  if (!raw || typeof raw !== "object") return null;
  return {
    state: String(raw.state ?? ""),
    pid: typeof raw.pid === "number" ? raw.pid : null,
    startedAtUnixMs: typeof raw.started_at_unix_ms === "number" ? raw.started_at_unix_ms : null,
    restarts: Number(raw.restarts) || 0,
    detail: String(raw.detail ?? ""),
  };
}

/**
 * @param {any} raw
 * @returns {any}
 */
export function shellSettingsFromWire(raw) {
  if (!raw || typeof raw !== "object") return null;
  return {
    settingsPath: String(raw.settings_path ?? ""),
    stored: overrideSetFromWire(raw.stored),
    effective: overrideSetFromWire(raw.effective),
    restartRequired: Boolean(raw.restart_required),
  };
}

/** @param {any} raw */
function overrideSetFromWire(raw) {
  return {
    dataDir: String(raw?.data_dir ?? ""),
    apiAddr: String(raw?.api_addr ?? ""),
    corePath: String(raw?.core_path ?? ""),
    coreConfig: String(raw?.core_config ?? ""),
  };
}

/**
 * @param {any} values
 * @returns {{data_dir: string, api_addr: string, core_path: string, core_config: string}}
 */
export function shellSettingsToWire(values) {
  return {
    data_dir: String(values?.dataDir ?? ""),
    api_addr: String(values?.apiAddr ?? ""),
    core_path: String(values?.corePath ?? ""),
    core_config: String(values?.coreConfig ?? ""),
  };
}

/**
 * @param {(command: string, args: Record<string, unknown>) => Promise<any>} invoke
 */
export function createTauriBridge(invoke) {
  return {
    kind: "tauri",
    async request({ method, path, body }) {
      try {
        const reply = await invoke("api_request", {
          method,
          path,
          body: body ?? null,
        });
        return { status: Number(reply?.status) || 0, body: String(reply?.body ?? "") };
      } catch (error) {
        throw asApiFailure(error);
      }
    },
    /** Where the shell looks for the core. Never includes the token itself. */
    async runtime() {
      try {
        const info = await invoke("runtime_info", {});
        return {
          mode: "tauri",
          apiAddress: String(info?.api_address ?? ""),
          dataDir: String(info?.data_dir ?? ""),
          tokenPath: String(info?.token_path ?? ""),
          settingsPath: String(info?.settings_path ?? ""),
        };
      } catch {
        return null;
      }
    },
    /** What the shell's supervisor says about the process it hosts. */
    async coreStatus() {
      try {
        return coreStatusFromWire(await invoke("core_status", {}));
      } catch {
        return null;
      }
    },
    /** Ask the shell to stop and start its child; returns the new status. */
    async coreRestart() {
      try {
        return coreStatusFromWire(await invoke("core_restart", {}));
      } catch {
        return null;
      }
    },
    /** The shell settings file: what it says, what is in effect, what needs a restart. */
    async shellSettings() {
      try {
        return shellSettingsFromWire(await invoke("get_shell_settings", {}));
      } catch {
        return null;
      }
    },
    /** Write the four overrides. No hot swap: the answer says what a restart needs. */
    async saveShellSettings(values) {
      try {
        return shellSettingsFromWire(
          await invoke("set_shell_settings", { values: shellSettingsToWire(values) }),
        );
      } catch {
        return null;
      }
    },
  };
}

/**
 * @param {{ baseUrl?: string, fetchImpl?: typeof fetch }} [options]
 */
export function createHttpBridge({ baseUrl = "/bridge", fetchImpl = globalThis.fetch } = {}) {
  /**
   * @param {string} path
   * @param {{ method?: string, body?: unknown }} [init]
   */
  async function call(path, { method = "GET", body } = {}) {
    let response;
    try {
      response = await fetchImpl(`${baseUrl}${path}`, {
        method,
        cache: "no-store",
        headers: body ? { "content-type": "application/json" } : undefined,
        body: body ? JSON.stringify(body) : undefined,
      });
    } catch (error) {
      throw new ApiFailure(ErrorCode.CORE_UNREACHABLE, {
        detail: String(error?.message ?? error ?? ""),
      });
    }
    if (!response.ok) return null;
    try {
      return await response.json();
    } catch {
      return null;
    }
  }

  return {
    kind: "http",
    async request({ method, path, body }) {
      let response;
      try {
        response = await fetchImpl(`${baseUrl}${path}`, {
          method,
          cache: "no-store",
          headers: body ? { "content-type": "application/json" } : undefined,
          body: body ?? undefined,
        });
      } catch (error) {
        throw new ApiFailure(ErrorCode.CORE_UNREACHABLE, {
          detail: String(error?.message ?? error ?? ""),
        });
      }
      return { status: response.status, body: await response.text() };
    },
    /** Where the preview proxy looks for the core. Never includes the token. */
    async runtime() {
      try {
        const response = await fetchImpl(`${baseUrl}/runtime`, { cache: "no-store" });
        if (!response.ok) return null;
        const info = await response.json();
        return {
          mode: "preview",
          apiAddress: String(info?.api_address ?? ""),
          dataDir: String(info?.data_dir ?? ""),
          tokenPath: String(info?.token_path ?? ""),
          settingsPath: String(info?.settings_path ?? ""),
        };
      } catch {
        return null;
      }
    },
    async coreStatus() {
      try {
        return coreStatusFromWire(await call("/shell/status"));
      } catch {
        return null;
      }
    },
    async coreRestart() {
      try {
        return coreStatusFromWire(await call("/shell/restart", { method: "POST", body: {} }));
      } catch {
        return null;
      }
    },
    async shellSettings() {
      try {
        return shellSettingsFromWire(await call("/shell/settings"));
      } catch {
        return null;
      }
    },
    async saveShellSettings(values) {
      try {
        return shellSettingsFromWire(
          await call("/shell/settings", { method: "POST", body: shellSettingsToWire(values) }),
        );
      } catch {
        return null;
      }
    },
  };
}

/** A bridge that always fails: used when the page was opened without a shell. */
export function createNullBridge() {
  return {
    kind: "none",
    async request() {
      throw new ApiFailure(ErrorCode.NO_BRIDGE);
    },
    async runtime() {
      return null;
    },
    /** No shell, so no process to report: the panel hides the whole section. */
    async coreStatus() {
      return null;
    },
    async coreRestart() {
      return null;
    },
    async shellSettings() {
      return null;
    },
    async saveShellSettings() {
      return null;
    },
  };
}

/**
 * Pick a transport.
 *
 * Order matters: a native shell wins, because in that case the token is only
 * reachable from Rust. The HTTP bridge is tried only when the page is served
 * over http(s), which is exactly the preview case — a `file://` page must not
 * pretend it can talk to the core.
 *
 * @param {{
 *   invoke?: ((command: string, args: Record<string, unknown>) => Promise<any>) | null,
 *   probe?: (() => Promise<boolean>) | null,
 * }} options
 * @returns {Promise<ReturnType<typeof createTauriBridge> | ReturnType<typeof createHttpBridge> | ReturnType<typeof createNullBridge>>}
 */
export async function chooseBridge({ invoke = null, probe = null } = {}) {
  if (typeof invoke === "function") return createTauriBridge(invoke);
  if (typeof probe === "function") {
    try {
      if (await probe()) return createHttpBridge();
    } catch {
      // A preview server that cannot be reached is the same as no preview.
    }
  }
  return createNullBridge();
}

/**
 * Probe the preview proxy without caring about the answer: any HTTP response
 * means the proxy is there (a 401 or a 502 both mean "the bridge exists").
 *
 * @param {{ fetchImpl?: typeof fetch, baseUrl?: string }} [options]
 * @returns {Promise<boolean>}
 */
export async function probePreview({ fetchImpl = globalThis.fetch, baseUrl = "/bridge" } = {}) {
  if (typeof fetchImpl !== "function") return false;
  try {
    await fetchImpl(`${baseUrl}/v1/status`, { method: "GET", cache: "no-store" });
    return true;
  } catch {
    return false;
  }
}
