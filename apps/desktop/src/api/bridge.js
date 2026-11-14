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
 */

import { ApiFailure, ErrorCode, asApiFailure } from "./errors.js";

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
        };
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
        };
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
