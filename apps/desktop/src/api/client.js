/**
 * The API client.
 *
 * It knows the endpoint paths and the shape of the answers; it does not know how
 * the request travels. A bridge does that, and there are exactly two: the Tauri
 * shell (which holds the token) and the browser preview proxy (which holds the
 * token for local development). The frontend never sees the token, so a bridge
 * is also the only place a credential could ever be added.
 */

import { ApiFailure, ErrorCode, asApiFailure } from "./errors.js";

/** Paths of the read-only surface the panels consume. */
export const Paths = Object.freeze({
  status: "/v1/status",
  config: "/v1/config",
  policies: "/v1/policies",
  inbound: "/v1/inbound",
  failures: "/v1/failures",
  rules: "/v1/rules",
  explain: "/v1/rules/explain",
  audit: "/v1/audit",
  select: "/v1/policies/select",
});

/**
 * @param {{ bridge: { kind: string, request: (req: {method: string, path: string, body?: string|null}) => Promise<{status: number, body: string}> } }} options
 */
export function createApiClient({ bridge }) {
  /**
   * @param {string} method
   * @param {string} path
   * @param {string} [body]
   * @returns {Promise<unknown>}
   */
  async function request(method, path, body) {
    if (!bridge || bridge.kind === "none") {
      throw new ApiFailure(ErrorCode.NO_BRIDGE);
    }

    let reply;
    try {
      reply = await bridge.request({ method, path, body: body ?? null });
    } catch (error) {
      throw asApiFailure(error);
    }

    const payload = parseJson(reply.body);

    if (reply.status === 401) {
      throw new ApiFailure(ErrorCode.UNAUTHORIZED, {
        status: 401,
        detail: payload?.error?.message ?? "",
      });
    }

    // The preview proxy reports its own failures with the proxy's status, so a
    // core that is down looks the same here as it does through the shell.
    if (reply.status === 502 && payload?.proxied === false) {
      const code = payload?.error?.code === ErrorCode.TOKEN_MISSING
        ? ErrorCode.TOKEN_MISSING
        : ErrorCode.CORE_UNREACHABLE;
      throw new ApiFailure(code, { status: 502, detail: payload?.error?.message ?? "" });
    }

    if (reply.status < 200 || reply.status >= 300) {
      throw new ApiFailure(ErrorCode.API_ERROR, {
        status: reply.status,
        detail: payload?.error?.message ?? "",
        apiCode: payload?.error?.code ?? "",
      });
    }

    if (payload === undefined) {
      throw new ApiFailure(ErrorCode.BAD_RESPONSE, { status: reply.status });
    }
    return payload;
  }

  return {
    kind: bridge?.kind ?? "none",

    /** @returns {Promise<any>} */
    status: () => request("GET", Paths.status),
    /** @returns {Promise<any>} */
    config: () => request("GET", Paths.config),
    /** @returns {Promise<any>} */
    policies: () => request("GET", Paths.policies),
    /** @returns {Promise<any>} */
    inbound: () => request("GET", Paths.inbound),

    /**
     * @param {number} [limit]
     * @returns {Promise<any>}
     */
    failures: (limit = 20) => request("GET", `${Paths.failures}?limit=${encodeURIComponent(limit)}`),

    /**
     * Pin a manual group to a member. The core decides whether the group can be
     * pinned at all; a refusal is an api_error and is shown as one.
     *
     * @param {string} group
     * @param {string} member
     * @returns {Promise<any>}
     */
    selectPolicy: (group, member) =>
      request("POST", Paths.select, JSON.stringify({ group, member })),

    /**
     * One page of compiled rules. The core caps a page at 5000 rules; a panel
     * asks for the size it can render and reports the total separately.
     *
     * @param {number} [limit]
     * @returns {Promise<any>}
     */
    rules: (limit = 500) => request("GET", withQuery(Paths.rules, { limit })),

    /**
     * Explain a classification. Only the four parameters the core accepts are
     * sent; an empty one is left out so the core's own validation stays in charge.
     *
     * @param {{ name?: string, addr?: string, port?: number, network?: string }} [query]
     * @returns {Promise<any>}
     */
    explain: (query = {}) => request("GET", withQuery(Paths.explain, query)),

    /**
     * The write operations the local API carried out.
     *
     * @param {number} [limit]
     * @returns {Promise<any>}
     */
    audit: (limit = 64) => request("GET", withQuery(Paths.audit, { limit })),

    /**
     * Metadata about where the shell looks for the core. This comes from the
     * bridge, not from an HTTP endpoint, and never contains the token itself.
     *
     * @returns {Promise<any>}
     */
    async runtime() {
      if (typeof bridge?.runtime !== "function") return null;
      try {
        return await bridge.runtime();
      } catch {
        return null;
      }
    },
  };
}

/**
 * Build a path with only the query parameters that carry a value.
 *
 * @param {string} path
 * @param {Record<string, unknown>} params
 * @returns {string}
 */
function withQuery(path, params) {
  const pairs = Object.entries(params)
    .filter(([, value]) => value !== undefined && value !== null && value !== "")
    .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(String(value))}`);
  return pairs.length ? `${path}?${pairs.join("&")}` : path;
}

/**
 * @param {string} text
 * @returns {any}
 */
function parseJson(text) {
  if (typeof text !== "string" || text === "") return undefined;
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}
