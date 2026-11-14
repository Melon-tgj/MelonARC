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

/** Paths of this step's read-only surface. */
export const Paths = Object.freeze({
  status: "/v1/status",
  config: "/v1/config",
  policies: "/v1/policies",
  inbound: "/v1/inbound",
  failures: "/v1/failures",
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
  };
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
