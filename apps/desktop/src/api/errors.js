/**
 * Failure taxonomy of the API layer.
 *
 * The codes are the contract between three places: the Rust shell (which reports
 * `token_missing` / `core_unreachable`), the browser preview proxy (which reports
 * the same two), and the UI (which turns them into one sentence in the user's
 * language). Nothing else is allowed to invent a code: an unexpected shape is
 * always `bad_response`, and an answer the core refused is always `api_error`.
 */

export const ErrorCode = Object.freeze({
  /** No bridge at all: the page was opened as a plain file, or the preview is off. */
  NO_BRIDGE: "no_bridge",
  /** The shell could not read <data-dir>/api-token: the core has not started yet. */
  TOKEN_MISSING: "token_missing",
  /** Nothing is listening on the API address, or the connection was cut. */
  CORE_UNREACHABLE: "core_unreachable",
  /** The token file exists but the core rejected it: stale file or another build. */
  UNAUTHORIZED: "unauthorized",
  /** The reply could not be understood as the API contract. */
  BAD_RESPONSE: "bad_response",
  /** The core answered with an error document. */
  API_ERROR: "api_error",
});

const CONNECTIVITY = new Set([
  ErrorCode.NO_BRIDGE,
  ErrorCode.TOKEN_MISSING,
  ErrorCode.CORE_UNREACHABLE,
]);

const KNOWN = new Set(Object.values(ErrorCode));

/** A failure that the UI can explain without parsing a message. */
export class ApiFailure extends Error {
  /**
   * @param {string} code one of {@link ErrorCode}
   * @param {{ detail?: string, status?: number, apiCode?: string }} [info]
   */
  constructor(code, info = {}) {
    const normalized = KNOWN.has(code) ? code : ErrorCode.BAD_RESPONSE;
    super(normalized);
    this.name = "ApiFailure";
    this.code = normalized;
    /** Technical detail for the diagnostic line, never shown as the headline. */
    this.detail = typeof info.detail === "string" ? info.detail : "";
    /** HTTP status when there was one. */
    this.status = Number(info.status) || 0;
    /** The core's own error code, when it sent one. */
    this.apiCode = typeof info.apiCode === "string" ? info.apiCode : "";
  }
}

/**
 * True when the failure means "the core is not answering", as opposed to "the
 * core answered and refused". Only the first kind turns the whole window into an
 * offline notice.
 *
 * @param {unknown} error
 * @returns {boolean}
 */
export function isConnectivityFailure(error) {
  return error instanceof ApiFailure && CONNECTIVITY.has(error.code);
}

/**
 * True when the failure means "the token is missing or not accepted".
 *
 * @param {unknown} error
 * @returns {boolean}
 */
export function isAuthFailure(error) {
  return error instanceof ApiFailure && error.code === ErrorCode.UNAUTHORIZED;
}

/**
 * Normalize anything thrown by a bridge into an ApiFailure.
 *
 * @param {unknown} error
 * @returns {ApiFailure}
 */
export function asApiFailure(error) {
  if (error instanceof ApiFailure) return error;
  if (error && typeof error === "object" && typeof error.code === "string") {
    return new ApiFailure(error.code, {
      detail: typeof error.detail === "string" ? error.detail : "",
      status: error.status,
    });
  }
  return new ApiFailure(ErrorCode.BAD_RESPONSE, {
    detail: typeof error === "string" ? error : String(error?.message ?? error ?? ""),
  });
}
