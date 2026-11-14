/**
 * Whether the core is answering, shared by the header, the banner and every
 * panel.
 *
 * The rules are narrow on purpose:
 *   - only a connectivity failure changes the global state to offline; a 500 on
 *     one endpoint is a panel's problem, not a reason to cover the window;
 *   - a 401 is a different state from "not running", because the fix is
 *     different (restart the core, which rotates the token);
 *   - any successful call marks the core online again, so the view recovers
 *     without a reload once the core comes back.
 */

import { ApiFailure, ErrorCode, isAuthFailure, isConnectivityFailure } from "../api/errors.js";
import { createPoll } from "./poll.js";

export const CoreStatus = Object.freeze({
  UNKNOWN: "unknown",
  ONLINE: "online",
  OFFLINE: "offline",
  UNAUTHORIZED: "unauthorized",
  NO_BRIDGE: "nobridge",
});

/**
 * @param {{
 *   client: ReturnType<typeof import("../api/client.js").createApiClient>,
 *   initial: { status: string, code?: string, detail?: string },
 *   every?: number,
 *   onChange?: (state: { status: string, code: string, detail: string, payload: any }) => void,
 * }} options
 */
export function createCoreState({ client, initial, every = 5000, onChange = () => {} }) {
  let state = {
    status: initial?.status ?? CoreStatus.UNKNOWN,
    code: initial?.code ?? "",
    detail: initial?.detail ?? "",
    payload: null,
  };

  function set(next) {
    const merged = { ...state, ...next };
    if (
      merged.status === state.status &&
      merged.code === state.code &&
      merged.detail === state.detail &&
      merged.payload === state.payload
    ) {
      return;
    }
    state = merged;
    onChange(state);
  }

  /** Classify a failure into the shared state, ignoring panel-local errors. */
  function report(error, { atStartup = false } = {}) {
    if (error instanceof ApiFailure && error.code === ErrorCode.NO_BRIDGE) {
      set({ status: CoreStatus.NO_BRIDGE, code: error.code, detail: error.detail, payload: null });
      return;
    }
    if (isAuthFailure(error)) {
      set({ status: CoreStatus.UNAUTHORIZED, code: error.code, detail: error.detail, payload: null });
      return;
    }
    if (isConnectivityFailure(error)) {
      set({ status: CoreStatus.OFFLINE, code: error.code, detail: error.detail, payload: null });
      return;
    }
    // The core answered. At start-up a refused status call still means the core
    // is up, so the window should not sit in "connecting" forever.
    if (atStartup) set({ status: CoreStatus.ONLINE, code: "", detail: "", payload: null });
  }

  async function refresh() {
    try {
      const payload = await client.status();
      set({ status: CoreStatus.ONLINE, code: "", detail: "", payload });
    } catch (error) {
      report(error, { atStartup: true });
    }
  }

  const poller = createPoll(refresh, { every });

  return {
    get state() {
      return state;
    },

    /** Mark the core as answering, from a call a panel just made. */
    noteSuccess() {
      if (state.status !== CoreStatus.ONLINE) {
        set({ status: CoreStatus.ONLINE, code: "", detail: "", payload: null });
      }
    },

    /** Feed a panel failure in; only connectivity and auth change the state. */
    noteFailure(error) {
      report(error);
    },

    refresh,
    start: () => poller.start(),
    stop: () => poller.stop(),
  };
}
