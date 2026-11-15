/**
 * The core process the preview bridge hosts.
 *
 * This is the Node mirror of `src-tauri/src/core.rs`: one child, a half-second
 * tick, the same four wire states, the same backoff (1s, 2s, then 5s), the same
 * start-up budget, the same five-failure ceiling, and the same output file
 * (`<data-dir>/core.log`). The bridge has to behave like the shell, otherwise a
 * state the browser renders during development would never happen in the real
 * window.
 *
 * The bridge only hosts when it was told to (`--core`). Without it there is no
 * child to report, and `/bridge/shell/status` falls back to probing the core a
 * developer started by hand — see `probeCore` in `dev-preview.mjs`.
 *
 * Development only.
 */

import { closeSync, existsSync, openSync } from "node:fs";
import { spawn as spawnProcess } from "node:child_process";
import http from "node:http";
import { readFile } from "node:fs/promises";

/** How long a spawned core may take to answer before the attempt fails. */
export const STARTUP_BUDGET_MS = 15_000;

/** The supervisor's tick. */
export const TICK_MS = 500;

/** Consecutive failures after which the supervisor gives up. */
export const MAX_FAILURES = 5;

/** How long a child gets after `SIGTERM` before it is killed. */
export const SHUTDOWN_GRACE_MS = 3_000;

/** The backoff sequence: 1s, 2s, then 5s forever. */
export function backoffFor(failures) {
  if (failures <= 1) return 1_000;
  if (failures === 2) return 2_000;
  return 5_000;
}

/** Five consecutive failures is the budget. */
export function givesUp(failures) {
  return failures >= MAX_FAILURES;
}

/**
 * @param {number} failures
 * @returns {{ action: "restart", delayMs: number } | { action: "giveUp" }}
 */
export function afterFailure(failures) {
  return givesUp(failures) ? { action: "giveUp" } : { action: "restart", delayMs: backoffFor(failures) };
}

/**
 * @param {{ alive: boolean, ready: boolean, elapsedMs: number, budgetMs?: number }} input
 * @returns {"running" | "pending" | "failed"}
 */
export function startupVerdict({ alive, ready, elapsedMs, budgetMs = STARTUP_BUDGET_MS }) {
  if (!alive) return "failed";
  if (ready) return "running";
  return elapsedMs >= budgetMs ? "failed" : "pending";
}

/**
 * Start and watch one core process.
 *
 * @param {{
 *   corePath: string,
 *   coreConfig: string,
 *   api: { host: string, port: number, label: string },
 *   tokenPath: string,
 *   logPath: string,
 *   spawnImpl?: typeof spawnProcess,
 *   probe?: () => Promise<boolean>,
 *   now?: () => number,
 *   tickMs?: number,
 *   budgetMs?: number,
 * }} options
 */
export function createSupervisor({
  corePath,
  coreConfig,
  api,
  tokenPath,
  logPath,
  spawnImpl = spawnProcess,
  probe = () => probeCore({ api, tokenPath }),
  now = () => Date.now(),
  tickMs = TICK_MS,
  budgetMs = STARTUP_BUDGET_MS,
}) {
  const state = {
    /** @type {"starting" | "running" | "stopped" | "crashed"} */
    state: "stopped",
    /** @type {number | null} */
    pid: null,
    /** @type {number | null} */
    startedAtUnixMs: null,
    restarts: 0,
    detail: "",
  };

  /** @type {import("node:child_process").ChildProcess | null} */
  let child = null;
  let generation = 0;
  let failures = 0;
  let spawnedAt = 0;
  let stopping = false;
  let ticker = null;
  /** @type {NodeJS.Timeout | null} */
  let restartTimer = null;
  let ticking = false;

  function snapshot() {
    return {
      state: state.state,
      pid: state.pid,
      started_at_unix_ms: state.startedAtUnixMs,
      restarts: state.restarts,
      detail: state.detail,
    };
  }

  function launch() {
    restartTimer = null;
    state.pid = null;
    state.startedAtUnixMs = null;

    if (!existsSync(corePath)) {
      state.state = "stopped";
      state.detail = `no core binary at ${corePath}`;
      return;
    }
    if (!existsSync(coreConfig)) {
      state.state = "stopped";
      state.detail = `the core configuration is missing: ${coreConfig} (set core_config in the settings file)`;
      return;
    }

    let logFd;
    try {
      logFd = openSync(logPath, "a");
    } catch (error) {
      state.state = "stopped";
      state.detail = `cannot open ${logPath}: ${error.message}`;
      return;
    }

    let spawned;
    try {
      // The child gets the same descriptor for stdout and stderr, exactly like
      // the shell: one append-only file, no console.
      spawned = spawnImpl(corePath, ["-config", coreConfig, "-api-listen", api.label], {
        stdio: ["ignore", logFd, logFd],
      });
    } catch (error) {
      closeSync(logFd);
      state.state = "stopped";
      state.detail = `cannot start ${corePath}: ${error.message}`;
      return;
    }
    closeSync(logFd);

    child = spawned;
    generation += 1;
    const mine = generation;
    spawnedAt = now();
    state.state = "starting";
    state.pid = spawned.pid ?? null;
    state.startedAtUnixMs = spawnedAt;
    state.detail = "";

    spawned.once("exit", (code, signal) => {
      if (mine !== generation) return;
      child = null;
      if (stopping) return;
      recordFailure(describeExit(code, signal));
    });

    spawned.once("error", (error) => {
      if (mine !== generation) return;
      child = null;
      if (stopping) return;
      recordFailure(`cannot start ${corePath}: ${error.message}`);
    });
  }

  function recordFailure(detail) {
    failures += 1;
    state.pid = null;
    state.startedAtUnixMs = null;
    state.detail = detail;

    const decision = afterFailure(failures);
    if (decision.action === "giveUp") {
      state.state = "crashed";
      state.detail = `${detail} (${failures} consecutive failures; no further attempt is made until a restart is requested)`;
      return;
    }

    // The next attempt is scheduled, so `starting` is the honest state.
    state.state = "starting";
    state.detail = `${detail}; restarting in ${decision.delayMs / 1000}s`;
    restartTimer = setTimeout(() => {
      restartTimer = null;
      if (stopping) return;
      state.restarts += 1;
      launch();
    }, decision.delayMs);
  }

  async function tick() {
    if (stopping || ticking || !child) return;
    if (state.state === "running") return;
    ticking = true;
    try {
      const ready = await probe();
      const verdict = startupVerdict({
        alive: child !== null,
        ready,
        elapsedMs: now() - spawnedAt,
        budgetMs,
      });
      if (verdict === "running") {
        state.state = "running";
        failures = 0;
        state.detail = "";
        return;
      }
      if (verdict === "failed") {
        const detail = ready
          ? `the core did not answer /v1/status within the ${Math.round(budgetMs / 1000)}s start-up budget`
          : `the core did not become ready within ${Math.round(budgetMs / 1000)}s`;
        await terminateChild();
        recordFailure(detail);
      }
    } finally {
      ticking = false;
    }
  }

  /** Stop the child, politely first, and wait for it. */
  async function terminateChild() {
    const target = child;
    if (!target) {
      state.pid = null;
      state.startedAtUnixMs = null;
      return;
    }
    generation += 1;
    child = null;

    const exited = new Promise((resolve) => target.once("exit", resolve));
    try {
      target.kill("SIGTERM");
    } catch {
      // Already gone.
    }
    const timeout = new Promise((resolve) => {
      // Unreferenced: waiting for a child that exits at once must not keep the
      // bridge alive for the rest of the grace period.
      const timer = setTimeout(resolve, SHUTDOWN_GRACE_MS);
      if (typeof timer.unref === "function") timer.unref();
    });
    await Promise.race([exited, timeout]);
    if (target.exitCode === null && target.signalCode === null) {
      try {
        target.kill("SIGKILL");
      } catch {
        // Already gone.
      }
    }

    state.pid = null;
    state.startedAtUnixMs = null;
  }

  return {
    /** Make the first attempt and start the tick. */
    start() {
      stopping = false;
      launch();
      ticker = setInterval(() => void tick(), tickMs);
      if (typeof ticker.unref === "function") ticker.unref();
      return snapshot();
    },

    status() {
      return snapshot();
    },

    /** Stop the child, clear the failure budget and start again. */
    async restart() {
      if (stopping) return snapshot();
      if (restartTimer) {
        clearTimeout(restartTimer);
        restartTimer = null;
      }
      await terminateChild();
      failures = 0;
      state.state = "stopped";
      state.detail = "";
      launch();
      return snapshot();
    },

    /** Stop for good. The bridge calls this from its signal handler. */
    async shutdown() {
      stopping = true;
      if (ticker) clearInterval(ticker);
      ticker = null;
      if (restartTimer) {
        clearTimeout(restartTimer);
        restartTimer = null;
      }
      await terminateChild();
      state.state = "stopped";
      state.detail = "the preview bridge is exiting";
    },
  };
}

/**
 * Ask the core on `api` whether it answers `/v1/status`.
 *
 * The token is read on every probe: the core rotates it on each start, and a
 * freshly restarted core has just written a new one.
 *
 * @param {{ api: { host: string, port: number }, tokenPath: string }} options
 * @returns {Promise<boolean>}
 */
export function probeCore({ api, tokenPath }) {
  return new Promise((resolve) => {
    readFile(tokenPath, "utf8")
      .then((raw) => {
        const token = raw.trim();
        if (token === "") {
          resolve(false);
          return;
        }
        const request = http.request(
          {
            host: api.host,
            port: api.port,
            path: "/v1/status",
            method: "GET",
            timeout: 2_000,
            headers: {
              authorization: `Bearer ${token}`,
              accept: "application/json",
              connection: "close",
            },
          },
          (response) => {
            response.resume();
            resolve(response.statusCode === 200);
          },
        );
        request.on("error", () => resolve(false));
        request.on("timeout", () => {
          request.destroy();
          resolve(false);
        });
        request.end();
      })
      .catch(() => resolve(false));
  });
}

/** @param {number | null} code @param {string | null} signal */
function describeExit(code, signal) {
  if (signal) return `the core was terminated by signal ${signal}`;
  return `the core exited with status ${code}`;
}
