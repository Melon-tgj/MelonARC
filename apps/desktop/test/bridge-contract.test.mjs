/**
 * The preview bridge's shell contract, exercised over real HTTP.
 *
 * The unit tests prove the pieces; this proves the wiring: a real
 * `dev-preview.mjs` process, a real child process, real sockets. It is the only
 * way to check the things that only exist at runtime — that a spawn actually
 * passes `-api-listen`, that a killed child comes back on its own, that a
 * refused value never reaches the file.
 *
 * The core is `test/lib/fake-core.mjs`, started through a two-line wrapper
 * because the supervisor spawns a path and cannot pass interpreter arguments.
 * Every test gets its own temporary directory and its own ports.
 */

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(here, "..");
const previewScript = path.join(appRoot, "scripts", "dev-preview.mjs");
const fakeCoreScript = path.join(here, "lib", "fake-core.mjs");

/** A scratch area with a data directory, a configuration home and a config file. */
function scratch() {
  const dir = mkdtempSync(path.join(tmpdir(), "melonarc-bridge-"));
  const dataDir = path.join(dir, "data");
  const configHome = path.join(dir, "config");
  const config = path.join(dir, "demo.conf");
  mkdirSync(dataDir, { recursive: true });
  mkdirSync(configHome, { recursive: true });
  writeFileSync(config, "[General]\n");

  const wrapper = path.join(dir, "core-runner.sh");
  writeFileSync(wrapper, `#!/bin/sh\nexec "${process.execPath}" "${fakeCoreScript}" "$@"\n`);
  chmodSync(wrapper, 0o755);

  return { dir, dataDir, configHome, config, wrapper, record: path.join(dir, "record.txt") };
}

/** @returns {Promise<number>} an ephemeral port nothing is listening on */
function freePort() {
  return new Promise((resolve, reject) => {
    const server = http.createServer();
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

/**
 * Start the preview bridge and wait for the line that carries its port.
 *
 * @param {string[]} args
 * @param {Record<string, string>} env
 */
function startBridge(args, env) {
  const child = spawn(process.execPath, [previewScript, ...args], {
    cwd: appRoot,
    env: { ...process.env, ...env },
    stdio: ["ignore", "pipe", "pipe"],
  });

  let output = "";
  const port = new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`the bridge printed no port:\n${output}`)), 10_000);
    const inspect = (chunk) => {
      output += chunk;
      const match = /preview\s+http:\/\/127\.0\.0\.1:(\d+)\//.exec(output);
      if (match) {
        clearTimeout(timer);
        resolve(Number(match[1]));
      }
    };
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", inspect);
    child.stderr.on("data", inspect);
    child.once("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`the bridge exited with ${code}:\n${output}`));
    });
  });

  return { child, port, output: () => output };
}

/** @param {{ child: import("node:child_process").ChildProcess }} bridge */
async function stopBridge(bridge) {
  if (bridge.child.exitCode !== null || bridge.child.signalCode !== null) return;
  const exited = new Promise((resolve) => bridge.child.once("exit", resolve));
  bridge.child.kill("SIGTERM");
  const timer = new Promise((resolve) => {
    const handle = setTimeout(resolve, 6_000);
    if (typeof handle.unref === "function") handle.unref();
  });
  await Promise.race([exited, timer]);
  if (bridge.child.exitCode === null && bridge.child.signalCode === null) bridge.child.kill("SIGKILL");
}

/**
 * @param {number} port
 * @param {string} pathname
 * @param {{ method?: string, body?: unknown, origin?: boolean }} [options]
 * @returns {Promise<{ status: number, body: any }>}
 */
function request(port, pathname, { method = "GET", body, origin = false } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? null : Buffer.from(JSON.stringify(body), "utf8");
    const outgoing = http.request(
      {
        host: "127.0.0.1",
        port,
        path: pathname,
        method,
        timeout: 5_000,
        headers: {
          host: `127.0.0.1:${port}`,
          connection: "close",
          ...(payload ? { "content-type": "application/json", "content-length": payload.length } : {}),
          ...(origin ? { origin: `http://127.0.0.1:${port}` } : {}),
        },
      },
      (response) => {
        const chunks = [];
        response.on("data", (chunk) => chunks.push(chunk));
        response.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          let parsed = null;
          try {
            parsed = text === "" ? null : JSON.parse(text);
          } catch {
            parsed = text;
          }
          resolve({ status: response.statusCode ?? 0, body: parsed });
        });
      },
    );
    outgoing.on("error", reject);
    outgoing.on("timeout", () => outgoing.destroy(new Error("the bridge did not answer in time")));
    if (payload) outgoing.write(payload);
    outgoing.end();
  });
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Poll `/bridge/shell/status` until the predicate holds, keeping every state
 * that was seen on the way.
 *
 * @param {number} port
 * @param {(status: any) => boolean} predicate
 * @param {{ timeout?: number, label?: string }} [options]
 */
async function waitForStatus(port, predicate, { timeout = 15_000, label = "a status" } = {}) {
  const seen = [];
  const deadline = Date.now() + timeout;
  let last = null;
  while (Date.now() < deadline) {
    const answer = await request(port, "/bridge/shell/status");
    last = answer.body;
    if (last && seen.at(-1) !== last.state) seen.push(last.state);
    if (last && predicate(last)) return { status: last, seen };
    await sleep(100);
  }
  throw new Error(`timed out waiting for ${label}; last status ${JSON.stringify(last)}`);
}

test("a supervised core starts, restarts on demand and comes back after a crash", { timeout: 60_000 }, async () => {
  const area = scratch();
  const apiPort = await freePort();
  const bridge = startBridge(
    [
      "--port", "0",
      "--api", `127.0.0.1:${apiPort}`,
      "--data-dir", area.dataDir,
      "--core", area.wrapper,
      "--core-config", area.config,
    ],
    {
      XDG_CONFIG_HOME: area.configHome,
      FAKE_CORE_DATA_DIR: area.dataDir,
      FAKE_CORE_DELAY_MS: "1200",
      FAKE_CORE_RECORD: area.record,
    },
  );

  try {
    const port = await bridge.port;

    const started = await waitForStatus(port, (status) => status.state === "running", {
      label: "the core to become ready",
    });
    assert.ok(
      started.seen.includes("starting"),
      `the start-up state was observable: ${started.seen.join(" -> ")}`,
    );
    const running = started.status;
    assert.equal(typeof running.pid, "number", "the supervisor reports the child it owns");
    assert.ok(running.started_at_unix_ms > 0, "the start time is a real timestamp");
    assert.equal(running.restarts, 0, "nothing has restarted yet");
    assert.equal(running.detail, "");

    // The child was started with exactly the arguments the contract names.
    const recorded = readFileSync(area.record, "utf8").split("\n");
    assert.equal(recorded[1], area.config, "the configuration path is passed through");
    assert.equal(recorded[2], `127.0.0.1:${apiPort}`, "-api-listen is always passed");

    // Restart: a new pid, and the state goes back to running on its own.
    const restarted = await request(port, "/bridge/shell/restart", { method: "POST", body: {}, origin: true });
    assert.equal(restarted.status, 200);
    assert.ok(["starting", "running"].includes(restarted.body.state));

    const afterRestart = await waitForStatus(
      port,
      (status) => status.state === "running" && status.pid !== running.pid,
      { label: "the restarted core" },
    );
    assert.notEqual(afterRestart.status.pid, running.pid, "a restart produces a new process");

    // Crash: the supervisor counts it, waits, and brings the core back.
    process.kill(afterRestart.status.pid, "SIGKILL");
    const failure = await waitForStatus(port, (status) => /SIGKILL|exited|restarting/.test(status.detail), {
      label: "the failure to be reported",
    });
    assert.equal(failure.status.pid, null, "no pid is reported while nothing runs");

    const recovered = await waitForStatus(
      port,
      (status) => status.state === "running" && status.pid !== afterRestart.status.pid,
      { label: "the automatic restart" },
    );
    assert.ok(recovered.status.restarts >= 1, "the automatic restart is counted");
  } finally {
    await stopBridge(bridge);
    rmSync(area.dir, { recursive: true, force: true });
  }
});

test("a core path that does not exist leaves the bridge stopped, with the reason", { timeout: 30_000 }, async () => {
  const area = scratch();
  const apiPort = await freePort();
  const missing = path.join(area.dir, "missing-core");
  const bridge = startBridge(
    [
      "--port", "0",
      "--api", `127.0.0.1:${apiPort}`,
      "--data-dir", area.dataDir,
      "--core", missing,
      "--core-config", area.config,
    ],
    { XDG_CONFIG_HOME: area.configHome },
  );

  try {
    const port = await bridge.port;
    const answer = await request(port, "/bridge/shell/status");
    assert.equal(answer.status, 200);
    assert.equal(answer.body.state, "stopped");
    assert.equal(answer.body.pid, null);
    assert.equal(answer.body.started_at_unix_ms, null, "no invented start time");
    assert.match(answer.body.detail, /no core binary at/);
    assert.ok(answer.body.detail.includes(missing), answer.body.detail);

    // The settings view still resolves the configuration path a restart would use.
    const settings = await request(port, "/bridge/shell/settings");
    assert.equal(settings.status, 200);
    assert.equal(settings.body.effective.core_config, area.config);
  } finally {
    await stopBridge(bridge);
    rmSync(area.dir, { recursive: true, force: true });
  }
});

test("without --core the status is a real probe, and nothing is restarted", { timeout: 30_000 }, async () => {
  const area = scratch();
  const apiPort = await freePort();
  const core = spawn(
    process.execPath,
    [fakeCoreScript, "-config", area.config, "-api-listen", `127.0.0.1:${apiPort}`],
    { env: { ...process.env, FAKE_CORE_DATA_DIR: area.dataDir }, stdio: "ignore" },
  );

  const bridge = startBridge(
    ["--port", "0", "--api", `127.0.0.1:${apiPort}`, "--data-dir", area.dataDir],
    { XDG_CONFIG_HOME: area.configHome },
  );

  try {
    const port = await bridge.port;

    const running = await waitForStatus(port, (status) => status.state === "running", {
      label: "the probe to reach the core",
    });
    assert.equal(running.status.pid, null, "a process this bridge does not host has no pid");
    assert.equal(running.status.started_at_unix_ms, null);
    assert.match(running.status.detail, /was not started by this bridge/);

    const refused = await request(port, "/bridge/shell/restart", { method: "POST", body: {}, origin: true });
    assert.equal(refused.status, 409, "the bridge does not kill a process it does not own");
    assert.equal(refused.body.error.code, "not_managed");

    core.kill("SIGKILL");
    const stopped = await waitForStatus(port, (status) => status.state === "stopped", {
      label: "the probe to notice the core is gone",
    });
    assert.match(stopped.status.detail, /no core answers/);
    assert.equal(stopped.status.pid, null);
  } finally {
    await stopBridge(bridge);
    if (core.exitCode === null && core.signalCode === null) core.kill("SIGKILL");
    rmSync(area.dir, { recursive: true, force: true });
  }
});

test("the settings file round-trips through the bridge, and a bad value is refused", { timeout: 30_000 }, async () => {
  const area = scratch();
  const apiPort = await freePort();
  const bridge = startBridge(
    ["--port", "0", "--api", `127.0.0.1:${apiPort}`, "--data-dir", area.dataDir],
    { XDG_CONFIG_HOME: area.configHome },
  );
  const settingsFile = path.join(area.configHome, "melonarc", "shell.json");

  try {
    const port = await bridge.port;

    const initial = await request(port, "/bridge/shell/settings");
    assert.equal(initial.status, 200);
    assert.equal(initial.body.settings_path, settingsFile);
    assert.deepEqual(initial.body.stored, { data_dir: "", api_addr: "", core_path: "", core_config: "" });
    assert.equal(initial.body.effective.data_dir, area.dataDir);
    assert.equal(initial.body.effective.api_addr, `127.0.0.1:${apiPort}`);
    assert.equal(initial.body.effective.core_config, path.join(area.dataDir, "melonarc.conf"));
    assert.equal(initial.body.restart_required, false);

    const saved = await request(port, "/bridge/shell/settings", {
      method: "POST",
      origin: true,
      body: {
        data_dir: "/tmp/arc/other",
        api_addr: "127.0.0.1:17999",
        core_path: "",
        core_config: "/tmp/arc/demo.conf",
      },
    });
    assert.equal(saved.status, 200);
    assert.equal(saved.body.stored.data_dir, "/tmp/arc/other");
    assert.equal(saved.body.stored.core_path, "");
    assert.equal(saved.body.restart_required, true, "a new data directory needs a restart");
    assert.equal(saved.body.effective.data_dir, area.dataDir, "the running bridge keeps what it started with");

    assert.deepEqual(JSON.parse(readFileSync(settingsFile, "utf8")), {
      data_dir: "/tmp/arc/other",
      api_addr: "127.0.0.1:17999",
      core_config: "/tmp/arc/demo.conf",
    });

    const readBack = await request(port, "/bridge/shell/settings");
    assert.equal(readBack.body.stored.api_addr, "127.0.0.1:17999");
    assert.equal(readBack.body.stored.core_config, "/tmp/arc/demo.conf");

    const bad = await request(port, "/bridge/shell/settings", {
      method: "POST",
      origin: true,
      body: { api_addr: "10.0.0.9:7946" },
    });
    assert.equal(bad.status, 400);
    assert.equal(bad.body.error.code, "bad_settings");
    assert.match(bad.body.error.message, /not a loopback address/);
    assert.equal(
      JSON.parse(readFileSync(settingsFile, "utf8")).api_addr,
      "127.0.0.1:17999",
      "a refused value never reaches the file",
    );

    const noOrigin = await request(port, "/bridge/shell/settings", { method: "POST", body: {} });
    assert.equal(noOrigin.status, 403, "a write without an Origin is refused");

    const cleared = await request(port, "/bridge/shell/settings", { method: "POST", origin: true, body: {} });
    assert.equal(cleared.status, 200);
    assert.deepEqual(cleared.body.stored, { data_dir: "", api_addr: "", core_path: "", core_config: "" });
    assert.deepEqual(JSON.parse(readFileSync(settingsFile, "utf8")), {}, "clearing writes an empty object");
  } finally {
    await stopBridge(bridge);
    rmSync(area.dir, { recursive: true, force: true });
  }
});
