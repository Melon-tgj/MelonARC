/**
 * The preview bridge's two pure pieces: the retry policy and the settings file.
 *
 * The state machine itself is exercised end to end in `bridge-contract.test.mjs`
 * against a real child process. What is pinned here is the arithmetic that is
 * easy to get subtly wrong — the backoff sequence, the failure budget, the
 * start-up verdict — and the file format, which has to match the Rust shell's
 * so a value saved in one place is the value the other reads.
 */

import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import {
  MAX_FAILURES,
  STARTUP_BUDGET_MS,
  afterFailure,
  backoffFor,
  givesUp,
  startupVerdict,
} from "../scripts/lib/supervisor.mjs";
import {
  CORE_CONFIG_FILE,
  cleanOverrides,
  coreConfigFor,
  isLoopbackText,
  readShellSettings,
  resolveShell,
  settingsPath,
  writeShellSettings,
} from "../scripts/lib/shell-settings.mjs";

/** @returns {string} */
function scratch() {
  return mkdtempSync(path.join(tmpdir(), "melonarc-shell-settings-"));
}

test("the backoff is one, two, then five seconds, and five failures end the retries", () => {
  assert.equal(backoffFor(1), 1_000);
  assert.equal(backoffFor(2), 2_000);
  assert.equal(backoffFor(3), 5_000);
  assert.equal(backoffFor(4), 5_000);
  assert.equal(backoffFor(9), 5_000, "the delay is capped");

  assert.deepEqual(afterFailure(1), { action: "restart", delayMs: 1_000 });
  assert.deepEqual(afterFailure(2), { action: "restart", delayMs: 2_000 });
  assert.deepEqual(afterFailure(3), { action: "restart", delayMs: 5_000 });
  assert.deepEqual(afterFailure(4), { action: "restart", delayMs: 5_000 });
  assert.deepEqual(afterFailure(5), { action: "giveUp" });
  assert.equal(MAX_FAILURES, 5);
  assert.equal(givesUp(4), false);
  assert.equal(givesUp(5), true);
});

test("a child is promoted only when it answers inside its budget", () => {
  assert.equal(startupVerdict({ alive: true, ready: true, elapsedMs: 600 }), "running");
  assert.equal(startupVerdict({ alive: true, ready: false, elapsedMs: 600 }), "pending");
  assert.equal(startupVerdict({ alive: true, ready: false, elapsedMs: STARTUP_BUDGET_MS }), "failed");
  assert.equal(startupVerdict({ alive: false, ready: true, elapsedMs: 10 }), "failed");
  assert.equal(
    startupVerdict({ alive: true, ready: false, elapsedMs: 1_500, budgetMs: 1_000 }),
    "failed",
    "an injected budget is respected",
  );
});

test("the settings file round-trips and omits what was cleared", () => {
  const dir = scratch();
  try {
    const file = path.join(dir, "melonarc", "shell.json");
    const written = writeShellSettings(file, {
      dataDir: "/tmp/arc/data",
      apiAddr: "127.0.0.1:7947",
      corePath: "",
      coreConfig: "/tmp/arc/demo.conf",
    });

    assert.deepEqual(written, {
      dataDir: "/tmp/arc/data",
      apiAddr: "127.0.0.1:7947",
      corePath: "",
      coreConfig: "/tmp/arc/demo.conf",
    });

    const raw = readFileSync(file, "utf8");
    assert.ok(!raw.includes("core_path"), `an empty value is omitted: ${raw}`);
    assert.ok(!raw.includes("api-token"), "the settings file never carries a token");

    assert.deepEqual(readShellSettings(file), written);
    assert.equal(existsSync(`${file}.tmp`), false, "the temporary file is gone");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a missing file reads as nothing set, and a damaged one is reported", () => {
  const dir = scratch();
  try {
    const file = path.join(dir, "shell.json");
    assert.deepEqual(readShellSettings(file), { dataDir: "", apiAddr: "", corePath: "", coreConfig: "" });

    writeFileSync(file, "not json");
    assert.throws(() => readShellSettings(file), /not valid JSON/);

    writeFileSync(file, JSON.stringify({ data_dir: 7 }));
    assert.throws(() => readShellSettings(file), /not a string/);

    writeFileSync(file, JSON.stringify(["/tmp/x"]));
    assert.throws(() => readShellSettings(file), /not a JSON object/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("an override is checked before it is written", () => {
  assert.equal(isLoopbackText("127.0.0.1:7946"), true);
  assert.equal(isLoopbackText("[::1]:7946"), true);
  assert.equal(isLoopbackText("localhost:7946"), true);
  assert.equal(isLoopbackText("10.0.0.9:7946"), false);
  assert.equal(isLoopbackText("127.0.0.1"), false);
  assert.equal(isLoopbackText("127.0.0.1:0"), false);

  assert.throws(() => cleanOverrides({ apiAddr: "10.0.0.9:7946" }), /not a loopback address/);
  assert.throws(() => cleanOverrides({ corePath: "/opt/bad\ncore" }), /control character/);
  assert.throws(() => cleanOverrides({ dataDir: "/tmp/\u0000" }), /control character/);

  assert.deepEqual(cleanOverrides({ dataDir: "  /tmp/arc  ", apiAddr: " 127.0.0.1:7946 " }), {
    dataDir: "/tmp/arc",
    apiAddr: "127.0.0.1:7946",
    corePath: "",
    coreConfig: "",
  });
});

test("an explicit start-up value wins over the file, and the file over the default", () => {
  const stored = { dataDir: "/srv/from-file", apiAddr: "127.0.0.1:7950", corePath: "", coreConfig: "" };
  const defaults = { dataDir: "/home/melon/.config/melonarc", apiAddr: "127.0.0.1:7946" };

  assert.deepEqual(resolveShell({ stored, defaults }), {
    dataDir: "/srv/from-file",
    apiAddr: "127.0.0.1:7950",
  });

  assert.deepEqual(resolveShell({ stored, explicit: { dataDir: "/srv/from-flag", apiAddr: "127.0.0.1:7951" }, defaults }), {
    dataDir: "/srv/from-flag",
    apiAddr: "127.0.0.1:7951",
  });

  assert.deepEqual(
    resolveShell({ stored: { dataDir: "", apiAddr: "", corePath: "", coreConfig: "" }, explicit: { dataDir: "", apiAddr: "" }, defaults }),
    defaults,
    "an empty string is 'not given', not an override",
  );
});

test("the core configuration defaults next to the effective data directory", () => {
  assert.equal(coreConfigFor({ coreConfig: "" }, "/srv/data"), path.join("/srv/data", CORE_CONFIG_FILE));
  assert.equal(coreConfigFor({ coreConfig: "/tmp/demo.conf" }, "/srv/data"), "/tmp/demo.conf");
});

test("the settings path follows the platform configuration directory", () => {
  assert.equal(
    settingsPath({ env: { XDG_CONFIG_HOME: "/tmp/cfg" }, platform: "linux", home: "/home/melon" }),
    path.join("/tmp/cfg", "melonarc", "shell.json"),
  );
  assert.equal(
    settingsPath({ env: {}, platform: "linux", home: "/home/melon" }),
    path.join("/home/melon", ".config", "melonarc", "shell.json"),
  );
});
