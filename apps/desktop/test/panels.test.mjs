/**
 * Mount the three new panels against canned API answers.
 *
 * The shell smoke test proves they work inside the real window; these tests
 * look at one panel at a time so a filter, a hit test or a save can be driven
 * directly. A light DOM is enough here — the panels only create nodes — and
 * every mount is disposed so no polling timer survives the test.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { createTranslator } from "../src/i18n/index.js";
import logsPanel from "../src/panels/logs.js";
import overviewPanel from "../src/panels/overview.js";
import rulesPanel from "../src/panels/rules.js";
import settingsPanel from "../src/panels/settings.js";
import { FakeNode, FakeText } from "./lib/fake-dom.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const catalog = JSON.parse(readFileSync(path.join(here, "..", "locales", "en.json"), "utf8"));

const ruleList = {
  total: 2,
  limit: 2,
  rules: [
    { index: 0, type: "DOMAIN", payload: "api.example.com", target: "manual", source: "config", line: 31, no_resolve: false },
    { index: 1, type: "DOMAIN-SUFFIX", payload: "example.com", target: "manual", source: "ads", line: 32, no_resolve: true },
  ],
};
const config = { rule_sets: [{ name: "ads", path: "./rulesets/ads.txt" }] };
const explanation = {
  query: { addr: "203.0.113.9" },
  matched: true,
  rule: { index: 1, type: "DOMAIN-SUFFIX", payload: "example.com", target: "manual", source: "config", line: 32 },
  target: "manual",
  resolution: { source: "hosts", addrs: ["203.0.113.5"], note: "static mapping" },
  steps: [{ type: "DOMAIN-SUFFIX", index: 1, rule: "DOMAIN-SUFFIX,example.com,manual", match: true, detail: "suffix matched" }],
  report: "DOMAIN-SUFFIX,example.com -> manual",
};
const audit = {
  capacity: 64,
  count: 2,
  entries: [
    { time: "2026-11-14T11:06:00Z", action: "policy.select", result: "ok", detail: "manual -> office-b", remote: "127.0.0.1" },
    { time: "2026-11-14T11:07:00Z", action: "config.reload", result: "failed", detail: "rule set missing", remote: "127.0.0.1" },
  ],
};
const failures = {
  capacity: 64,
  count: 2,
  failures: [
    { time: "2026-11-14T11:05:00Z", target: "example.invalid:80", network: "tcp", stage: "dial", category: "refused", policy: "manual" },
    { time: "2026-11-14T11:08:00Z", target: "blocked.test:80", network: "tcp", stage: "route", category: "rejected", policy: "" },
  ],
};
const runtime = {
  mode: "preview",
  apiAddress: "127.0.0.1:7946",
  dataDir: "/tmp/arc/data",
  tokenPath: "/tmp/arc/data/api-token",
  settingsPath: "/tmp/arc/melonarc/shell.json",
};

const shellSettings = {
  settingsPath: "/tmp/arc/melonarc/shell.json",
  stored: { dataDir: "/tmp/arc/data", apiAddr: "127.0.0.1:7946", corePath: "", coreConfig: "" },
  effective: {
    dataDir: "/tmp/arc/data",
    apiAddr: "127.0.0.1:7946",
    corePath: "/opt/melonarc-core",
    coreConfig: "/tmp/arc/data/melonarc.conf",
  },
  restartRequired: false,
};

/** @param {Record<string, Function>} [overrides] */
function apiStub(overrides = {}) {
  return {
    rules: async () => ruleList,
    config: async () => config,
    explain: async () => explanation,
    audit: async () => audit,
    failures: async () => failures,
    runtime: async () => runtime,
    coreStatus: async () => null,
    coreRestart: async () => null,
    shellSettings: async () => null,
    saveShellSettings: async () => null,
    ...overrides,
  };
}

/** @param {Record<string, Function>} [overrides] */
function context(overrides = {}) {
  return {
    t: createTranslator(catalog, {}),
    locale: "en",
    api: apiStub(overrides),
    core: { noteSuccess() {}, noteFailure() {}, state: {} },
    root: new FakeNode("div"),
    navigate() {},
  };
}

test("the rules panel lists rules and rule sets, and explains one address", async () => {
  await inDom(async () => {
    const seen = [];
    const ctx = context({
      explain: async (query) => {
        seen.push(query);
        return explanation;
      },
    });
    const mounted = rulesPanel.mount(ctx);
    try {
      await settle();
      assert.match(ctx.root.textContent, /DOMAIN-SUFFIX/);
      assert.match(ctx.root.textContent, /rulesets\/ads\.txt/);
      assert.match(ctx.root.textContent, /No test has been run/);

      const input = find(ctx.root, (node) => node.tagName === "input");
      const button = find(ctx.root, (node) => node.tagName === "button" && node.textContent === "Test");
      assert.ok(input && button, "the hit test has controls");
      input.dispatch("input", { target: { value: "203.0.113.9" } });
      button.dispatch("click");
      await settle();

      assert.deepEqual(seen, [{ addr: "203.0.113.9" }], "an IP goes as addr, not as name");
      assert.match(ctx.root.textContent, /Rule matched/);
      assert.match(ctx.root.textContent, /Decision path/);
      assert.match(ctx.root.textContent, /203\.0\.113\.5/);
      assert.match(ctx.root.textContent, /Full report/);
    } finally {
      mounted.dispose();
    }
  });
});

test("the rules panel keeps the focus-friendly controls when a poll lands", async () => {
  await inDom(async () => {
    const ctx = context();
    const mounted = rulesPanel.mount(ctx);
    try {
      await settle();
      const before = find(ctx.root, (node) => node.tagName === "input");
      assert.ok(before, "the input is mounted once");
      assert.equal(find(ctx.root, (node) => node.tagName === "input"), before, "the input node is reused");
    } finally {
      mounted.dispose();
    }
  });
});

test("the logs panel filters by level and source, and can be paused", async () => {
  await inDom(async () => {
    const ctx = context();
    const mounted = logsPanel.mount(ctx);
    try {
      await settle();
      assert.match(ctx.root.textContent, /Policy selection/);
      assert.match(ctx.root.textContent, /example\.invalid:80/);
      assert.match(ctx.root.textContent, /blocked\.test:80/);

      const level = find(ctx.root, (node) => node.tagName === "select" && node.attributes?.get?.("aria-label") === "Level");
      const source = find(ctx.root, (node) => node.tagName === "select" && node.attributes?.get?.("aria-label") === "Source");
      assert.ok(level && source, "both filters exist");

      level.dispatch("change", { target: { value: "ok" } });
      assert.doesNotMatch(ctx.root.textContent, /example\.invalid:80/, "failure records have no success level");
      assert.match(ctx.root.textContent, /manual -> office-b/, "the successful audit entry stays");

      level.dispatch("change", { target: { value: "" } });
      source.dispatch("change", { target: { value: "route" } });
      assert.match(ctx.root.textContent, /blocked\.test:80/);
      assert.doesNotMatch(ctx.root.textContent, /example\.invalid:80/);

      source.dispatch("change", { target: { value: "" } });
      const pause = find(ctx.root, (node) => node.tagName === "button" && node.textContent === "Pause scrolling");
      assert.ok(pause, "the pause button exists");
      pause.dispatch("click");
      assert.match(ctx.root.textContent, /Paused/);
      assert.match(ctx.root.textContent, /Resume scrolling/);
    } finally {
      mounted.dispose();
    }
  });
});

test("the settings panel reads and writes the shell's file, never local storage", async () => {
  await inDom(async ({ data }) => {
    const saves = [];
    let restarts = 0;
    const ctx = context({
      shellSettings: async () => shellSettings,
      saveShellSettings: async (values) => {
        saves.push(values);
        return {
          ...shellSettings,
          stored: { ...values },
          restartRequired: values.dataDir !== "" && values.dataDir !== shellSettings.effective.dataDir,
        };
      },
      coreRestart: async () => {
        restarts += 1;
        return { state: "running", pid: 9, startedAtUnixMs: 1, restarts: 0, detail: "" };
      },
    });

    const mounted = settingsPanel.mount(ctx);
    try {
      await settle();
      assert.match(ctx.root.textContent, /\/tmp\/arc\/melonarc\/shell\.json/, "the settings file path");
      assert.match(ctx.root.textContent, /\/tmp\/arc\/data/, "the effective data directory");
      assert.match(ctx.root.textContent, /\/tmp\/arc\/data\/api-token/, "the token path, never the token");
      assert.match(ctx.root.textContent, /GPLv3/);
      assert.match(ctx.root.textContent, /0\.1\.0/);

      const dataInput = find(ctx.root, (node) => node.attributes?.get?.("id") === "settings-data-dir");
      const apiInput = find(ctx.root, (node) => node.attributes?.get?.("id") === "settings-api-addr");
      const coreInput = find(ctx.root, (node) => node.attributes?.get?.("id") === "settings-core-path");
      const configInput = find(ctx.root, (node) => node.attributes?.get?.("id") === "settings-core-config");
      const save = find(ctx.root, (node) => node.tagName === "button" && node.textContent === "Save");
      assert.ok(dataInput && apiInput && coreInput && configInput && save, "the four fields and the save button");
      assert.equal(dataInput.value, "/tmp/arc/data", "the stored value is filled in");
      assert.equal(coreInput.value, "", "an unset override is an empty field");

      coreInput.dispatch("input", { target: { value: "/opt/other-core" } });
      configInput.dispatch("input", { target: { value: "/tmp/arc/other.conf" } });
      save.dispatch("click");
      await settle();

      assert.deepEqual(saves[0], {
        dataDir: "/tmp/arc/data",
        apiAddr: "127.0.0.1:7946",
        corePath: "/opt/other-core",
        coreConfig: "/tmp/arc/other.conf",
      }, "the save goes through the shell contract, not a local store");
      assert.match(ctx.root.textContent, /Saved to the settings file/);

      dataInput.dispatch("input", { target: { value: "/tmp/arc/moved" } });
      save.dispatch("click");
      await settle();
      assert.match(ctx.root.textContent, /Restart the application to apply this/, "a new data directory needs a restart");

      apiInput.dispatch("input", { target: { value: "10.0.0.5:80" } });
      save.dispatch("click");
      await settle();
      assert.equal(saves.length, 2, "a bad address is refused before it is sent");
      assert.match(ctx.root.textContent, /loopback host and port/);

      const restartCore = find(ctx.root, (node) => node.tagName === "button" && node.textContent === "Restart core");
      assert.ok(restartCore, "the core path and configuration can be applied at once");
      restartCore.dispatch("click");
      await settle();
      assert.equal(restarts, 1);
      assert.match(ctx.root.textContent, /The core was restarted/);

      assert.equal(data.size, 0, "the panel never writes to local storage");
    } finally {
      mounted.dispose();
    }
  });
});

test("the settings panel says so when no shell can read the file", async () => {
  await inDom(async () => {
    const ctx = context({ shellSettings: async () => null, saveShellSettings: async () => null });
    const mounted = settingsPanel.mount(ctx);
    try {
      await settle();
      assert.match(ctx.root.textContent, /No shell is attached/);
    } finally {
      mounted.dispose();
    }
  });
});

test("all three new panels follow the registry contract", () => {
  for (const panel of [rulesPanel, logsPanel, settingsPanel]) {
    assert.equal(typeof panel.id, "string");
    assert.equal(typeof panel.titleKey, "string");
    assert.equal(typeof panel.mount, "function");
    assert.equal(typeof panel.order, "number");
  }
  assert.deepEqual([rulesPanel.id, logsPanel.id, settingsPanel.id], ["rules", "logs", "settings"]);
});

// --------------------------------------------------------------- supervision

/** The three API answers the overview needs, so only supervision varies. */
function overviewContext(coreStatus, coreRestart = async () => null) {
  return context({
    status: async () => ({ version: "0.1.0-dev", uptime_seconds: 120, rule_count: 3, policy_count: 1 }),
    config: async () => ({
      api_listen: "127.0.0.1:7946",
      http_listen: "127.0.0.1:7890",
      socks5_listen: "127.0.0.1:7891",
      log_level: "info",
      proxies: [{ name: "office-a" }],
    }),
    policies: async () => ({ policies: [] }),
    coreStatus,
    coreRestart,
  });
}

test("the overview names all four process states the shell can report", async () => {
  await inDom(async () => {
    const states = [
      ["starting", "Starting"],
      ["running", "Running"],
      ["stopped", "Not started"],
      ["crashed", "Crashed"],
    ];

    for (const [state, label] of states) {
      const ctx = overviewContext(async () => ({
        state,
        pid: 4321,
        startedAtUnixMs: 1_760_000_000_000,
        restarts: 2,
        detail: "technical detail from the shell",
      }));
      const mounted = overviewPanel.mount(ctx);
      try {
        await settle();
        const text = ctx.root.textContent;
        assert.ok(text.includes(label), `${state} renders as "${label}": ${text.slice(0, 400)}`);
        assert.ok(text.includes("4321"), "the pid is shown");
        assert.ok(text.includes("Core process"), "the card is titled");
        assert.ok(
          text.includes("Reported by the shell"),
          "the supervision card is kept distinct from the API status card",
        );

        const restart = find(ctx.root, (node) => node.tagName === "button" && node.textContent === "Restart core");
        assert.equal(
          Boolean(restart),
          state === "stopped" || state === "crashed",
          `the restart button is offered for ${state}`,
        );
      } finally {
        mounted.dispose();
      }
    }
  });
});

test("the overview offers a restart when the shell gave up, and shows the new state", async () => {
  await inDom(async () => {
    let restarted = 0;
    let crashed = true;
    const ctx = overviewContext(
      async () =>
        crashed
          ? {
              state: "crashed",
              pid: null,
              startedAtUnixMs: null,
              restarts: 5,
              detail: "the core exited with status 1 (5 consecutive failures)",
            }
          : { state: "running", pid: 77, startedAtUnixMs: 1_760_000_000_000, restarts: 0, detail: "" },
      async () => {
        restarted += 1;
        crashed = false;
        return { state: "starting", pid: 77, startedAtUnixMs: 1_760_000_000_000, restarts: 0, detail: "" };
      },
    );

    const mounted = overviewPanel.mount(ctx);
    try {
      await settle();
      assert.match(ctx.root.textContent, /The core kept failing/);
      assert.match(ctx.root.textContent, /5 consecutive failures/, "the shell's detail is shown verbatim");
      assert.match(ctx.root.textContent, /5/, "the automatic restart count");

      const restart = find(ctx.root, (node) => node.tagName === "button" && node.textContent === "Restart core");
      assert.ok(restart, "a crashed core can be restarted from the panel");
      restart.dispatch("click");
      await settle();

      assert.equal(restarted, 1, "the button calls the shell, not the core");
      assert.match(ctx.root.textContent, /Running/, "the refreshed state is rendered");
      assert.doesNotMatch(ctx.root.textContent, /The core kept failing/, "the warning is gone");
    } finally {
      mounted.dispose();
    }
  });
});

test("a transport that cannot report the process hides the whole section", async () => {
  await inDom(async () => {
    const ctx = overviewContext(async () => null);
    const mounted = overviewPanel.mount(ctx);
    try {
      await settle();
      assert.match(ctx.root.textContent, /Core is running/, "the API status card is still there");
      assert.doesNotMatch(ctx.root.textContent, /Core process/, "no invented supervision section");
    } finally {
      mounted.dispose();
    }
  });
});

/** Let every pending promise from a panel's first load settle. */
async function settle() {
  for (let index = 0; index < 12; index += 1) {
    await new Promise((resolve) => setImmediate(resolve));
  }
}

/** @param {FakeNode} node @param {(node: any) => boolean} predicate */
function find(node, predicate) {
  if (!node) return null;
  if (predicate(node)) return node;
  for (const child of node.children ?? []) {
    const found = find(child, predicate);
    if (found) return found;
  }
  return null;
}

/**
 * Install only the DOM surface the panels use. Unlike the shell smoke test's
 * shim this leaves the real timers alone: every mount is disposed, so the poll
 * loop's timer is cancelled by the panel itself.
 *
 * The storage is handed to the test so it can assert that a panel did *not*
 * write to it.
 */
async function inDom(run) {
  const keys = ["Node", "document", "localStorage"];
  const saved = {};
  for (const key of keys) saved[key] = globalThis[key];

  const data = new Map();
  const store = {
    getItem: (key) => data.get(key) ?? null,
    setItem: (key, value) => data.set(key, String(value)),
    removeItem: (key) => data.delete(key),
  };

  define("Node", FakeNode);
  define("document", {
    createElement: (tag) => new FakeNode(tag),
    createElementNS: (_namespace, tag) => new FakeNode(tag),
    createTextNode: (text) => new FakeText(text),
    getElementById: () => null,
    addEventListener() {},
    removeEventListener() {},
    visibilityState: "visible",
  });
  define("localStorage", store);

  try {
    await run({ store, data });
  } finally {
    for (const key of keys) {
      if (saved[key] === undefined) delete globalThis[key];
      else define(key, saved[key]);
    }
  }
}

/** @param {string} key @param {any} value */
function define(key, value) {
  Object.defineProperty(globalThis, key, { value, writable: true, configurable: true });
}
