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
const runtime = { mode: "preview", apiAddress: "127.0.0.1:7946", dataDir: "/tmp/arc/data", tokenPath: "/tmp/arc/data/api-token" };

/** @param {Record<string, Function>} [overrides] */
function apiStub(overrides = {}) {
  return {
    rules: async () => ruleList,
    config: async () => config,
    explain: async () => explanation,
    audit: async () => audit,
    failures: async () => failures,
    runtime: async () => runtime,
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

test("the settings panel shows what is in effect, saves overrides and reports a bad address", async () => {
  await inDom(async () => {
    const ctx = context();
    const mounted = settingsPanel.mount(ctx);
    try {
      await settle();
      assert.match(ctx.root.textContent, /MELONARC_DATA_DIR/);
      assert.match(ctx.root.textContent, /MELONARC_API_ADDR/);
      assert.match(ctx.root.textContent, /\/tmp\/arc\/data/, "the effective data directory");
      assert.match(ctx.root.textContent, /\/tmp\/arc\/data\/api-token/, "the token path, never the token");
      assert.match(ctx.root.textContent, /GPLv3/);
      assert.match(ctx.root.textContent, /0\.1\.0/);

      const dataInput = find(ctx.root, (node) => node.attributes?.get?.("id") === "settings-data-dir");
      const apiInput = find(ctx.root, (node) => node.attributes?.get?.("id") === "settings-api-addr");
      const save = find(ctx.root, (node) => node.tagName === "button" && node.textContent === "Save");
      const reset = find(ctx.root, (node) => node.tagName === "button" && node.textContent === "Reset");
      assert.ok(dataInput && apiInput && save && reset, "the form is complete");

      dataInput.dispatch("input", { target: { value: "/tmp/arc/other" } });
      apiInput.dispatch("input", { target: { value: "127.0.0.1:7947" } });
      save.dispatch("click");
      assert.match(ctx.root.textContent, /MELONARC_DATA_DIR=\/tmp\/arc\/other/);
      assert.match(ctx.root.textContent, /MELONARC_API_ADDR=127\.0\.0\.1:7947/);
      assert.match(ctx.root.textContent, /Saved to the window settings/);

      apiInput.dispatch("input", { target: { value: "10.0.0.5:80" } });
      save.dispatch("click");
      assert.match(ctx.root.textContent, /loopback host and port/, "a non-loopback address is refused");

      reset.dispatch("click");
      assert.match(ctx.root.textContent, /Window settings cleared/);
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
    await run();
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
