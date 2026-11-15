/**
 * Headless mount of the real shell, run as a child process by
 * `app-smoke.test.mjs`.
 *
 * The page is fed canned API answers through the same `fetch` path it uses in a
 * browser, so this exercises the shell, the registry, the panels, the i18n
 * packs and the error banner together — the one thing a unit test cannot do.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { installFakeDom } from "./fake-dom.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(here, "../..");
const localeDir = path.join(appRoot, "locales");

const catalogs = {
  "zh-CN": JSON.parse(readFileSync(path.join(localeDir, "zh-CN.json"), "utf8")),
  en: JSON.parse(readFileSync(path.join(localeDir, "en.json"), "utf8")),
};

const answers = {
  "/bridge/runtime": {
    mode: "preview",
    api_address: "127.0.0.1:7946",
    data_dir: "/tmp/arc/data",
    token_path: "/tmp/arc/data/api-token",
    settings_path: "/tmp/arc/melonarc/shell.json",
  },
  "/bridge/shell/status": {
    state: "running",
    pid: 5150,
    started_at_unix_ms: 1_760_000_000_000,
    restarts: 1,
    detail: "",
  },
  "/bridge/shell/settings": {
    settings_path: "/tmp/arc/melonarc/shell.json",
    stored: { data_dir: "/tmp/arc/data", api_addr: "", core_path: "", core_config: "" },
    effective: {
      data_dir: "/tmp/arc/data",
      api_addr: "127.0.0.1:7946",
      core_path: "/opt/melonarc-core",
      core_config: "/tmp/arc/data/melonarc.conf",
    },
    restart_required: false,
  },
  "/bridge/v1/status": {
    version: "0.1.0-dev",
    started_at: "2026-11-14T11:00:00Z",
    uptime_seconds: 3725,
    rule_count: 7,
    policy_count: 3,
  },
  "/bridge/v1/config": {
    path: "/tmp/arc/demo.conf",
    log_level: "info",
    api_listen: "127.0.0.1:7946",
    http_listen: "127.0.0.1:7890",
    socks5_listen: "127.0.0.1:7891",
    proxies: [{ name: "office-a", type: "socks5", server: "127.0.0.1", port: 1080 }],
    groups: [{ name: "manual", type: "select", members: ["office-a", "office-b", "DIRECT"] }],
    rule_sets: [{ name: "ads", path: "./rulesets/ads.txt" }],
  },
  "/bridge/v1/policies": {
    policies: [
      {
        name: "manual",
        type: "select",
        active: "office-a",
        healthy_members: 3,
        all_unhealthy: false,
        members: [
          { name: "office-a", healthy: true, checked: true, latency_ms: 46, failures: 0 },
          { name: "office-b", healthy: false, checked: true, latency_ms: 0, failures: 2 },
          { name: "DIRECT", healthy: true, checked: false, latency_ms: 0, failures: 0 },
        ],
      },
    ],
  },
  "/bridge/v1/inbound": {
    inbounds: [{ protocol: "http", open: 2, accepted: 12, datagram_associations: 0 }],
    open: 2,
    accepted: 12,
    failures: 2,
    rejected: 1,
    failure_log_capacity: 64,
    failure_log_count: 2,
  },
  "/bridge/v1/failures?limit=20": {
    capacity: 64,
    count: 1,
    failures: [
      {
        time: "2026-11-14T11:05:00Z",
        target: "example.invalid:80",
        network: "tcp",
        stage: "dial",
        category: "refused",
        policy: "manual",
      },
    ],
  },
  "/bridge/v1/rules?limit=500": {
    total: 2,
    limit: 2,
    rules: [
      { index: 0, type: "DOMAIN", payload: "api.example.com", target: "manual", source: "config", line: 31, no_resolve: false },
      { index: 1, type: "DOMAIN-SUFFIX", payload: "example.com", target: "manual", source: "ads", line: 32, no_resolve: true },
    ],
  },
  "/bridge/v1/audit?limit=64": {
    capacity: 64,
    count: 2,
    entries: [
      { time: "2026-11-14T11:06:00Z", action: "policy.select", result: "ok", detail: "manual -> office-b", remote: "127.0.0.1" },
      { time: "2026-11-14T11:07:00Z", action: "config.reload", result: "failed", detail: "rule set missing", remote: "127.0.0.1" },
    ],
  },
  "/bridge/v1/failures?limit=64": {
    capacity: 64,
    count: 2,
    failures: [
      { time: "2026-11-14T11:05:00Z", target: "example.invalid:80", network: "tcp", stage: "dial", category: "refused", policy: "manual" },
      { time: "2026-11-14T11:08:00Z", target: "blocked.test:80", network: "tcp", stage: "route", category: "rejected", policy: "" },
    ],
  },
};

const explainAnswer = {
  query: { name: "example.com" },
  matched: true,
  rule: { index: 1, type: "DOMAIN-SUFFIX", payload: "example.com", target: "manual", source: "config", line: 32, no_resolve: false },
  target: "manual",
  resolution: { source: "hosts", addrs: ["203.0.113.5"], note: "static mapping" },
  steps: [
    { type: "DOMAIN", index: 0, rule: "DOMAIN,api.example.com,manual", match: false, detail: "exact entry not found" },
    { type: "DOMAIN-SUFFIX", index: 1, rule: "DOMAIN-SUFFIX,example.com,manual", match: true, detail: "suffix matched" },
  ],
  report: "DOMAIN-SUFFIX,example.com -> manual",
};

const seen = [];
const posted = [];
const restartCalls = [];
let offline = false;

/** @type {(input: any, init?: any) => Promise<any>} */
async function fakeFetch(input, init = {}) {
  const url = typeof input === "string" ? input : String(input?.href ?? input);
  const method = String(init.method ?? "GET").toUpperCase();
  seen.push(url);

  for (const [id, catalog] of Object.entries(catalogs)) {
    if (url.endsWith(`/locales/${id}.json`)) return reply(200, catalog);
  }

  // Runtime metadata is served by the shell (or the preview proxy), not by the
  // core, so it is still available while the core is down.
  if (url.endsWith("/bridge/runtime")) return reply(200, answers["/bridge/runtime"]);

  if (offline && url.includes("/bridge/")) {
    return reply(502, { proxied: false, error: { code: "core_unreachable", message: "connect ECONNREFUSED" } });
  }

  if (url.endsWith("/bridge/shell/settings") && method === "POST") {
    const written = JSON.parse(init.body ?? "{}");
    posted.push(written);
    const next = {
      ...answers["/bridge/shell/settings"],
      stored: written,
      restart_required: written.data_dir !== "" && written.data_dir !== "/tmp/arc/data",
    };
    return reply(200, next);
  }

  if (url.endsWith("/bridge/shell/restart")) {
    restartCalls.push(method);
    return reply(200, {
      state: "starting",
      pid: null,
      started_at_unix_ms: null,
      restarts: 1,
      detail: "",
    });
  }

  if (url.includes("/bridge/v1/rules/explain?")) return reply(200, explainAnswer);

  const key = Object.keys(answers).find((candidate) => url.endsWith(candidate));
  if (key) return reply(200, answers[key]);
  return reply(404, { error: { code: "not_found", message: url } });
}

/** @param {number} status @param {any} value */
function reply(status, value) {
  const body = JSON.stringify(value);
  return {
    ok: status >= 200 && status < 300,
    status,
    text: async () => body,
    json: async () => value,
  };
}

/** Let every pending promise from the panels settle. */
async function tick() {
  for (let index = 0; index < 12; index += 1) {
    await new Promise((resolve) => setImmediate(resolve));
  }
}

/** @param {any} node @param {(node: any) => boolean} predicate */
function find(node, predicate) {
  if (!node) return null;
  if (predicate(node)) return node;
  for (const child of node.children ?? []) {
    const found = find(child, predicate);
    if (found) return found;
  }
  return null;
}

async function main() {
  const { startApp } = await import("../../src/app.js");

  // ------------------------------------------------------------- online pass
  const dom = installFakeDom();
  globalThis.fetch = fakeFetch;
  await startApp(dom.root);
  await tick();

  const shell = dom.root.replacedWith;
  assert.ok(shell, "the shell replaced the mount point");
  assert.equal(shell.className, "app-shell");

  const nav = shell.querySelectorAll("[data-panel]");
  assert.equal(nav.length, 6, "the navigation is generated from the registry");

  let text = shell.textContent;
  assert.match(text, /概览/, "the default language is Chinese");
  assert.match(text, /0\.1\.0-dev/, "the overview shows the core version");
  assert.match(text, /127\.0\.0\.1:7946/, "the overview shows the API address");
  assert.match(text, /1h 02m/, "the formatted uptime is rendered");

  const select = find(shell, (node) => node.tagName === "select");
  assert.ok(select, "the language switcher exists");
  select.value = "en";
  select.dispatch("change", { target: { value: "en" } });
  await tick();
  text = shell.textContent;
  assert.match(text, /Overview/, "switching the language relabels the navigation immediately");
  assert.match(text, /Core is running/, "the panel copy is translated too");
  assert.match(text, /Core process/, "the shell's view of the process is its own card");
  assert.match(text, /5150/, "the shell-reported process id is shown");
  assert.match(text, /Automatic restarts/, "the automatic restart count is labelled");
  assert.match(text, /Reported by the shell/, "the card says where the fact comes from");
  assert.doesNotMatch(text, /概览/, "no Chinese navigation label remains");

  const clickPanel = async (id) => {
    const button = shell.querySelectorAll("[data-panel]").find((node) => node.dataset.panel === id);
    assert.ok(button, `nav button for ${id}`);
    button.dispatch("click");
    await tick();
  };

  await clickPanel("policies");
  assert.match(shell.textContent, /manual/, "the policies panel lists the group");
  assert.match(shell.textContent, /office-b/, "the policies panel lists its members");

  await clickPanel("connections");
  assert.match(shell.textContent, /example\.invalid:80/, "the connections panel lists real failure rows");
  assert.match(shell.textContent, /Recent failures/, "the failure card is translated");

  // ------------------------------------------------------------------ rules
  await clickPanel("rules");
  assert.match(shell.textContent, /DOMAIN-SUFFIX/, "the rules panel lists compiled rules");
  assert.match(shell.textContent, /rulesets\/ads\.txt/, "the declared rule set is listed");

  const hitInput = find(shell, (node) => node.tagName === "input");
  assert.ok(hitInput, "the hit test has an input");
  hitInput.dispatch("input", { target: { value: "example.com" } });
  const hitButton = find(shell, (node) => node.tagName === "button" && node.textContent === "Test");
  assert.ok(hitButton, "the hit test has a run button");
  hitButton.dispatch("click");
  await tick();
  assert.ok(
    seen.some((url) => url.includes("/bridge/v1/rules/explain?name=example.com")),
    "a name is sent as the name parameter",
  );
  assert.match(shell.textContent, /Rule matched/, "the explanation reports a match");
  assert.match(shell.textContent, /Decision path/, "the decision path is rendered");
  assert.match(shell.textContent, /203\.0\.113\.5/, "the resolution addresses are rendered");
  assert.match(shell.textContent, /Full report/, "the core report is rendered");

  hitInput.dispatch("input", { target: { value: "203.0.113.9" } });
  hitButton.dispatch("click");
  await tick();
  assert.ok(
    seen.some((url) => url.includes("/bridge/v1/rules/explain?addr=203.0.113.9")),
    "an IP address is sent as the addr parameter",
  );

  // ------------------------------------------------------------------- logs
  await clickPanel("logs");
  assert.match(shell.textContent, /Policy selection/, "audit actions are translated");
  assert.match(shell.textContent, /example\.invalid:80/, "failure records are listed");
  assert.match(shell.textContent, /blocked\.test:80/, "the second failure record is listed");

  const levelSelect = find(
    shell,
    (node) => node.tagName === "select" && node.attributes?.get?.("aria-label") === "Level",
  );
  assert.ok(levelSelect, "the level filter exists");
  levelSelect.dispatch("change", { target: { value: "ok" } });
  await tick();
  assert.doesNotMatch(shell.textContent, /example\.invalid:80/, "a success level hides the failures");
  levelSelect.dispatch("change", { target: { value: "" } });
  await tick();

  const sourceSelect = find(
    shell,
    (node) => node.tagName === "select" && node.attributes?.get?.("aria-label") === "Source",
  );
  assert.ok(sourceSelect, "the source filter exists");
  sourceSelect.dispatch("change", { target: { value: "route" } });
  await tick();
  assert.match(shell.textContent, /blocked\.test:80/, "the routing failure survives the source filter");
  assert.doesNotMatch(shell.textContent, /example\.invalid:80/, "the dialing failure is filtered out");
  sourceSelect.dispatch("change", { target: { value: "" } });
  await tick();

  const pauseButton = find(shell, (node) => node.tagName === "button" && node.textContent === "Pause scrolling");
  assert.ok(pauseButton, "the pause button exists");
  pauseButton.dispatch("click");
  await tick();
  assert.match(shell.textContent, /Paused/, "pausing is shown");
  assert.match(shell.textContent, /Resume scrolling/, "the button offers to resume");

  // --------------------------------------------------------------- settings
  await clickPanel("settings");
  assert.match(shell.textContent, /Shell settings/, "the overrides card is titled from the locale pack");
  assert.match(
    shell.textContent,
    /\/tmp\/arc\/melonarc\/shell\.json/,
    "the settings file path replaces the old environment lines",
  );
  assert.match(
    shell.textContent,
    /MELONARC_DATA_DIR and MELONARC_API_ADDR win over this file/,
    "the precedence between environment, file and defaults is stated",
  );
  assert.match(shell.textContent, /\/tmp\/arc\/data/, "the effective data directory is shown");
  assert.match(shell.textContent, /GPLv3/, "the about block names the licence");
  assert.match(shell.textContent, /0\.1\.0/, "the about block shows the version");

  const dataInput = find(shell, (node) => node.attributes?.get?.("id") === "settings-data-dir");
  const apiInput = find(shell, (node) => node.attributes?.get?.("id") === "settings-api-addr");
  const corePathInput = find(shell, (node) => node.attributes?.get?.("id") === "settings-core-path");
  const coreConfigInput = find(shell, (node) => node.attributes?.get?.("id") === "settings-core-config");
  assert.ok(dataInput && apiInput && corePathInput && coreConfigInput, "all four overrides are editable");
  assert.equal(dataInput.value, "/tmp/arc/data", "the stored value is filled in from the shell");
  assert.equal(corePathInput.value, "", "an unset override is an empty field");

  dataInput.dispatch("input", { target: { value: "/tmp/arc/other" } });
  apiInput.dispatch("input", { target: { value: "127.0.0.1:7947" } });
  const saveButton = find(shell, (node) => node.tagName === "button" && node.textContent === "Save");
  assert.ok(saveButton, "the save button exists");
  saveButton.dispatch("click");
  await tick();

  assert.equal(posted.length, 1, "saving goes through the shell contract, not a local store");
  assert.deepEqual(
    posted[0],
    {
      data_dir: "/tmp/arc/other",
      api_addr: "127.0.0.1:7947",
      core_path: "",
      core_config: "",
    },
    "the wire form is snake_case and an empty override stays empty",
  );
  assert.match(shell.textContent, /Saved to the settings file/, "the save is confirmed by the shell's answer");
  assert.match(
    shell.textContent,
    /Restart the application to apply this/,
    "a new data directory is flagged as needing a shell restart",
  );

  const restartCoreButton = find(shell, (node) => node.tagName === "button" && node.textContent === "Restart core");
  assert.ok(restartCoreButton, "the core can be restarted without restarting the window");
  restartCoreButton.dispatch("click");
  await tick();
  assert.deepEqual(restartCalls, ["POST"], "the restart goes to the shell");
  assert.match(shell.textContent, /The core was restarted \(Starting\)/, "the state after a restart is named");

  const settingsLang = find(
    shell,
    (node) => node.tagName === "select" && node.attributes?.get?.("aria-label") === "Interface language",
  );
  assert.ok(settingsLang, "the settings language switch exists");
  settingsLang.dispatch("change", { target: { value: "zh-CN" } });
  await tick();
  assert.match(shell.textContent, /设置/, "the settings switch relabels the window immediately");
  assert.doesNotMatch(shell.textContent, /Shell settings/, "the English panel label is gone");

  // Nothing in the DOM is a credential: the shell only ever shows its path.
  assert.doesNotMatch(shell.textContent, /Bearer /, "no bearer header is rendered");

  dom.restore();

  // ------------------------------------------------------------ offline pass
  offline = true;
  const down = installFakeDom();
  globalThis.fetch = fakeFetch;
  await startApp(down.root);
  await tick();

  const downShell = down.root.replacedWith;
  const downText = downShell.textContent;
  assert.match(downText, /没有连上核心/, "the offline notice is in Chinese");
  assert.match(downText, /melonarc-core -config/, "the notice tells the user how to start the core");
  assert.match(downText, /\/tmp\/arc\/data\/api-token/, "the notice shows where the token should be");
  assert.match(downText, /核心未运行/, "the header pill shows the core is off");
  down.restore();

  console.log("app-smoke-ok: 6 panels, zh-CN + en, six data panels and the offline notice");
  // The polling loops were deliberately left without timers; exit explicitly.
  process.exit(0);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
