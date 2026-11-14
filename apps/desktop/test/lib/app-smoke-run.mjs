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
};

let offline = false;

/** @type {(input: any, init?: any) => Promise<any>} */
async function fakeFetch(input) {
  const url = typeof input === "string" ? input : String(input?.href ?? input);

  for (const [id, catalog] of Object.entries(catalogs)) {
    if (url.endsWith(`/locales/${id}.json`)) return reply(200, catalog);
  }

  // Runtime metadata is served by the shell (or the preview proxy), not by the
  // core, so it is still available while the core is down.
  if (url.endsWith("/bridge/runtime")) return reply(200, answers["/bridge/runtime"]);

  if (offline && url.includes("/bridge/")) {
    return reply(502, { proxied: false, error: { code: "core_unreachable", message: "connect ECONNREFUSED" } });
  }

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

  await clickPanel("rules");
  assert.match(shell.textContent, /Comes in a later step/, "placeholder panels state what is missing");

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

  console.log("app-smoke-ok: 6 panels, zh-CN + en, three data panels and the offline notice");
  // The polling loops were deliberately left without timers; exit explicitly.
  process.exit(0);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
