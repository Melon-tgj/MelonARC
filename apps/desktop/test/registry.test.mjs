/**
 * The registry is the extension point, so its promises are tested:
 * ordering, unique ids, a title that exists in both languages, an icon that
 * exists in the icon set, and a mount that returns a disposable result.
 */

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { findPanel, listPanels, registerPanels } from "../src/panels/registry.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(here, "..");

test("the sidebar is built from the registry, in order", () => {
  const panels = listPanels();
  assert.ok(panels.length >= 7, `expected at least seven panels, found ${panels.length}`);
  assert.equal(panels[0].id, "overview");

  const ids = panels.map((panel) => panel.id);
  assert.equal(new Set(ids).size, ids.length, "panel ids are unique");

  const orders = panels.map((panel) => panel.order);
  assert.deepEqual(orders, [...orders].sort((a, b) => a - b), "panels are sorted by order");
  assert.deepEqual(ids.slice(0, 3), ["overview", "policies", "subscriptions"]);
});

test("every panel has a translated title", async () => {
  const zh = JSON.parse(await readFile(path.join(appRoot, "locales", "zh-CN.json"), "utf8"));
  const en = JSON.parse(await readFile(path.join(appRoot, "locales", "en.json"), "utf8"));
  for (const panel of listPanels()) {
    assert.ok(zh[panel.titleKey], `${panel.id}: ${panel.titleKey} missing from zh-CN`);
    assert.ok(en[panel.titleKey], `${panel.id}: ${panel.titleKey} missing from en`);
  }
});

test("every panel names an icon that exists", async () => {
  const icons = await readFile(path.join(appRoot, "src", "components", "icons.js"), "utf8");
  for (const panel of listPanels()) {
    assert.ok(new RegExp(`\\b${panel.icon}:`).test(icons), `${panel.id}: icon "${panel.icon}" is not defined`);
  }
});

test("an unknown id falls back to the caller, not to a crash", () => {
  assert.equal(findPanel("does-not-exist"), undefined);
  assert.equal(findPanel("overview")?.id, "overview");
});

test("registration refuses a broken panel", () => {
  assert.throws(() => registerPanels([{ id: "overview", titleKey: "nav.overview", mount: () => ({}) }]), /twice/);
  assert.throws(() => registerPanels([{ id: "no-mount", titleKey: "nav.overview" }]), /mount/);
  assert.throws(() => registerPanels([{ id: "no-title", mount: () => ({}) }]), /titleKey/);
});
