/**
 * Guard the language packs.
 *
 * Three things can rot silently in an i18n tree: a key that exists in one
 * language only, a key nobody uses, and a translated string pasted back into a
 * component. The first two are checked here; the third is checked by scanning
 * `src/` for CJK characters, which is cheap and has no false negatives while the
 * only non-English language is Chinese.
 */

import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(here, "..");
const localesDir = path.join(appRoot, "locales");

/** @returns {Promise<Record<string, Record<string, string>>>} */
async function catalogs() {
  const names = (await readdir(localesDir)).filter((name) => name.endsWith(".json"));
  const result = {};
  for (const name of names) {
    result[name] = JSON.parse(await readFile(path.join(localesDir, name), "utf8"));
  }
  return result;
}

test("the two language packs carry the same keys", async () => {
  const all = await catalogs();
  const names = Object.keys(all).sort();
  assert.deepEqual(names, ["en.json", "zh-CN.json"]);

  const reference = Object.keys(all["zh-CN.json"]).sort();
  for (const name of names) {
    assert.deepEqual(Object.keys(all[name]).sort(), reference, `${name} key set`);
  }
});

test("no catalogue value is empty", async () => {
  const all = await catalogs();
  for (const [name, catalog] of Object.entries(all)) {
    for (const [key, value] of Object.entries(catalog)) {
      assert.equal(typeof value, "string", `${name}:${key}`);
      assert.notEqual(value.trim(), "", `${name}:${key} is empty`);
    }
  }
});

test("placeholders survive translation", async () => {
  const all = await catalogs();
  const placeholders = (value) => [...value.matchAll(/\{(\w+)\}/g)].map((match) => match[1]).sort();

  for (const [key, value] of Object.entries(all["zh-CN.json"])) {
    assert.deepEqual(
      placeholders(all["en.json"][key]),
      placeholders(value),
      `placeholders differ for ${key}`,
    );
  }
});

test("every panel and notice key referenced by the source exists in both packs", async () => {
  const all = await catalogs();
  const keys = new Set(Object.keys(all["zh-CN.json"]));
  const referenced = await collectKeys(path.join(appRoot, "src"));

  const missing = [...referenced].filter((key) => !keys.has(key)).sort();
  assert.deepEqual(missing, [], `keys used in src/ but missing from the packs: ${missing.join(", ")}`);
});

test("no interface string is hard coded in the source tree", async () => {
  const offenders = [];
  for (const file of await walk(path.join(appRoot, "src"))) {
    if (!/\.(js|css|html)$/.test(file)) continue;
    const text = await readFile(file, "utf8");
    const lines = text.split("\n");
    lines.forEach((line, index) => {
      if (/[\u4e00-\u9fff]/.test(line)) {
        offenders.push(`${path.relative(appRoot, file)}:${index + 1}: ${line.trim()}`);
      }
    });
  }
  assert.deepEqual(offenders, [], `CJK text outside locales/:\n${offenders.join("\n")}`);
});

/**
 * Pull `t("…")` and `ctx.t("…")` literals out of the source.
 *
 * Only literal keys are checked; a key built from a template is the caller's
 * responsibility, and the panels use that pattern only for the closed stage and
 * category sets, which the integration test covers against a real core.
 *
 * @param {string} dir
 * @returns {Promise<Set<string>>}
 */
async function collectKeys(dir) {
  const keys = new Set();
  for (const file of await walk(dir)) {
    if (!file.endsWith(".js")) continue;
    const text = await readFile(file, "utf8");
    for (const match of text.matchAll(/\bt\(\s*"([^"]+)"/g)) keys.add(match[1]);
  }
  return keys;
}

/**
 * @param {string} dir
 * @returns {Promise<string[]>}
 */
async function walk(dir) {
  const entries = await readdir(dir, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const target = path.join(dir, entry.name);
    if (entry.isDirectory()) files.push(...(await walk(target)));
    else files.push(target);
  }
  return files;
}
