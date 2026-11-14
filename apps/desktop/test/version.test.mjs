/**
 * The version string appears in three manifests and in the about block. Four
 * copies of one number is three too many, so they are compared here.
 */

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { APP_LICENSE, APP_VERSION } from "../src/version.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(here, "..");

test("package.json, tauri.conf.json and Cargo.toml agree with src/version.js", async () => {
  const pkg = JSON.parse(await readFile(path.join(appRoot, "package.json"), "utf8"));
  const tauri = JSON.parse(await readFile(path.join(appRoot, "src-tauri", "tauri.conf.json"), "utf8"));
  const cargo = await readFile(path.join(appRoot, "src-tauri", "Cargo.toml"), "utf8");

  assert.equal(pkg.version, APP_VERSION);
  assert.equal(tauri.version, APP_VERSION);
  assert.match(cargo, new RegExp(`^version = "${APP_VERSION.replace(/\./g, "\\.")}"`, "m"));
  assert.equal(pkg.license, APP_LICENSE);
  assert.equal(tauri.bundle.license, APP_LICENSE);
});
