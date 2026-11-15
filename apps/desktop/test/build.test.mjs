/**
 * The build can stamp a release number into the tree it emits.
 *
 * `MELONARC_VERSION` must change the copy in `dist/` and nothing else: the
 * source module is what the manifests are checked against, so a release build
 * that edited it would make the next `npm test` fail on a clean checkout.
 *
 * The build is run against a throwaway root rather than the real app directory:
 * these cases must not leave a `dist/` behind, and two of them run in parallel
 * with the rest of the suite.
 */

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { APP_VERSION } from "../src/version.js";

const run = promisify(execFile);
const here = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(here, "..");
const buildScript = path.join(appRoot, "scripts", "build.mjs");
const versionModule = path.join(appRoot, "src", "version.js");

/**
 * Copy the files a build reads into a scratch root.
 *
 * Implemented with readdir/readFile/writeFile rather than `fs.cp`: the build
 * script avoids the kernel copy path on purpose, and a test that depended on it
 * would be the one place that still fails in a restricted sandbox.
 *
 * @param {string} dir
 */
async function scratchRoot(dir) {
  await mkdir(dir, { recursive: true });
  for (const entry of ["index.html", "package.json"]) {
    await writeFile(path.join(dir, entry), await readFile(path.join(appRoot, entry)));
  }
  for (const entry of ["src", "locales"]) await copyTree(path.join(appRoot, entry), path.join(dir, entry));
  return dir;
}

/**
 * @param {string} from
 * @param {string} to
 */
async function copyTree(from, to) {
  await mkdir(to, { recursive: true });
  for (const entry of await readdir(from, { withFileTypes: true })) {
    const source = path.join(from, entry.name);
    const target = path.join(to, entry.name);
    if (entry.isDirectory()) await copyTree(source, target);
    else if (entry.isFile()) await writeFile(target, await readFile(source));
  }
}

/**
 * Build a scratch root and return what the build wrote.
 *
 * @param {Record<string, string>} env
 */
async function build(env) {
  const root = await scratchRoot(await mkdtemp(path.join(tmpdir(), "melonarc-build-")));
  const childEnv = { ...process.env, ...env };
  if (!("MELONARC_VERSION" in env)) delete childEnv.MELONARC_VERSION;

  const { stdout } = await run(process.execPath, [buildScript, "--root", root], { env: childEnv });
  const distVersion = await readFile(path.join(root, "dist", "src", "version.js"), "utf8");
  return { stdout, distVersion, root };
}

/**
 * The APP_VERSION a version module declares.
 *
 * @param {string} source
 */
function declaredVersion(source) {
  const match = source.match(/export const APP_VERSION = "([^"]*)";/);
  assert.ok(match, "the version module has no APP_VERSION declaration");
  return match[1];
}

test("a build without MELONARC_VERSION reports the source version", async () => {
  const built = await build({});

  assert.equal(declaredVersion(built.distVersion), APP_VERSION);
  assert.match(built.stdout, new RegExp(`^melonarc-desktop ${APP_VERSION.replace(/\./g, "\\.")}$`, "m"));
  assert.doesNotMatch(built.stdout, /MELONARC_VERSION/);
});

test("a build with MELONARC_VERSION reports it in dist and leaves src alone", async () => {
  const built = await build({ MELONARC_VERSION: "0.1.0-preview.1-test" });

  assert.equal(declaredVersion(built.distVersion), "0.1.0-preview.1-test");
  assert.match(built.distVersion, /export const APP_LICENSE = "GPL-3\.0-only";/);
  assert.equal(declaredVersion(await readFile(versionModule, "utf8")), APP_VERSION);
  assert.match(built.stdout, /^melonarc-desktop 0\.1\.0-preview\.1-test$/m);
  assert.match(built.stdout, /MELONARC_VERSION/);
});
