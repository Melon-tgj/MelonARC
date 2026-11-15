/**
 * Build the desktop frontend.
 *
 * The build is deliberately dependency free: it copies the source tree into
 * `dist/`, checks the things that would otherwise fail only at runtime (a
 * missing locale, a stylesheet the page links but nobody ships, a reference to a
 * remote asset), and prints what it produced. `npm ci` therefore needs no
 * package registry, and `package-lock.json` is the whole dependency graph.
 *
 * The layout is preserved on purpose: `index.html` loads `./src/main.js` and the
 * language packs sit next to it, so relative imports and `new URL(...,
 * import.meta.url)` resolve identically from source and from `dist/`.
 *
 * `MELONARC_VERSION` overrides the version string the built tree reports. It is
 * applied to the copy in `dist/src/version.js` only: `src/version.js` keeps the
 * number the three manifests agree on, so the source tree and the manifests stay
 * in sync and a release build still carries its own number. Without it the build
 * is byte for byte what it was before this option existed.
 */

import { mkdir, readdir, readFile, rmdir, stat, unlink, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const rootFlag = args.indexOf("--root");
const appRoot =
  rootFlag >= 0 && args[rootFlag + 1] ? path.resolve(args[rootFlag + 1]) : path.resolve(here, "..");
const outDir = path.join(appRoot, "dist");

const COPY = ["src", "locales"];

/**
 * The version a release build stamps into the tree, or "" when the build should
 * report the one `src/version.js` declares.
 *
 * Validated rather than trusted: the value ends up inside a JavaScript string
 * literal and, before that, in a shell argument of scripts/build-release.sh.
 */
const versionOverride = (process.env.MELONARC_VERSION ?? "").trim();

async function main() {
  if (versionOverride && !/^[0-9A-Za-z][0-9A-Za-z._+-]*$/.test(versionOverride)) {
    throw new Error(`MELONARC_VERSION is not a version string: ${JSON.stringify(versionOverride)}`);
  }
  if (!outDir.startsWith(appRoot + path.sep)) {
    throw new Error(`refusing to clean ${outDir}: it is outside the app directory`);
  }
  await emptyDirectory(outDir);
  await mkdir(outDir, { recursive: true });

  const pkg = JSON.parse(await readFile(path.join(appRoot, "package.json"), "utf8"));

  await copyFile(path.join(appRoot, "index.html"), path.join(outDir, "index.html"));
  for (const entry of COPY) {
    await copyTree(path.join(appRoot, entry), path.join(outDir, entry));
  }

  await checkLocales(path.join(outDir, "locales"));
  await checkLocalReferences(path.join(outDir, "index.html"));
  if (versionOverride) {
    await stampVersion(path.join(outDir, "src", "version.js"), versionOverride);
  }

  const { files, bytes } = await measure(outDir);
  console.log(`melonarc-desktop ${versionOverride || pkg.version}`);
  if (versionOverride) {
    console.log(`  version: ${versionOverride} (MELONARC_VERSION overrides dist/src/version.js)`);
  }
  console.log(`  output : ${path.relative(appRoot, outDir)}/`);
  console.log(`  files  : ${files}`);
  console.log(`  size   : ${(bytes / 1024).toFixed(1)} KiB`);
}

/**
 * Rewrite the APP_VERSION declaration of a copied version module.
 *
 * Only the copy is touched: `src/version.js` is what the three manifests are
 * checked against, and a release number must not become the number a source
 * checkout claims to be. A missing declaration is an error rather than a silent
 * no-op, because "the build says 0.1.0" is exactly the failure this option is
 * meant to prevent.
 *
 * @param {string} file
 * @param {string} value
 */
async function stampVersion(file, value) {
  const source = await readFile(file, "utf8");
  const pattern = /(export const APP_VERSION = )"[^"]*";/;
  if (!pattern.test(source)) {
    throw new Error(`no APP_VERSION declaration in ${file}`);
  }
  await writeFile(file, source.replace(pattern, `$1${JSON.stringify(value)};`));
}

/**
 * Every language pack must parse and carry exactly the same keys: a key that
 * exists in one language only is a blank line in the other.
 *
 * @param {string} dir
 */
async function checkLocales(dir) {
  const names = (await readdir(dir)).filter((name) => name.endsWith(".json")).sort();
  if (names.length < 2) throw new Error(`expected at least two language packs in ${dir}, found ${names.length}`);

  const catalogs = new Map();
  for (const name of names) {
    const raw = await readFile(path.join(dir, name), "utf8");
    try {
      catalogs.set(name, JSON.parse(raw));
    } catch (error) {
      throw new Error(`locale ${name} is not valid JSON: ${error.message}`);
    }
  }

  const [reference, ...rest] = [...catalogs.keys()];
  const referenceKeys = new Set(Object.keys(catalogs.get(reference)));
  for (const name of rest) {
    const keys = new Set(Object.keys(catalogs.get(name)));
    const missing = [...referenceKeys].filter((key) => !keys.has(key));
    const extra = [...keys].filter((key) => !referenceKeys.has(key));
    if (missing.length || extra.length) {
      throw new Error(
        `locale ${name} does not match ${reference}: missing ${JSON.stringify(missing)}, extra ${JSON.stringify(extra)}`,
      );
    }
  }
}

/**
 * The page may only reference files that ship with it. This catches a renamed
 * stylesheet and, more importantly, an accidental remote font or script.
 *
 * @param {string} indexPath
 */
async function checkLocalReferences(indexPath) {
  const html = await readFile(indexPath, "utf8");
  const refs = [...html.matchAll(/(?:href|src)="([^"]+)"/g)].map((match) => match[1]);

  for (const ref of refs) {
    if (/^(https?:)?\/\//.test(ref) || ref.startsWith("data:")) {
      throw new Error(`index.html references a remote or inline resource: ${ref}`);
    }
    const target = path.join(path.dirname(indexPath), ref);
    if (!existsSync(target)) throw new Error(`index.html references a missing file: ${ref}`);
  }

  for (const name of ["zh-CN.json", "en.json"]) {
    if (!existsSync(path.join(path.dirname(indexPath), "locales", name))) {
      throw new Error(`missing language pack: locales/${name}`);
    }
  }
}

/**
 * Copy a tree file by file.
 *
 * `fs.cp` is avoided on purpose: it delegates to a kernel copy syscall that not
 * every build sandbox allows, and it would happily follow a symlink out of the
 * source tree. Reading and writing each file is slower by microseconds at this
 * size and predictable everywhere.
 *
 * @param {string} source
 * @param {string} target
 */
async function copyTree(source, target) {
  await mkdir(target, { recursive: true });
  for (const entry of await readdir(source, { withFileTypes: true })) {
    const from = path.join(source, entry.name);
    const to = path.join(target, entry.name);
    if (entry.isDirectory()) await copyTree(from, to);
    else if (entry.isFile()) await copyFile(from, to);
    else throw new Error(`unexpected entry in the source tree: ${from}`);
  }
}

/**
 * @param {string} from
 * @param {string} to
 */
async function copyFile(from, to) {
  await writeFile(to, await readFile(from));
}

/**
 * Empty a directory without a recursive delete primitive.
 *
 * Walking and unlinking is not faster, but it never follows a symlink out of the
 * tree and it fails loudly if something is not what this script expects. A stale
 * `dist/` is the one thing that makes a "reproducible" build lie, so it is
 * removed completely.
 *
 * @param {string} dir
 */
async function emptyDirectory(dir) {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch (error) {
    if (error.code === "ENOENT") return;
    throw error;
  }

  for (const entry of entries) {
    const target = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      await emptyDirectory(target);
      await rmdir(target);
    } else {
      await unlink(target);
    }
  }
}

/**
 * @param {string} dir
 */
async function measure(dir) {
  let files = 0;
  let bytes = 0;
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const target = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      const nested = await measure(target);
      files += nested.files;
      bytes += nested.bytes;
      continue;
    }
    files += 1;
    bytes += (await stat(target)).size;
  }
  return { files, bytes };
}

main().catch((error) => {
  console.error(`build failed: ${error.message}`);
  process.exitCode = 1;
});
