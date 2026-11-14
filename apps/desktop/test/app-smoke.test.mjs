/**
 * The browser-less shell test.
 *
 * It runs in a child process because the fake DOM replaces a few globals; that
 * keeps the test runner's own timers untouched. Any failure in the real mount
 * path — a missing module, a broken panel, a language pack that cannot be read —
 * makes this test fail with the child's stack trace.
 */

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const runner = path.join(here, "lib", "app-smoke-run.mjs");

test("the shell mounts, navigates, switches language and explains an absent core", () => {
  const result = spawnSync(process.execPath, [runner], {
    encoding: "utf8",
    env: {
      ...process.env,
      NODE_USE_ENV_PROXY: "",
      HTTP_PROXY: "",
      HTTPS_PROXY: "",
      http_proxy: "",
      https_proxy: "",
    },
  });

  assert.equal(result.status, 0, `child failed:\n${result.stdout}\n${result.stderr}`);
  assert.match(result.stdout, /app-smoke-ok/);
});
