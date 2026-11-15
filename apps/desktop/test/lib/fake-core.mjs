/**
 * A stand-in for `melonarc-core`, used by the bridge contract test.
 *
 * It does the four things the supervisor actually depends on: accept
 * `-config` and `-api-listen`, write a fresh `<data-dir>/api-token` (a new one
 * on every start, like the real core), answer `/v1/status` with the bearer
 * token, and die on `SIGTERM`.
 *
 * Two environment variables make it useful for timing: `FAKE_CORE_DATA_DIR`
 * says where the token goes, `FAKE_CORE_DELAY_MS` delays the listener so the
 * `starting` state is observable instead of instantaneous. `FAKE_CORE_RECORD`
 * is written on every start with the arguments it was given, so a test can
 * assert what the supervisor actually passed.
 *
 * This file is never executed by the test runner: the test writes a two-line
 * shell wrapper that runs it with a known node binary, because the supervisor
 * spawns a path and cannot pass interpreter arguments.
 */

import { mkdirSync, writeFileSync } from "node:fs";
import http from "node:http";
import path from "node:path";

const args = process.argv.slice(2);

/** @param {string} flag */
function valueOf(flag) {
  const index = args.indexOf(flag);
  return index >= 0 ? String(args[index + 1] ?? "") : "";
}

const config = valueOf("-config");
const listen = valueOf("-api-listen");
const dataDir = process.env.FAKE_CORE_DATA_DIR ?? "";
const delay = Number(process.env.FAKE_CORE_DELAY_MS ?? "0");

if (dataDir === "") {
  console.error("fake core: FAKE_CORE_DATA_DIR is not set");
  process.exit(2);
}
if (listen === "") {
  console.error("fake core: -api-listen was not passed");
  process.exit(2);
}

const token = `fake-${process.pid}-${Date.now()}`;
mkdirSync(dataDir, { recursive: true });
writeFileSync(path.join(dataDir, "api-token"), `${token}\n`, { mode: 0o600 });
if (process.env.FAKE_CORE_RECORD) {
  writeFileSync(process.env.FAKE_CORE_RECORD, `${process.pid}\n${config}\n${listen}\n`);
}

const current = listen.startsWith("[")
  ? { host: listen.slice(1, listen.indexOf("]")), port: Number(listen.slice(listen.indexOf("]") + 2)) }
  : { host: listen.slice(0, listen.lastIndexOf(":")), port: Number(listen.slice(listen.lastIndexOf(":") + 1)) };

const server = http.createServer((request, response) => {
  if (request.headers.authorization !== `Bearer ${token}`) {
    response.writeHead(401, { "content-type": "application/json" });
    response.end('{"error":{"code":"unauthorized"}}');
    return;
  }
  if (request.url === "/v1/status") {
    response.writeHead(200, { "content-type": "application/json" });
    response.end(
      JSON.stringify({ version: "fake-core", uptime_seconds: 3, rule_count: 1, policy_count: 1 }),
    );
    return;
  }
  response.writeHead(404, { "content-type": "application/json" });
  response.end('{"error":{"code":"not_found"}}');
});

setTimeout(() => {
  server.listen(current.port, current.host, () => {
    console.log(`fake core listening on ${current.host}:${current.port}`);
  });
}, Number.isFinite(delay) ? delay : 0);
