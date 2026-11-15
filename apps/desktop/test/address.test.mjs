/**
 * The preview bridge and the CLI both add a bearer token before connecting.
 * These tests pin the checks that keep that request on this machine: IP-type
 * loopback validation, verified localhost resolution, canonical IPv6, and
 * Host/Origin/write validation on the development-only bridge.
 */

import assert from "node:assert/strict";
import test from "node:test";

import {
  assertDevelopmentOnly,
  isLoopbackIP,
  resolveAddress,
  upstreamRequestOptions,
  validateBridgeRequest,
  validateBridgeTarget,
} from "../scripts/lib/address.mjs";

test("loopback is decided by IP type, not by a string prefix", () => {
  for (const good of ["127.0.0.1", "127.9.8.7", "127.255.255.254", "::1", "0:0:0:0:0:0:0:1", "::ffff:127.0.0.1"]) {
    assert.equal(isLoopbackIP(good), true, `${good} is loopback`);
  }
  for (const bad of ["128.0.0.1", "192.168.1.1", "10.0.0.1", "0.0.0.0", "::2", "2001:db8::1", "127.example.com", "localhost", ""]) {
    assert.equal(isLoopbackIP(bad), false, `${bad} is not loopback`);
  }
});

test("a configured literal must be a loopback IP and keep the canonical form", async () => {
  assert.deepEqual(await resolveAddress("127.0.0.1:7946"), {
    host: "127.0.0.1", port: 7946, label: "127.0.0.1:7946",
  });
  assert.deepEqual(await resolveAddress("[0:0:0:0:0:0:0:1]:7946"), {
    host: "::1", port: 7946, label: "[::1]:7946",
  });
  for (const bad of [
    "192.168.1.10:7946", "10.0.0.1:7946", "[2001:db8::1]:7946",
    "0.0.0.0:7946", "core.example:7946", "127.example.com:7946",
  ]) {
    await assert.rejects(() => resolveAddress(bad), /loopback|neither a loopback IP/, bad);
  }
});

test("localhost is resolved and every answer must be loopback", async () => {
  const lookup = async () => ["::1", "127.0.0.1"];
  assert.deepEqual(await resolveAddress("localhost:7946", { lookup }), {
    host: "127.0.0.1", port: 7946, label: "127.0.0.1:7946",
  });

  const ipv6Only = async () => ["::1"];
  assert.deepEqual(await resolveAddress("LOCALHOST:7946", { lookup: ipv6Only }), {
    host: "::1", port: 7946, label: "[::1]:7946",
  });

  await assert.rejects(
    () => resolveAddress("localhost:7946", { lookup: async () => ["127.0.0.1", "192.0.2.5"] }),
    /not loopback/,
  );
  await assert.rejects(() => resolveAddress("localhost:7946", { lookup: async () => [] }), /no address/);
  await assert.rejects(() => resolveAddress("localhost:7946", { lookup: async () => { throw new Error("dns down"); } }), /dns down/);
});

test("the upstream request dials the verified IP and carries no proxy or token leak", () => {
  const api = { host: "::1", port: 7946, label: "[::1]:7946" };
  const options = upstreamRequestOptions({ api, method: "GET", path: "/v1/status" });
  assert.equal(options.host, "::1");
  assert.equal(options.port, 7946);
  assert.equal(options.path, "/v1/status");
  assert.equal(options.headers.host, "[::1]:7946");
  assert.equal(options.headers.authorization, undefined);
  assert.equal(options.agent, undefined);
  assert.equal(options.proxy, undefined);
});

test("the bridge validates Host and a browser Origin and authorises writes", () => {
  const port = 5173;
  assert.deepEqual(validateBridgeRequest({ hostHeader: `127.0.0.1:${port}`, port }), { ok: true });
  assert.deepEqual(validateBridgeRequest({ hostHeader: `localhost:${port}`, port }), { ok: true });
  assert.deepEqual(
    validateBridgeRequest({ hostHeader: `[::1]:${port}`, originHeader: "http://[::1]:5173", method: "POST", port }),
    { ok: true },
  );
  assert.equal(validateBridgeRequest({ hostHeader: "evil.example:5173", port }).code, "bad_host");
  assert.equal(validateBridgeRequest({ hostHeader: undefined, port }).code, "bad_host");
  assert.equal(validateBridgeRequest({ hostHeader: `127.0.0.1:${port}`, originHeader: "https://evil.example", port }).code, "bad_origin");
  assert.equal(validateBridgeRequest({ hostHeader: `127.0.0.1:${port}`, method: "POST", port }).code, "missing_origin");
});

test("the bridge forwards only known read methods and the two write endpoints", () => {
  assert.deepEqual(validateBridgeTarget({ method: "GET", path: "/v1/status" }), { ok: true });
  assert.deepEqual(validateBridgeTarget({ method: "POST", path: "/v1/policies/select" }), { ok: true });
  assert.deepEqual(validateBridgeTarget({ method: "POST", path: "/v1/config/reload?dry=1" }), { ok: true });
  assert.equal(validateBridgeTarget({ method: "DELETE", path: "/v1/status" }).code, "bad_method");
  assert.equal(validateBridgeTarget({ method: "POST", path: "/v1/history" }).code, "write_not_allowed");
  assert.equal(validateBridgeTarget({ method: "GET", path: "//evil.example" }).code, "bad_path");
  assert.equal(validateBridgeTarget({ method: "GET", path: "/v1/status\r\nX: y" }).code, "bad_path");
});

test("the preview bridge refuses to start in a production build", () => {
  assert.doesNotThrow(() => assertDevelopmentOnly({}));
  assert.doesNotThrow(() => assertDevelopmentOnly({ NODE_ENV: "development" }));
  assert.throws(() => assertDevelopmentOnly({ NODE_ENV: "production" }), /development only/);
});
