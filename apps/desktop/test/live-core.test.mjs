/**
 * Integration test against a really running core.
 *
 * The other tests prove the client maps answers correctly; this one proves the
 * answers exist. It is skipped unless a core is running, which keeps `npm test`
 * usable without one, and it says why it skipped instead of passing silently.
 *
 *   MELONARC_TEST_API=127.0.0.1:7946 MELONARC_TEST_DATA_DIR=/tmp/arc/data npm test
 *
 * The bridge here is a plain `node:http` client that reads the token file — the
 * same job the Rust shell and the preview proxy do. `fetch` is avoided on
 * purpose: it is not available in every runtime this test may run under.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";

import { createApiClient } from "../src/api/client.js";

const address = process.env.MELONARC_TEST_API ?? "";
const dataDir = process.env.MELONARC_TEST_DATA_DIR ?? "";
const skip =
  address === "" || dataDir === ""
    ? "set MELONARC_TEST_API and MELONARC_TEST_DATA_DIR to run against a live core"
    : false;

test("every panel's endpoints answer a real core", { skip }, async () => {
  const { client, token } = await liveClient();

  const status = await client.status();
  assert.equal(typeof status.version, "string");
  assert.ok(status.version.length > 0, "the core reports a version");
  assert.ok(typeof status.uptime_seconds === "number");
  assert.ok(status.rule_count > 0, "the test configuration has rules");
  assert.ok(status.policy_count > 0, "the test configuration has groups");

  const config = await client.config();
  assert.equal(config.api_listen, address);
  assert.ok(config.http_listen.length > 0);
  assert.ok(Array.isArray(config.proxies) && config.proxies.length > 0);
  assert.ok(Array.isArray(config.groups) && config.groups.length > 0);

  const policies = await client.policies();
  assert.ok(Array.isArray(policies.policies) && policies.policies.length > 0);
  for (const group of policies.policies) {
    assert.ok(typeof group.name === "string" && group.name !== "");
    assert.ok(typeof group.type === "string");
    assert.ok(Array.isArray(group.members) && group.members.length > 0);
    for (const member of group.members) {
      assert.ok(typeof member.name === "string");
      assert.equal(typeof member.healthy, "boolean");
    }
  }

  const inbound = await client.inbound();
  assert.ok(Array.isArray(inbound.inbounds) && inbound.inbounds.length > 0);
  for (const listener of inbound.inbounds) {
    assert.ok(["http", "socks5", "tun"].includes(listener.protocol));
    assert.equal(typeof listener.accepted, "number");
  }
  assert.equal(typeof inbound.failure_log_capacity, "number");
  // The core always sends the pool counter, even when no TUN device exists: a
  // missing key would make the panel's zero default indistinguishable from a
  // core that cannot count the answers at all.
  assert.equal(typeof inbound.fake_ip_pool_exhausted_queries_total, "number");

  const failures = await client.failures(5);
  assert.ok(Array.isArray(failures.failures));
  assert.ok(failures.failures.length <= 5);
  for (const record of failures.failures) {
    assert.ok(typeof record.target === "string");
    assert.ok(["route", "dial"].includes(record.stage), `unexpected stage ${record.stage}`);
    assert.ok(typeof record.category === "string" && record.category !== "");
  }

  // The rules panel reads the compiled list and the declared external sets.
  const rules = await client.rules(500);
  assert.ok(typeof rules.total === "number");
  assert.ok(Array.isArray(rules.rules) && rules.rules.length > 0);
  for (const rule of rules.rules) {
    assert.equal(typeof rule.index, "number");
    assert.equal(typeof rule.type, "string");
    assert.equal(typeof rule.target, "string");
  }
  assert.ok(Array.isArray(config.rule_sets), "the config reports its rule sets");

  // The hit test uses the core's own explanation endpoint, for a name and an IP.
  const byName = await client.explain({ name: "example.com", network: "tcp" });
  assert.equal(byName.query.name, "example.com");
  assert.equal(typeof byName.matched, "boolean");
  assert.ok(Array.isArray(byName.steps));
  for (const step of byName.steps) {
    assert.equal(typeof step.type, "string");
    assert.equal(typeof step.match, "boolean");
    assert.equal(typeof step.detail, "string");
  }
  const byAddr = await client.explain({ addr: "203.0.113.9" });
  assert.equal(byAddr.query.addr, "203.0.113.9");
  assert.equal(typeof byAddr.report, "string");

  const audit = await client.audit(64);
  assert.ok(typeof audit.capacity === "number");
  assert.ok(Array.isArray(audit.entries));
  for (const entry of audit.entries) {
    assert.equal(typeof entry.time, "string");
    assert.ok(["policy.select", "config.reload"].includes(entry.action), `unexpected action ${entry.action}`);
    assert.ok(["ok", "failed"].includes(entry.result), `unexpected result ${entry.result}`);
  }

  // The token is a credential: nothing the API returns may contain it.
  for (const payload of [status, config, policies, inbound, failures, rules, byName, byAddr, audit]) {
    assert.ok(!JSON.stringify(payload).includes(token), "a payload leaked the token");
  }
});

test("a manual group can be pinned and pinned back", { skip }, async () => {
  const { client } = await liveClient();
  const before = await client.policies();
  const group = before.policies.find((item) => item.type === "select");
  assert.ok(group, "the test configuration has a manual group");
  assert.ok(group.members.length >= 2, "the manual group has at least two members");

  const other = group.members.find((member) => member.name !== group.active);
  assert.ok(other, "the manual group has another member");

  const switched = await client.selectPolicy(group.name, other.name);
  assert.equal(switched.group, group.name);
  assert.equal(switched.active, other.name);

  const after = await client.policies();
  const updated = after.policies.find((item) => item.name === group.name);
  assert.equal(updated.active, other.name, "the core kept the pin");

  await client.selectPolicy(group.name, group.active);
  const restored = await client.policies();
  assert.equal(
    restored.policies.find((item) => item.name === group.name).active,
    group.active,
    "the pin was put back",
  );
});

/** @returns {Promise<{ client: ReturnType<typeof createApiClient>, token: string }>} */
async function liveClient() {
  // Imported only when a core is actually being tested: a static import would
  // load the HTTP stack in every `npm test` run, including the skipped one.
  const http = await import("node:http");
  const tokenFile = path.join(dataDir, "api-token");
  const token = readFileSync(tokenFile, "utf8").trim();
  const [host, portText] = splitAddress(address);

  const bridge = {
    kind: "node",
    request: ({ method, path: requestPath, body }) =>
      new Promise((resolve, reject) => {
        const request = http.request(
          {
            host,
            port: Number(portText),
            method,
            path: requestPath,
            headers: {
              authorization: `Bearer ${token}`,
              accept: "application/json",
              connection: "close",
              ...(body ? { "content-type": "application/json", "content-length": Buffer.byteLength(body) } : {}),
            },
          },
          (response) => {
            const chunks = [];
            response.on("data", (chunk) => chunks.push(chunk));
            response.on("end", () =>
              resolve({ status: response.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }),
            );
          },
        );
        request.on("error", reject);
        if (body) request.write(body);
        request.end();
      }),
  };

  return { client: createApiClient({ bridge }), token };
}

/** @param {string} value */
function splitAddress(value) {
  const trimmed = value.trim();
  const index = trimmed.lastIndexOf(":");
  if (index <= 0) throw new Error(`not an address: ${value}`);
  return [trimmed.slice(0, index), trimmed.slice(index + 1)];
}
