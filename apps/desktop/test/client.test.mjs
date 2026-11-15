/**
 * The client's contract: which path, which method, and how a transport failure
 * becomes one of the five codes the UI knows how to explain.
 */

import assert from "node:assert/strict";
import test from "node:test";

import { createApiClient } from "../src/api/client.js";
import { chooseBridge, createHttpBridge, createNullBridge, createTauriBridge } from "../src/api/bridge.js";
import { ApiFailure, ErrorCode } from "../src/api/errors.js";

/**
 * A bridge that records calls and answers with a canned reply.
 *
 * @param {Array<{ status: number, body: string }> | ((req: object) => any)} answer
 */
function recordingBridge(answer) {
  const calls = [];
  return {
    calls,
    kind: "test",
    async request(request) {
      calls.push(request);
      if (typeof answer === "function") return answer(request);
      const next = Array.isArray(answer) ? answer.shift() : answer;
      if (next instanceof Error) throw next;
      return next;
    },
  };
}

test("reads the endpoints this step needs", async () => {
  const bridge = recordingBridge({ status: 200, body: "{}" });
  const api = createApiClient({ bridge });

  await api.status();
  await api.config();
  await api.policies();
  await api.inbound();
  await api.failures(5);

  assert.deepEqual(
    bridge.calls.map((call) => `${call.method} ${call.path}`),
    [
      "GET /v1/status",
      "GET /v1/config",
      "GET /v1/policies",
      "GET /v1/inbound",
      "GET /v1/failures?limit=5",
    ],
  );
});

test("the rules, explanation and audit endpoints go through the same bridge", async () => {
  const bridge = recordingBridge({ status: 200, body: "{}" });
  const api = createApiClient({ bridge });

  await api.rules(500);
  await api.explain({ name: "example.com", network: "tcp" });
  await api.explain({ addr: "203.0.113.9", port: 443, network: "" });
  await api.audit(64);

  assert.deepEqual(
    bridge.calls.map((call) => `${call.method} ${call.path}`),
    [
      "GET /v1/rules?limit=500",
      "GET /v1/rules/explain?name=example.com&network=tcp",
      "GET /v1/rules/explain?addr=203.0.113.9&port=443",
      "GET /v1/audit?limit=64",
    ],
  );
});

test("runtime metadata comes from the bridge, and a missing one is not an error", async () => {
  const withRuntime = { kind: "test", runtime: async () => ({ mode: "preview", dataDir: "/tmp/arc/data" }) };
  assert.equal((await createApiClient({ bridge: withRuntime }).runtime()).dataDir, "/tmp/arc/data");

  const noRuntime = { kind: "test" };
  assert.equal(await createApiClient({ bridge: noRuntime }).runtime(), null);

  const failing = { kind: "test", runtime: async () => { throw new Error("gone"); } };
  assert.equal(await createApiClient({ bridge: failing }).runtime(), null);
});

test("pins a member with a JSON body", async () => {
  const bridge = recordingBridge({ status: 200, body: JSON.stringify({ group: "manual", active: "b" }) });
  const api = createApiClient({ bridge });

  const view = await api.selectPolicy("manual", "b");
  assert.equal(view.active, "b");
  assert.equal(bridge.calls[0].method, "POST");
  assert.equal(bridge.calls[0].path, "/v1/policies/select");
  assert.deepEqual(JSON.parse(bridge.calls[0].body), { group: "manual", member: "b" });
});

test("a 401 is an auth failure, not a transport failure", async () => {
  const bridge = recordingBridge({ status: 401, body: JSON.stringify({ error: { code: "unauthorized" } }) });
  const api = createApiClient({ bridge });
  await assert.rejects(api.status(), (error) => {
    assert.ok(error instanceof ApiFailure);
    assert.equal(error.code, ErrorCode.UNAUTHORIZED);
    assert.equal(error.status, 401);
    return true;
  });
});

test("the preview proxy counts as the core being down, with its own reason", async () => {
  const missingToken = recordingBridge({
    status: 502,
    body: JSON.stringify({ error: { code: "token_missing", message: "no token file" }, proxied: false }),
  });
  await assert.rejects(createApiClient({ bridge: missingToken }).status(), { code: ErrorCode.TOKEN_MISSING });

  const unreachable = recordingBridge({
    status: 502,
    body: JSON.stringify({ error: { code: "core_unreachable", message: "connect ECONNREFUSED" }, proxied: false }),
  });
  await assert.rejects(createApiClient({ bridge: unreachable }).status(), { code: ErrorCode.CORE_UNREACHABLE });
});

test("an error document from the core keeps its message as detail only", async () => {
  const bridge = recordingBridge({
    status: 400,
    body: JSON.stringify({ error: { code: "bad_request", message: "group is required" } }),
  });
  await assert.rejects(createApiClient({ bridge }).selectPolicy("", "x"), (error) => {
    assert.equal(error.code, ErrorCode.API_ERROR);
    assert.equal(error.apiCode, "bad_request");
    assert.equal(error.detail, "group is required");
    assert.equal(error.message, ErrorCode.API_ERROR, "the message is a code, never the core text");
    return true;
  });
});

test("an answer that is not JSON is a bad response, not a crash", async () => {
  const bridge = recordingBridge({ status: 200, body: "<html>nope</html>" });
  await assert.rejects(createApiClient({ bridge }).status(), { code: ErrorCode.BAD_RESPONSE });
});

test("a failing bridge is normalized into an ApiFailure", async () => {
  const failing = recordingBridge(new ApiFailure(ErrorCode.CORE_UNREACHABLE, { detail: "ECONNREFUSED" }));
  await assert.rejects(createApiClient({ bridge: failing }).status(), (error) => {
    assert.equal(error.code, ErrorCode.CORE_UNREACHABLE);
    assert.equal(error.detail, "ECONNREFUSED");
    return true;
  });

  const odd = recordingBridge(new Error("boom"));
  await assert.rejects(createApiClient({ bridge: odd }).status(), { code: ErrorCode.BAD_RESPONSE });
});

test("without a bridge the client says so instead of fetching", async () => {
  const api = createApiClient({ bridge: createNullBridge() });
  await assert.rejects(api.status(), { code: ErrorCode.NO_BRIDGE });
});

test("the preview bridge prefixes /bridge and forwards the body", async () => {
  const seen = [];
  const bridge = createHttpBridge({
    fetchImpl: async (url, init) => {
      seen.push({ url, method: init.method, body: init.body });
      return { status: 200, text: async () => "{}" };
    },
  });

  await bridge.request({ method: "POST", path: "/v1/policies/select", body: '{"group":"g","member":"m"}' });
  assert.deepEqual(seen, [
    { url: "/bridge/v1/policies/select", method: "POST", body: '{"group":"g","member":"m"}' },
  ]);
});

test("a refused connection in the preview bridge is a connectivity failure", async () => {
  const bridge = createHttpBridge({
    fetchImpl: async () => {
      throw new TypeError("fetch failed");
    },
  });
  await assert.rejects(bridge.request({ method: "GET", path: "/v1/status" }), {
    code: ErrorCode.CORE_UNREACHABLE,
  });
});

test("the shell wins over the preview server", async () => {
  const invokes = [];
  const tauri = await chooseBridge({
    invoke: async (command, args) => {
      invokes.push(command);
      return { status: 200, body: "{}" };
    },
    probe: async () => true,
  });
  assert.equal(tauri.kind, "tauri");
  await tauri.request({ method: "GET", path: "/v1/status" });
  assert.deepEqual(invokes, ["api_request"]);

  const preview = await chooseBridge({ invoke: null, probe: async () => true });
  assert.equal(preview.kind, "http");

  const none = await chooseBridge({ invoke: null, probe: async () => false });
  assert.equal(none.kind, "none");

  const brokenProbe = await chooseBridge({
    invoke: null,
    probe: async () => {
      throw new Error("no server");
    },
  });
  assert.equal(brokenProbe.kind, "none");
});

// --------------------------------------------------------------- supervision

const coreStatusWire = {
  state: "crashed",
  pid: 4242,
  started_at_unix_ms: 1_760_000_000_000,
  restarts: 3,
  detail: "the core exited with status 1",
};

const shellSettingsWire = {
  settings_path: "/home/melon/.config/melonarc/shell.json",
  stored: { data_dir: "/tmp/arc/data", api_addr: "", core_path: "", core_config: "" },
  effective: { data_dir: "/tmp/arc/data", api_addr: "127.0.0.1:7946", core_path: "/opt/melonarc-core", core_config: "/tmp/arc/data/melonarc.conf" },
  restart_required: true,
};

test("the shell's process status keeps snake_case off the page", async () => {
  const calls = [];
  const bridge = createTauriBridge(async (command, args) => {
    calls.push({ command, args });
    if (command === "core_status" || command === "core_restart") return coreStatusWire;
    if (command === "get_shell_settings") return shellSettingsWire;
    if (command === "set_shell_settings") return { ...shellSettingsWire, stored: { ...shellSettingsWire.stored, ...args.values } };
    return null;
  });

  assert.deepEqual(await bridge.coreStatus(), {
    state: "crashed",
    pid: 4242,
    startedAtUnixMs: 1_760_000_000_000,
    restarts: 3,
    detail: "the core exited with status 1",
  });
  assert.equal((await bridge.coreRestart()).state, "crashed");

  const settings = await bridge.shellSettings();
  assert.equal(settings.settingsPath, "/home/melon/.config/melonarc/shell.json");
  assert.equal(settings.restartRequired, true);
  assert.equal(settings.effective.coreConfig, "/tmp/arc/data/melonarc.conf");

  const saved = await bridge.saveShellSettings({ dataDir: "/tmp/arc/other", apiAddr: "", corePath: "", coreConfig: "" });
  assert.equal(saved.stored.dataDir, "/tmp/arc/other", "the answer comes back in the page's names");
  assert.equal("data_dir" in saved.stored, false, "no snake_case key reaches a panel");
  assert.deepEqual(calls.at(-1), {
    command: "set_shell_settings",
    args: { values: { data_dir: "/tmp/arc/other", api_addr: "", core_path: "", core_config: "" } },
  });
});

test("the preview bridge answers the same four questions over HTTP", async () => {
  const seen = [];
  const bridge = createHttpBridge({
    fetchImpl: async (url, init = {}) => {
      const method = init.method ?? "GET";
      seen.push({ url, method, body: init.body ?? null });

      if (url.endsWith("/shell/status") || url.endsWith("/shell/restart")) {
        return { ok: true, status: 200, json: async () => coreStatusWire, text: async () => "" };
      }
      if (url.endsWith("/shell/settings")) {
        // A write answers with the file as it now stands, exactly like the shell.
        const payload = method === "POST" ? { ...shellSettingsWire, stored: JSON.parse(init.body) } : shellSettingsWire;
        return { ok: true, status: 200, json: async () => payload, text: async () => "" };
      }
      return { ok: false, status: 404, json: async () => null, text: async () => "" };
    },
  });

  assert.equal((await bridge.coreStatus()).pid, 4242);
  assert.equal((await bridge.coreRestart()).state, "crashed");
  assert.equal((await bridge.shellSettings()).restartRequired, true);
  const saved = await bridge.saveShellSettings({ dataDir: "/tmp/x", apiAddr: "127.0.0.1:1", corePath: "", coreConfig: "" });
  assert.equal(saved.stored.dataDir, "/tmp/x");

  assert.deepEqual(
    seen.map((call) => `${call.method} ${call.url}`),
    [
      "GET /bridge/shell/status",
      "POST /bridge/shell/restart",
      "GET /bridge/shell/settings",
      "POST /bridge/shell/settings",
    ],
  );
  assert.deepEqual(JSON.parse(seen.at(-1).body), {
    data_dir: "/tmp/x",
    api_addr: "127.0.0.1:1",
    core_path: "",
    core_config: "",
  });
});

test("a transport without supervision says so instead of inventing a state", async () => {
  const none = createNullBridge();
  assert.equal(await none.coreStatus(), null);
  assert.equal(await none.coreRestart(), null);
  assert.equal(await none.shellSettings(), null);
  assert.equal(await none.saveShellSettings({ dataDir: "" }), null);

  const bare = { kind: "test" };
  const api = createApiClient({ bridge: bare });
  assert.equal(await api.coreStatus(), null);
  assert.equal(await api.coreRestart(), null);
  assert.equal(await api.shellSettings(), null);
  assert.equal(await api.saveShellSettings({ dataDir: "/tmp/x" }), null);

  const failing = { kind: "test", coreStatus: async () => { throw new Error("gone"); } };
  assert.equal(await createApiClient({ bridge: failing }).coreStatus(), null, "a failure is null, not an invention");
});
