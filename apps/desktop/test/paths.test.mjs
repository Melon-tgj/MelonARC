/**
 * The data directory rule is shared with the Go core, so it is pinned here and
 * once more, independently, in `internal/datadir`, in `src-tauri/src/settings.rs`.
 */

import assert from "node:assert/strict";
import test from "node:test";

import { configHome, parseAddress, resolveDataDir, tokenPath } from "../scripts/lib/paths.mjs";

test("linux follows XDG_CONFIG_HOME, then ~/.config", () => {
  assert.equal(configHome({ env: { XDG_CONFIG_HOME: "/xdg" }, platform: "linux", home: "/home/melon" }), "/xdg");
  assert.equal(configHome({ env: {}, platform: "linux", home: "/home/melon" }), "/home/melon/.config");
  assert.equal(
    configHome({ env: { XDG_CONFIG_HOME: "" }, platform: "linux", home: "/home/melon" }),
    "/home/melon/.config",
  );
});

test("macOS and Windows use their own configuration directory", () => {
  assert.equal(
    configHome({ env: {}, platform: "darwin", home: "/Users/melon" }),
    "/Users/melon/Library/Application Support",
  );
  assert.equal(
    configHome({ env: { APPDATA: "C:\\Users\\melon\\AppData\\Roaming" }, platform: "win32", home: "C:\\Users\\melon" }),
    "C:\\Users\\melon\\AppData\\Roaming",
  );
});

test("the default directory is the configuration directory plus the product name", () => {
  assert.equal(
    resolveDataDir({ explicit: null, env: { XDG_CONFIG_HOME: "/xdg" }, platform: "linux", home: "/home/melon" }),
    "/xdg/melonarc",
  );
});

test("an explicit directory wins and is made absolute", () => {
  assert.equal(
    resolveDataDir({ explicit: "/tmp/arc/data", env: {}, platform: "linux", home: "/home/melon" }),
    "/tmp/arc/data",
  );
  assert.equal(
    resolveDataDir({ explicit: "  /tmp/arc/data  ", env: {}, platform: "linux", home: "/home/melon" }),
    "/tmp/arc/data",
  );
  assert.equal(
    resolveDataDir({ explicit: "", env: { XDG_CONFIG_HOME: "/xdg" }, platform: "linux", home: "/home/melon" }),
    "/xdg/melonarc",
  );
});

test("the token file has one name", () => {
  assert.equal(tokenPath("/tmp/arc/data"), "/tmp/arc/data/api-token");
});

test("an address must be host:port", () => {
  assert.deepEqual(parseAddress("127.0.0.1:7946"), { host: "127.0.0.1", port: 7946, label: "127.0.0.1:7946" });
  assert.deepEqual(parseAddress("[::1]:7946"), { host: "::1", port: 7946, label: "[::1]:7946" });
  assert.throws(() => parseAddress("127.0.0.1"), /not an address/);
  assert.throws(() => parseAddress("127.0.0.1:0"), /not a port/);
  assert.throws(() => parseAddress("127.0.0.1:99999"), /not a port/);
});
