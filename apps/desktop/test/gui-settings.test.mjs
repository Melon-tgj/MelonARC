/**
 * The window's own settings store.
 *
 * It is deliberately tiny: two strings, one validation rule and the language
 * key shared with the header switcher. These tests use a stub storage so they
 * never depend on a browser being present.
 */

import assert from "node:assert/strict";
import test from "node:test";

import {
  DEFAULT_API_ADDR,
  ENV_API_ADDR,
  ENV_DATA_DIR,
  LOCALE_KEY,
  SETTINGS_KEY,
  SettingsError,
  clearSettings,
  envLines,
  isLoopbackAddress,
  readSettings,
  saveSettings,
  setLocale,
  validateSettings,
} from "../src/lib/gui-settings.js";

/** @returns {{ getItem: Function, setItem: Function, removeItem: Function, data: Map<string, string> }} */
function storage() {
  const data = new Map();
  return {
    data,
    getItem: (key) => data.get(key) ?? null,
    setItem: (key, value) => data.set(key, String(value)),
    removeItem: (key) => data.delete(key),
  };
}

test("an absent or damaged record reads as the defaults", () => {
  const store = storage();
  assert.deepEqual(readSettings(store), { dataDir: "", apiAddr: "" });

  store.setItem(SETTINGS_KEY, "not json");
  assert.deepEqual(readSettings(store), { dataDir: "", apiAddr: "" });

  store.setItem(SETTINGS_KEY, JSON.stringify({ dataDir: 7, apiAddr: null }));
  assert.deepEqual(readSettings(store), { dataDir: "", apiAddr: "" });
});

test("a saved record survives a round trip and can be cleared", () => {
  const store = storage();
  const values = { dataDir: "/tmp/arc/data", apiAddr: "127.0.0.1:7947" };

  assert.equal(saveSettings(values, store), true);
  assert.deepEqual(readSettings(store), values);
  assert.equal(clearSettings(store), true);
  assert.deepEqual(readSettings(store), { dataDir: "", apiAddr: "" });
});

test("a storage that refuses writes reports the failure instead of throwing", () => {
  const refusing = {
    getItem: () => null,
    setItem: () => {
      throw new Error("denied");
    },
    removeItem: () => {
      throw new Error("denied");
    },
  };
  assert.equal(saveSettings({ dataDir: "", apiAddr: "" }, refusing), false);
  assert.equal(clearSettings(refusing), false);
  assert.equal(saveSettings({ dataDir: "", apiAddr: "" }, null), false);
});

test("only a loopback address with a usable port is accepted", () => {
  assert.equal(isLoopbackAddress("127.0.0.1:7946"), true);
  assert.equal(isLoopbackAddress("localhost:1"), true);
  assert.equal(isLoopbackAddress("[::1]:65535"), true);
  assert.equal(isLoopbackAddress("::1:7946"), true);

  for (const value of ["192.168.1.2:7946", "0.0.0.0:7946", "127.0.0.1", "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:http", ""]) {
    assert.equal(isLoopbackAddress(value), false, value);
  }
});

test("validation fills the default address and rejects a bad data directory", () => {
  const trimmed = validateSettings({ dataDir: "  /tmp/arc/data  ", apiAddr: "  127.0.0.1:7947 " });
  assert.equal(trimmed.errorKey, "");
  assert.deepEqual(trimmed.values, { dataDir: "/tmp/arc/data", apiAddr: "127.0.0.1:7947" });

  const blank = validateSettings({ dataDir: "", apiAddr: "" });
  assert.equal(blank.errorKey, "");
  assert.equal(blank.values.apiAddr, DEFAULT_API_ADDR);

  assert.equal(validateSettings({ dataDir: "/tmp/ok", apiAddr: "10.0.0.1:80" }).errorKey, SettingsError.API_ADDR);
  assert.equal(validateSettings({ dataDir: "/tmp/bad\nplace", apiAddr: "127.0.0.1:80" }).errorKey, SettingsError.DATA_DIR);
});

test("the launcher lines carry the two environment variable names", () => {
  assert.deepEqual(envLines({ dataDir: "/tmp/arc/data", apiAddr: "127.0.0.1:7947" }), [
    `${ENV_DATA_DIR}=/tmp/arc/data`,
    `${ENV_API_ADDR}=127.0.0.1:7947`,
  ]);
});

test("a language change writes the shared key and notifies the header control", () => {
  const store = storage();
  const previous = globalThis.localStorage;
  Object.defineProperty(globalThis, "localStorage", { value: store, writable: true, configurable: true });

  const calls = [];
  const select = {
    value: "en",
    dispatch: (type, event) => calls.push({ type, value: event.target.value, self: select.value }),
  };
  const doc = { getElementById: (id) => (id === "locale-select" ? select : null) };

  try {
    assert.equal(setLocale("zh-CN", doc), true);
    assert.equal(store.getItem(LOCALE_KEY), "zh-CN");
    assert.deepEqual(calls, [{ type: "change", value: "zh-CN", self: "zh-CN" }]);
    assert.equal(setLocale("en", { getElementById: () => null }), false);
    assert.equal(store.getItem(LOCALE_KEY), "en", "the choice is still remembered without a header control");
  } finally {
    if (previous === undefined) delete globalThis.localStorage;
    else Object.defineProperty(globalThis, "localStorage", { value: previous, writable: true, configurable: true });
  }
});
