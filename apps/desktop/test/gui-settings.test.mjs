/**
 * The window's own settings helpers.
 *
 * Since this stage the four overrides belong to the shell and live in
 * `shell.json`; what is left here is the check the panel runs before it sends
 * anything, plus the language key shared with the header switcher. The tests
 * therefore pin two things: that a bad value is refused *before* a request, and
 * that the address rule still matches the shell's loopback-only rule.
 */

import assert from "node:assert/strict";
import test from "node:test";

import {
  BLANK_DRAFT,
  LOCALE_KEY,
  SettingsError,
  isLoopbackAddress,
  readShellDraft,
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

test("the draft reads the stored overrides and stays blank without them", () => {
  assert.deepEqual(readShellDraft(null), BLANK_DRAFT);

  const view = {
    stored: { dataDir: "/tmp/arc/data", apiAddr: "127.0.0.1:7947", corePath: "", coreConfig: "/tmp/arc/demo.conf" },
    effective: { dataDir: "/tmp/arc/other", apiAddr: "127.0.0.1:7946", corePath: "/opt/core", coreConfig: "/tmp/arc/demo.conf" },
    settingsPath: "/home/melon/.config/melonarc/shell.json",
    restartRequired: true,
  };
  assert.deepEqual(readShellDraft(view), {
    dataDir: "/tmp/arc/data",
    apiAddr: "127.0.0.1:7947",
    corePath: "",
    coreConfig: "/tmp/arc/demo.conf",
  });
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

test("validation trims the four values and keeps an empty address empty", () => {
  const trimmed = validateSettings({
    dataDir: "  /tmp/arc/data  ",
    apiAddr: "  127.0.0.1:7947 ",
    corePath: " /opt/melonarc-core ",
    coreConfig: " /tmp/arc/demo.conf ",
  });
  assert.equal(trimmed.errorKey, "");
  assert.deepEqual(trimmed.values, {
    dataDir: "/tmp/arc/data",
    apiAddr: "127.0.0.1:7947",
    corePath: "/opt/melonarc-core",
    coreConfig: "/tmp/arc/demo.conf",
  });

  const blank = validateSettings({ dataDir: "", apiAddr: "", corePath: "", coreConfig: "" });
  assert.equal(blank.errorKey, "");
  assert.equal(blank.values.apiAddr, "", "an empty address means 'no override', not 'use the default'");
});

test("a value the shell would refuse is refused here first", () => {
  const base = { dataDir: "/tmp/ok", apiAddr: "127.0.0.1:80", corePath: "", coreConfig: "" };

  assert.equal(validateSettings({ ...base, apiAddr: "10.0.0.1:80" }).errorKey, SettingsError.API_ADDR);
  assert.equal(validateSettings({ ...base, dataDir: "/tmp/bad\nplace" }).errorKey, SettingsError.DATA_DIR);
  assert.equal(validateSettings({ ...base, corePath: "/opt/bad\ncore" }).errorKey, SettingsError.CORE_PATH);
  assert.equal(validateSettings({ ...base, coreConfig: "/tmp/bad.conf\u0007" }).errorKey, SettingsError.CORE_CONFIG);
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
