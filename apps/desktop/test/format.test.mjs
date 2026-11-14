/**
 * Formatting is shared by every panel, so its edges are worth pinning: a byte
 * count that reads "1 KiB", a duration that never shows a bare 0 in a table, and
 * a timestamp that survives an unparseable value.
 */

import assert from "node:assert/strict";
import test from "node:test";

import { formatBytes, formatDuration, formatLatency, formatNumber, formatTime } from "../src/lib/format.js";

test("byte counts use binary units and drop trailing zeros", () => {
  assert.equal(formatBytes(0), "0 B");
  assert.equal(formatBytes(999), "999 B");
  assert.equal(formatBytes(1024), "1 KiB");
  assert.equal(formatBytes(1536), "1.5 KiB");
  assert.equal(formatBytes(1024 * 1024 * 8.63), "8.63 MiB");
  assert.equal(formatBytes(-1), "—");
  assert.equal(formatBytes(Number.NaN), "—");
});

test("durations keep the two largest units", () => {
  assert.equal(formatDuration(0), "0s");
  assert.equal(formatDuration(45), "45s");
  assert.equal(formatDuration(65), "1m 05s");
  assert.equal(formatDuration(3725), "1h 02m");
  assert.equal(formatDuration(90000), "1d 01h");
  assert.equal(formatDuration(-3), "—");
});

test("a latency of zero means unmeasured, not instant", () => {
  assert.equal(formatLatency(0), "—");
  assert.equal(formatLatency(46.4), "46 ms");
});

test("numbers follow the locale", () => {
  assert.equal(formatNumber(1234, "en"), "1,234");
});

test("a timestamp renders as a clock or as a dash", () => {
  assert.match(formatTime("2026-11-14T10:50:26Z", "en"), /^\d{2}:\d{2}:\d{2}$/);
  assert.equal(formatTime("not a time", "en"), "—");
  assert.equal(formatTime("", "en"), "—");
});
