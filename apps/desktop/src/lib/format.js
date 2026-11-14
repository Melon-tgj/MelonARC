/**
 * Value formatting shared by every panel.
 *
 * Numbers and dates go through `Intl`, so a panel never decides on its own
 * whether the app is in Chinese or English. Units stay ASCII: they are symbols,
 * not prose, and keeping them identical across locales keeps tables aligned.
 */

const UNITS = ["B", "KiB", "MiB", "GiB", "TiB"];

/**
 * Human readable byte count, binary units, at most two fraction digits.
 *
 * @param {number} bytes
 * @returns {string}
 */
export function formatBytes(bytes) {
  const value = Number(bytes);
  if (!Number.isFinite(value) || value < 0) return "—";
  if (value < 1024) return `${Math.round(value)} B`;
  let scaled = value;
  let unit = 0;
  while (scaled >= 1024 && unit < UNITS.length - 1) {
    scaled /= 1024;
    unit += 1;
  }
  const digits = scaled >= 100 ? 0 : scaled >= 10 ? 1 : 2;
  const text = scaled.toFixed(digits);
  const trimmed = text.includes(".") ? text.replace(/0+$/, "").replace(/\.$/, "") : text;
  return `${trimmed} ${UNITS[unit]}`;
}

/**
 * Duration in seconds as a compact pair of the two largest units.
 *
 * @param {number} seconds
 * @returns {string}
 */
export function formatDuration(seconds) {
  const total = Math.floor(Number(seconds));
  if (!Number.isFinite(total) || total < 0) return "—";
  if (total < 60) return `${total}s`;
  if (total < 3600) {
    const minutes = Math.floor(total / 60);
    const rest = total % 60;
    return `${minutes}m ${String(rest).padStart(2, "0")}s`;
  }
  if (total < 86400) {
    const hours = Math.floor(total / 3600);
    const minutes = Math.floor((total % 3600) / 60);
    return `${hours}h ${String(minutes).padStart(2, "0")}m`;
  }
  const days = Math.floor(total / 86400);
  const hours = Math.floor((total % 86400) / 3600);
  return `${days}d ${String(hours).padStart(2, "0")}h`;
}

/**
 * Parse an RFC 3339 timestamp from the API.
 *
 * @param {string} value
 * @returns {Date | null}
 */
export function parseTime(value) {
  if (typeof value !== "string" || value === "") return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

/**
 * Time of day, seconds included: failure records are often seconds apart.
 *
 * @param {string} value
 * @param {string} locale
 * @returns {string}
 */
export function formatTime(value, locale) {
  const date = parseTime(value);
  if (!date) return "—";
  return new Intl.DateTimeFormat(locale, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(date);
}

/**
 * Date and time, used where a record may be older than today.
 *
 * @param {string} value
 * @param {string} locale
 * @returns {string}
 */
export function formatDateTime(value, locale) {
  const date = parseTime(value);
  if (!date) return "—";
  return new Intl.DateTimeFormat(locale, {
    dateStyle: "short",
    timeStyle: "medium",
    hour12: false,
  }).format(date);
}

/**
 * @param {number} value
 * @param {string} locale
 * @returns {string}
 */
export function formatNumber(value, locale) {
  const number = Number(value);
  if (!Number.isFinite(number)) return "—";
  return new Intl.NumberFormat(locale).format(number);
}

/**
 * Milliseconds as a latency figure; 0 means the member was never measured.
 *
 * @param {number} ms
 * @returns {string}
 */
export function formatLatency(ms) {
  const value = Number(ms);
  if (!Number.isFinite(value) || value <= 0) return "—";
  return `${Math.round(value)} ms`;
}
