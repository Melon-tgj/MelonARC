/**
 * Settings owned by the window itself.
 *
 * These are not core settings: the core reads its own configuration file, and
 * the shell reads two environment variables when it starts. What the window can
 * own is a small record of those two values plus the chosen language, kept in
 * local storage so it survives a restart. The window never holds the token.
 *
 * The language key is deliberately the same one the header switcher uses, so a
 * change made here and one made in the header converge on one value.
 */

export const SETTINGS_KEY = "melonarc.gui";
export const LOCALE_KEY = "melonarc.locale";
export const ENV_DATA_DIR = "MELONARC_DATA_DIR";
export const ENV_API_ADDR = "MELONARC_API_ADDR";
export const DEFAULT_API_ADDR = "127.0.0.1:7946";

/** Error keys, not sentences: the panel translates them. */
export const SettingsError = Object.freeze({
  DATA_DIR: "settings.error.datadir",
  API_ADDR: "settings.error.address",
});

/**
 * @param {Storage | null} [storage]
 * @returns {{ dataDir: string, apiAddr: string }}
 */
export function readSettings(storage = defaultStorage()) {
  const empty = { dataDir: "", apiAddr: "" };
  if (!storage) return empty;
  try {
    const raw = storage.getItem(SETTINGS_KEY);
    if (!raw) return empty;
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return empty;
    return {
      dataDir: typeof parsed.dataDir === "string" ? parsed.dataDir : "",
      apiAddr: typeof parsed.apiAddr === "string" ? parsed.apiAddr : "",
    };
  } catch {
    // A damaged record is the same as no record; the defaults still work.
    return empty;
  }
}

/**
 * Persist the two overrides. Returns false when storage is unavailable, so the
 * caller can say so instead of claiming a save that did not happen.
 *
 * @param {{ dataDir: string, apiAddr: string }} values
 * @param {Storage | null} [storage]
 * @returns {boolean}
 */
export function saveSettings(values, storage = defaultStorage()) {
  if (!storage) return false;
  try {
    storage.setItem(SETTINGS_KEY, JSON.stringify({
      dataDir: String(values?.dataDir ?? ""),
      apiAddr: String(values?.apiAddr ?? ""),
    }));
    return true;
  } catch {
    return false;
  }
}

/**
 * @param {Storage | null} [storage]
 * @returns {boolean}
 */
export function clearSettings(storage = defaultStorage()) {
  if (!storage) return false;
  try {
    storage.removeItem(SETTINGS_KEY);
    return true;
  } catch {
    return false;
  }
}

/**
 * Normalize and check the two values before they are stored.
 *
 * The address rule mirrors the shell: only a loopback host with a usable port
 * is accepted, because a bearer credential must never be sent off the machine.
 * An empty data directory means "use the core's default", which is valid.
 *
 * @param {{ dataDir?: string, apiAddr?: string }} input
 * @returns {{ values: { dataDir: string, apiAddr: string }, errorKey: string }}
 */
export function validateSettings(input) {
  const dataDir = String(input?.dataDir ?? "").trim();
  const apiAddr = String(input?.apiAddr ?? "").trim();
  const values = { dataDir, apiAddr: apiAddr || DEFAULT_API_ADDR };

  if (/[\u0000-\u001f\u007f]/.test(dataDir)) {
    return { values, errorKey: SettingsError.DATA_DIR };
  }
  if (!isLoopbackAddress(values.apiAddr)) {
    return { values, errorKey: SettingsError.API_ADDR };
  }
  return { values, errorKey: "" };
}

/**
 * @param {string} value
 * @returns {boolean}
 */
export function isLoopbackAddress(value) {
  const text = String(value ?? "").trim();
  const index = text.lastIndexOf(":");
  if (index <= 0) return false;

  let host = text.slice(0, index).trim();
  const port = text.slice(index + 1).trim();
  if (host.startsWith("[") && host.endsWith("]")) host = host.slice(1, -1);
  if (host === "") return false;
  if (!(host === "localhost" || host === "::1" || host.startsWith("127."))) return false;
  if (!/^\d+$/.test(port)) return false;

  const number = Number(port);
  return Number.isInteger(number) && number >= 1 && number <= 65535;
}

/**
 * Switch language through the entry point the shell already owns.
 *
 * The header select has the change listener, so writing the stored key and
 * firing one change at that control relabels the window without editing the
 * shell. The small `dispatch` branch is for the headless DOM used in tests.
 *
 * @param {string} id
 * @param {Document | { getElementById?: (id: string) => any }} [doc]
 * @returns {boolean} whether the running window was notified
 */
export function setLocale(id, doc = defaultDocument()) {
  const storage = defaultStorage();
  try {
    storage?.setItem(LOCALE_KEY, String(id));
  } catch {
    // Storage can be unavailable; the choice then lasts for this window only.
  }

  const select = doc?.getElementById?.("locale-select");
  if (!select) return false;
  select.value = String(id);
  if (typeof select.dispatch === "function") {
    select.dispatch("change", { target: { value: String(id) } });
  } else if (typeof select.dispatchEvent === "function" && typeof Event === "function") {
    select.dispatchEvent(new Event("change"));
  } else {
    return false;
  }
  return true;
}

/**
 * The two environment variable assignments a launcher needs on the next start.
 *
 * @param {{ dataDir: string, apiAddr: string }} values
 * @returns {string[]}
 */
export function envLines(values) {
  return [
    `${ENV_DATA_DIR}=${values?.dataDir ?? ""}`,
    `${ENV_API_ADDR}=${values?.apiAddr ?? ""}`,
  ];
}

/** @returns {Storage | null} */
function defaultStorage() {
  try {
    return typeof localStorage === "undefined" ? null : localStorage;
  } catch {
    return null;
  }
}

/** @returns {Document | null} */
function defaultDocument() {
  try {
    return typeof document === "undefined" ? null : document;
  } catch {
    return null;
  }
}
