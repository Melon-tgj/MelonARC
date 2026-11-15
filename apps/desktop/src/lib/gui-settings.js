/**
 * The window's own settings helpers.
 *
 * Two very different things used to live here and are now separated:
 *
 * * the four overrides (data directory, API address, core binary, core
 *   configuration) belong to the *shell*, are stored in `shell.json`, and are
 *   read and written through the transport. This module only normalises and
 *   checks them before they are sent, because an invalid value must be caught
 *   before a request is made — and the same rule is enforced again on the shell
 *   side, which is the one that matters.
 * * the language belongs to *this window* and stays in local storage under the
 *   key the header switcher uses.
 *
 * A `melonarc.gui` record from an earlier build may still sit in local storage.
 * It is deliberately ignored rather than migrated: the file is the single
 * source of truth now, and migrating a stale copy into it would resurrect values
 * the user never re-confirmed.
 */

export const LOCALE_KEY = "melonarc.locale";

/** The core's default listener, shown as a placeholder in the settings panel. */
export const DEFAULT_API_ADDR = "127.0.0.1:7946";

/** Error keys, not sentences: the panel translates them. */
export const SettingsError = Object.freeze({
  DATA_DIR: "settings.error.datadir",
  API_ADDR: "settings.error.address",
  CORE_PATH: "settings.error.corepath",
  CORE_CONFIG: "settings.error.coreconfig",
});

/**
 * The four values as the panel edits them, all empty.
 */
export const BLANK_DRAFT = Object.freeze({
  dataDir: "",
  apiAddr: "",
  corePath: "",
  coreConfig: "",
});

/**
 * The four values as the panel edits them. An empty string means "no override",
 * which is also how the shell reads a missing key.
 *
 * @param {any} view the answer of `shellSettings` (or `saveShellSettings`)
 * @param {{ blank?: Record<string, string> }} [options]
 * @returns {{ dataDir: string, apiAddr: string, corePath: string, coreConfig: string }}
 */
export function readShellDraft(view, { blank = BLANK_DRAFT } = {}) {
  const stored = view?.stored;
  if (!stored) return { ...blank };
  return {
    dataDir: String(stored.dataDir ?? ""),
    apiAddr: String(stored.apiAddr ?? ""),
    corePath: String(stored.corePath ?? ""),
    coreConfig: String(stored.coreConfig ?? ""),
  };
}

/**
 * Normalize and check the four values before they are written.
 *
 * The address rule mirrors the shell: only a loopback host with a usable port
 * is accepted, because a bearer credential must never be sent off the machine.
 * An empty value means "keep the default" for every field, so it is always
 * valid. Paths refuse control characters: a newline in a path would end up in
 * the settings file and then in a spawn argument.
 *
 * @param {{ dataDir?: string, apiAddr?: string, corePath?: string, coreConfig?: string }} input
 * @returns {{ values: { dataDir: string, apiAddr: string, corePath: string, coreConfig: string }, errorKey: string }}
 */
export function validateSettings(input) {
  const values = {
    dataDir: String(input?.dataDir ?? "").trim(),
    apiAddr: String(input?.apiAddr ?? "").trim(),
    corePath: String(input?.corePath ?? "").trim(),
    coreConfig: String(input?.coreConfig ?? "").trim(),
  };

  const control = /[\u0000-\u001f\u007f]/;
  if (control.test(values.dataDir)) return { values, errorKey: SettingsError.DATA_DIR };
  if (control.test(values.corePath)) return { values, errorKey: SettingsError.CORE_PATH };
  if (control.test(values.coreConfig)) return { values, errorKey: SettingsError.CORE_CONFIG };
  if (values.apiAddr !== "" && !isLoopbackAddress(values.apiAddr)) {
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
