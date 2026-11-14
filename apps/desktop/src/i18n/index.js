/**
 * Internationalisation.
 *
 * Every string the user can read comes from `locales/<id>.json`. A panel asks
 * the translator for a key; nothing in `src/` is allowed to contain a literal
 * sentence (the test suite greps for CJK text outside `locales/` to keep that
 * honest). Adding a language is adding a file and one entry in LOCALES.
 */

/** Languages shipped in this step. `id` is also the filename in `locales/`. */
export const LOCALES = Object.freeze([{ id: "zh-CN" }, { id: "en" }]);

export const DEFAULT_LOCALE = "zh-CN";
export const FALLBACK_LOCALE = "en";

/**
 * @param {string} id
 * @returns {{id: string, label: string} | undefined}
 */
export function findLocale(id) {
  return LOCALES.find((locale) => locale.id === id);
}

/**
 * Resolve the locale to start in: an explicit choice wins, then the first
 * language the system asks for, then the default.
 *
 * @param {{ available?: string[], languages?: string[], stored?: string | null }} [options]
 * @returns {string}
 */
export function detectLocale({ available = LOCALES.map((l) => l.id), languages = [], stored = null } = {}) {
  if (stored && available.includes(stored)) return stored;

  for (const language of languages) {
    if (typeof language !== "string" || language === "") continue;
    if (available.includes(language)) return language;
    const lower = language.toLowerCase();
    const exact = available.find((id) => id.toLowerCase() === lower);
    if (exact) return exact;
    const primary = lower.split("-")[0];
    const byPrimary = available.find((id) => id.toLowerCase().split("-")[0] === primary);
    if (byPrimary) return byPrimary;
  }

  return available.includes(DEFAULT_LOCALE) ? DEFAULT_LOCALE : available[0];
}

/**
 * Load one catalogue.
 *
 * @param {string} id
 * @param {{ fetchImpl?: typeof fetch, baseUrl?: string | URL }} [options]
 * @returns {Promise<Record<string, string>>}
 */
export async function loadCatalog(id, options = {}) {
  const locale = findLocale(id);
  if (!locale) throw new Error(`unknown locale: ${id}`);

  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  const base = options.baseUrl ?? defaultBaseUrl();
  const response = await fetchImpl(new URL(`${locale.id}.json`, base), { cache: "no-store" });
  if (!response.ok) throw new Error(`locale ${locale.id}: HTTP ${response.status}`);
  return response.json();
}

/**
 * Load every catalogue at start-up.
 *
 * The language switcher needs each language's own name (`meta.self`), so the
 * packs are read up front rather than on selection; switching a language then
 * costs nothing and takes effect immediately. A pack that cannot be read is
 * replaced by an empty one: the window stays usable in the remaining languages.
 *
 * @param {{ fetchImpl?: typeof fetch, baseUrl?: string | URL }} [options]
 * @returns {Promise<Map<string, Record<string, string>>>}
 */
export async function loadCatalogs(options = {}) {
  const loaded = await Promise.all(
    LOCALES.map(async (locale) => {
      try {
        return [locale.id, await loadCatalog(locale.id, options)];
      } catch {
        return [locale.id, {}];
      }
    }),
  );
  return new Map(loaded);
}

/**
 * The name a language calls itself, taken from its own pack.
 *
 * @param {Record<string, string> | undefined} catalog
 * @param {string} id
 * @returns {string}
 */
export function localeLabel(catalog, id) {
  const label = catalog?.["meta.self"];
  return typeof label === "string" && label !== "" ? label : id;
}

/**
 * @returns {URL}
 */
function defaultBaseUrl() {
  // src/i18n/index.js -> ../../locales/. The same relative walk works in the
  // built tree (dist/src/i18n/index.js -> dist/locales/), because the build
  // copies src/ and locales/ side by side.
  return new URL("../../locales/", import.meta.url);
}

/**
 * Build a translator over one catalogue with a fallback chain.
 *
 * Missing keys fall back to the other catalogue and finally to the key itself,
 * which is visible but never fatal: a half translated build still runs.
 *
 * @param {Record<string, string>} catalog
 * @param {Record<string, string>} [fallback]
 * @returns {(key: string, vars?: Record<string, string | number>) => string}
 */
export function createTranslator(catalog, fallback = {}) {
  return function translate(key, vars) {
    const template = catalog[key] ?? fallback[key] ?? key;
    if (!vars) return template;
    return template.replace(/\{(\w+)\}/g, (match, name) => {
      const value = vars[name];
      return value === undefined || value === null ? match : String(value);
    });
  };
}

/**
 * Apply translations to every tagged node under `root`.
 *
 * `data-i18n` sets the text, `data-i18n-title` the title attribute and
 * `data-i18n-aria-label` the accessible name.
 *
 * @param {ParentNode} root
 * @param {(key: string) => string} t
 */
export function applyTranslations(root, t) {
  for (const node of root.querySelectorAll("[data-i18n]")) {
    node.textContent = t(node.dataset.i18n);
  }
  for (const node of root.querySelectorAll("[data-i18n-title]")) {
    node.setAttribute("title", t(node.dataset.i18nTitle));
  }
  for (const node of root.querySelectorAll("[data-i18n-aria-label]")) {
    node.setAttribute("aria-label", t(node.dataset.i18nAriaLabel));
  }
}
