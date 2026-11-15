/**
 * The panel registry.
 *
 * The navigation is generated from this list and nothing else: the shell asks
 * for the registered panels, sorts them and renders one button per entry. A new
 * screen is therefore a new module plus one `register` call — the shell, the
 * router and the sidebar are not edited. That is the whole extension point of
 * this step; a future "add a plugin panel" feature would call `registerPanels`
 * with modules loaded from elsewhere and nothing else would change.
 *
 * Panel contract:
 *   id        stable identifier, also the URL hash and the persistence key
 *   icon      a name from components/icons.js
 *   titleKey  i18n key of the navigation label
 *   order     ascending sort order in the sidebar
 *   mount     (ctx) => ({ dispose? }) — fills ctx.root, releases on unmount
 *   ctx       { t, locale, api, core, root, navigate }
 */

import connections from "./connections.js";
import logs from "./logs.js";
import overview from "./overview.js";
import policies from "./policies.js";
import rules from "./rules.js";
import settings from "./settings.js";

/** @type {Array<ReturnType<typeof normalize>>} */
const panels = [];
const ids = new Set();

/**
 * @param {Array<Record<string, unknown>>} list
 */
export function registerPanels(list) {
  for (const panel of list) {
    const normalized = normalize(panel);
    if (ids.has(normalized.id)) throw new Error(`panel "${normalized.id}" is registered twice`);
    ids.add(normalized.id);
    panels.push(normalized);
  }
}

/**
 * @param {string} id
 * @returns {ReturnType<typeof normalize> | undefined}
 */
export function findPanel(id) {
  return panels.find((panel) => panel.id === id);
}

/** @returns {Array<ReturnType<typeof normalize>>} */
export function listPanels() {
  return [...panels].sort((a, b) => a.order - b.order);
}

/**
 * Validate a module once, at registration, so a broken panel fails at start-up
 * instead of when the user clicks it.
 *
 * @param {Record<string, unknown>} panel
 */
function normalize(panel) {
  const { id, icon = "dot", titleKey, order = 100, mount } = panel ?? {};
  if (typeof id !== "string" || id === "") throw new Error("panel needs an id");
  if (typeof titleKey !== "string" || titleKey === "") throw new Error(`panel "${id}" needs a titleKey`);
  if (typeof mount !== "function") throw new Error(`panel "${id}" needs a mount function`);
  return { id, icon, titleKey, order: Number(order) || 100, mount };
}

// The single line a new panel touches. Keep it alphabetical-ish by order value.
registerPanels([overview, policies, connections, rules, logs, settings]);
