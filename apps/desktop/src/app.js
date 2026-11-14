/**
 * The shell: header, navigation, banner and the panel host.
 *
 * This file is the only place that knows about panels as a collection. It does
 * not know which panels exist — `panels/registry.js` does — and it does not know
 * how a request travels — `api/bridge.js` does. Adding a screen or a transport
 * should not require editing this file; that is the test of the structure.
 */

import { chooseBridge, probePreview } from "./api/bridge.js";
import { createApiClient } from "./api/client.js";
import { icon } from "./components/icons.js";
import { notice, pill } from "./components/common.js";
import { LOCALES, createTranslator, detectLocale, findLocale, loadCatalogs, localeLabel } from "./i18n/index.js";
import { CoreStatus, createCoreState } from "./lib/core-state.js";
import { clear, el } from "./lib/dom.js";
import { findPanel, listPanels } from "./panels/registry.js";
import { APP_LICENSE, APP_VERSION } from "./version.js";

const LOCALE_STORAGE_KEY = "melonarc.locale";
const logoUrl = new URL("./assets/logo.png", import.meta.url).href;

/**
 * @param {HTMLElement} root
 */
export async function startApp(root) {
  const shell = createShell();
  root.replaceWith(shell.node);
  shell.node.id = root.id;

  const state = {
    locale: detectLocale({
      available: LOCALES.map((locale) => locale.id),
      languages: navigator.languages ?? [navigator.language],
      stored: readStoredLocale(),
    }),
    catalog: {},
    fallback: {},
    catalogs: new Map(),
    runtime: null,
  };

  state.catalogs = await loadCatalogs();
  loadLocale();

  const invoke = resolveInvoke();
  const bridge = await chooseBridge({
    invoke,
    probe: location.protocol.startsWith("http") ? () => probePreview() : null,
  });
  const api = createApiClient({ bridge });
  state.runtime = (await bridge.runtime?.()) ?? null;

  const core = createCoreState({
    client: api,
    initial: bridge.kind === "none" ? { status: CoreStatus.NO_BRIDGE, code: "no_bridge" } : { status: CoreStatus.UNKNOWN },
    onChange: () => {
      renderChrome();
      renderBanner();
    },
  });

  let active = null;

  function currentT(key, vars) {
    return createTranslator(state.catalog, state.fallback)(key, vars);
  }

  function selectPanel(id, { updateHash = true } = {}) {
    const panel = findPanel(id) ?? listPanels()[0];
    if (!panel) return;
    if (active?.dispose) active.dispose();
    clear(shell.panelRoot);

    const context = {
      t: currentT,
      locale: state.locale,
      api,
      core,
      root: shell.panelRoot,
      navigate: (next) => selectPanel(next),
    };
    const result = panel.mount(context);
    active = { id: panel.id, dispose: typeof result?.dispose === "function" ? result.dispose : null };

    for (const button of shell.navRoot.querySelectorAll("[data-panel]")) {
      if (button.dataset.panel === panel.id) button.setAttribute("aria-current", "page");
      else button.removeAttribute("aria-current");
    }
    document.title = `${currentT("app.name")} — ${currentT(panel.titleKey)}`;
    if (updateHash && location.hash.slice(1) !== panel.id) location.hash = panel.id;
  }

  function renderNav() {
    clear(shell.navRoot);
    for (const panel of listPanels()) {
      shell.navRoot.append(
        el(
          "button",
          {
            class: "nav-item",
            type: "button",
            dataset: { panel: panel.id },
            onClick: () => selectPanel(panel.id),
          },
          [icon(panel.icon), el("span", { text: currentT(panel.titleKey) })],
        ),
      );
    }
  }

  function renderChrome() {
    const status = core.state.status;
    const tone =
      status === CoreStatus.ONLINE
        ? "ok"
        : status === CoreStatus.UNKNOWN
          ? "muted"
          : status === CoreStatus.UNAUTHORIZED
            ? "warn"
            : "bad";
    const labelKey =
      status === CoreStatus.ONLINE
        ? "core.pill.online"
        : status === CoreStatus.UNAUTHORIZED
          ? "core.pill.unauthorized"
          : status === CoreStatus.OFFLINE || status === CoreStatus.NO_BRIDGE
            ? "core.pill.offline"
            : "core.pill.unknown";

    clear(shell.pillRoot);
    shell.pillRoot.append(pill({ text: currentT(labelKey), tone }));
    shell.footerVersion.textContent = `${currentT("overview.version")} ${APP_VERSION} · ${APP_LICENSE}`;
    shell.brandName.textContent = currentT("app.name");
    shell.langLabel.textContent = currentT("lang.label");
  }

  function renderBanner() {
    clear(shell.bannerRoot);
    const status = core.state.status;
    if (status === CoreStatus.ONLINE || status === CoreStatus.UNKNOWN) return;

    const runtime = state.runtime ?? {};
    const retry = el("button", { class: "btn", type: "button", text: currentT("common.retry"), onClick: () => core.refresh() });

    if (status === CoreStatus.NO_BRIDGE) {
      shell.bannerRoot.append(
        notice({
          tone: "warn",
          title: currentT("core.nobridge.title"),
          body: currentT("core.nobridge.body"),
          actions: [retry],
        }),
      );
      return;
    }

    if (status === CoreStatus.UNAUTHORIZED) {
      const hints = runtime.tokenPath
        ? [{ text: currentT("core.auth.hint.token", { path: runtime.tokenPath }) }]
        : [];
      shell.bannerRoot.append(
        notice({
          tone: "warn",
          title: currentT("core.auth.title"),
          body: currentT("core.auth.body"),
          hints,
          detail: core.state.detail,
          detailLabel: currentT("core.detail"),
          actions: [retry],
        }),
      );
      return;
    }

    const hints = [{ text: currentT("core.offline.hint.start"), mono: true }];
    if (runtime.apiAddress) hints.push({ text: currentT("core.offline.hint.address", { address: runtime.apiAddress }) });
    if (runtime.tokenPath) hints.push({ text: currentT("core.offline.hint.token", { path: runtime.tokenPath }) });

    shell.bannerRoot.append(
      notice({
        tone: "warn",
        title: currentT("core.offline.title"),
        body: currentT("core.offline.body"),
        hints,
        detail: core.state.detail,
        detailLabel: currentT("core.detail"),
        actions: [retry],
      }),
    );
  }

  function renderLanguageOptions() {
    clear(shell.langSelect);
    for (const locale of LOCALES) {
      const label = localeLabel(state.catalogs.get(locale.id), locale.id);
      shell.langSelect.append(
        el("option", { value: locale.id, text: label, selected: locale.id === state.locale }),
      );
    }
    shell.langSelect.value = state.locale;
  }

  function relabel() {
    renderChrome();
    renderNav();
    renderBanner();
    if (active) selectPanel(active.id, { updateHash: false });
  }

  /** Point the translator at the current pack; all packs are already loaded. */
  function loadLocale() {
    if (state.catalogs.size === 0) return;
    state.catalog = state.catalogs.get(state.locale) ?? {};
    state.fallback = state.catalogs.get("en") ?? {};
  }

  shell.langSelect.addEventListener("change", (event) => {
    const next = findLocale(event.target.value);
    if (!next || next.id === state.locale) return;
    state.locale = next.id;
    storeLocale(next.id);
    loadLocale();
    relabel();
  });

  window.addEventListener("hashchange", () => {
    const id = location.hash.slice(1);
    if (id && id !== active?.id) selectPanel(id, { updateHash: false });
  });

  renderLanguageOptions();
  renderChrome();
  renderNav();
  renderBanner();
  core.start();
  selectPanel(location.hash.slice(1) || listPanels()[0]?.id, { updateHash: false });
}

/** Build the static skeleton once; everything below only fills regions. */
function createShell() {
  const brandName = el("span");
  const brand = el("div", { class: "app-brand" }, [
    el("img", { src: logoUrl, alt: "", width: "24", height: "24" }),
    brandName,
  ]);
  const pillRoot = el("span", { class: "row" });
  const langLabel = el("span", { class: "sr-only" });
  const langSelect = el("select", { id: "locale-select" });
  const footerVersion = el("span", { class: "faint" });
  const navRoot = el("nav", { class: "sidebar-nav stack" });
  const bannerRoot = el("div", { class: "stack" });
  const panelRoot = el("div");

  const node = el("div", { class: "app-shell" }, [
    el("header", { class: "app-header" }, [
      brand,
      pillRoot,
      el("span", { class: "spacer" }),
      el("div", { class: "lang-select" }, [langLabel, langSelect]),
    ]),
    el("div", { class: "app-body" }, [
      el("aside", { class: "sidebar" }, [
        navRoot,
        el("div", { class: "sidebar-foot" }, [el("span", { text: "MelonARC" }), footerVersion]),
      ]),
      el("main", { class: "main" }, [bannerRoot, panelRoot]),
    ]),
  ]);

  langSelect.setAttribute("aria-label", "Language");

  return { node, brandName, pillRoot, langLabel, langSelect, footerVersion, navRoot, bannerRoot, panelRoot };
}

/** The Tauri entry point, if this page is running inside the shell. */
function resolveInvoke() {
  const fromGlobal = window.__TAURI__?.core?.invoke;
  if (typeof fromGlobal === "function") return fromGlobal;
  const fromInternals = window.__TAURI_INTERNALS__?.invoke;
  if (typeof fromInternals === "function") return fromInternals;
  return null;
}

function readStoredLocale() {
  try {
    return localStorage.getItem(LOCALE_STORAGE_KEY);
  } catch {
    return null;
  }
}

function storeLocale(id) {
  try {
    localStorage.setItem(LOCALE_STORAGE_KEY, id);
  } catch {
    // Storage can be unavailable; the choice then lasts for this window only.
  }
}
