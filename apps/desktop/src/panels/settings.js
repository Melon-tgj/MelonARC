/**
 * Settings: the window's own overrides, the language switch and the about block.
 *
 * The two overrides are the environment variables the native shell reads when
 * it starts. The window cannot change the environment of the process it runs
 * in, so it keeps its own copy in local storage, shows what is in effect right
 * now, and prints the exact assignments a launcher needs on the next start.
 * Nothing here edits the core's configuration: that file belongs to the core,
 * and changing its data directory or listener needs a core restart.
 *
 * The language switch is connected to the entry point the shell already owns:
 * it writes the same storage key as the header selector and asks that control
 * to change, so the whole window relabels immediately with no shell edit.
 */

import { card, keyValues, notice, pageHead, pill } from "../components/common.js";
import { LOCALES } from "../i18n/index.js";
import { clear, el } from "../lib/dom.js";
import {
  DEFAULT_API_ADDR,
  ENV_API_ADDR,
  ENV_DATA_DIR,
  clearSettings,
  envLines,
  readSettings,
  saveSettings,
  setLocale,
  validateSettings,
} from "../lib/gui-settings.js";
import { APP_LICENSE, APP_VERSION } from "../version.js";

/** Resolved against this module, so the build can copy `src/` verbatim. */
const logoUrl = new URL("../assets/logo.png", import.meta.url).href;

export default {
  id: "settings",
  icon: "settings",
  titleKey: "nav.settings",
  order: 60,

  mount(ctx) {
    const runtimeSlot = el("div", { class: "stack" });
    const messageSlot = el("span");
    const envSlot = el("div", { class: "env-box" });

    const stored = readSettings();
    let draft = {
      dataDir: stored.dataDir,
      apiAddr: stored.apiAddr || DEFAULT_API_ADDR,
    };
    let disposed = false;

    const dataInput = el("input", {
      id: "settings-data-dir",
      class: "field-input mono",
      type: "text",
      "aria-label": ctx.t("settings.field.datadir"),
      autocomplete: "off",
      spellcheck: "false",
      onInput: (event) => {
        draft.dataDir = String(event?.target?.value ?? "");
      },
    });
    const apiInput = el("input", {
      id: "settings-api-addr",
      class: "field-input mono",
      type: "text",
      "aria-label": ctx.t("settings.field.api"),
      autocomplete: "off",
      spellcheck: "false",
      onInput: (event) => {
        draft.apiAddr = String(event?.target?.value ?? "");
      },
    });
    dataInput.value = draft.dataDir;
    apiInput.value = draft.apiAddr;

    /** @param {"ok" | "warn" | "bad" | "muted"} tone @param {string} text */
    function showMessage(tone, text) {
      clear(messageSlot);
      messageSlot.append(pill({ text, tone, withDot: false }));
    }

    function renderEnv() {
      clear(envSlot);
      for (const line of envLines(draft)) {
        envSlot.append(el("code", { class: "env-line mono", text: line }));
      }
    }

    function syncInputs() {
      dataInput.value = draft.dataDir;
      apiInput.value = draft.apiAddr;
      renderEnv();
    }

    function save() {
      const checked = validateSettings(draft);
      if (checked.errorKey) {
        showMessage("bad", ctx.t(checked.errorKey));
        return;
      }
      draft = checked.values;
      syncInputs();
      const persisted = saveSettings(draft);
      showMessage(
        persisted ? "ok" : "bad",
        ctx.t(persisted ? "settings.saved" : "settings.error.storage"),
      );
    }

    function reset() {
      const cleared = clearSettings();
      const fresh = readSettings();
      draft = { dataDir: fresh.dataDir, apiAddr: fresh.apiAddr || DEFAULT_API_ADDR };
      syncInputs();
      showMessage(
        cleared ? "muted" : "bad",
        ctx.t(cleared ? "settings.reset.done" : "settings.error.storage"),
      );
    }

    const langSelect = el(
      "select",
      {
        class: "field-select",
        "aria-label": ctx.t("settings.language.label"),
        onChange: (event) => {
          const next = String(event?.target?.value ?? "");
          if (next && next !== ctx.locale) setLocale(next);
        },
      },
      LOCALES.map((locale) =>
        el("option", {
          value: locale.id,
          text: ctx.t(`settings.lang.${locale.id}`),
          selected: locale.id === ctx.locale,
        }),
      ),
    );
    langSelect.value = ctx.locale;

    async function loadRuntime() {
      const info = await ctx.api.runtime();
      if (disposed) return;
      const effective = info ?? {};
      clear(runtimeSlot);
      runtimeSlot.append(
        keyValues([
          { key: ctx.t("settings.effective.datadir"), value: effective.dataDir || ctx.t("common.na") },
          { key: ctx.t("settings.effective.api"), value: effective.apiAddress || ctx.t("common.na") },
          { key: ctx.t("settings.effective.token"), value: effective.tokenPath || ctx.t("common.na") },
          { key: ctx.t("settings.effective.mode"), value: effective.mode || ctx.t("common.na") },
        ]),
      );
    }

    /**
     * @param {{ label: string, hint: string, env: string, input: HTMLElement, id: string }} spec
     */
    function field(spec) {
      return el("div", { class: "field" }, [
        el("label", { class: "field-label", for: spec.id }, [
          el("span", { text: spec.label }),
          el("code", { class: "mono", text: spec.env }),
        ]),
        spec.input,
        el("p", { class: "faint", text: spec.hint }),
      ]);
    }

    ctx.root.append(
      pageHead({ title: ctx.t("settings.title"), subtitle: ctx.t("settings.subtitle") }),
      card({ title: ctx.t("settings.effective"), children: runtimeSlot }),
      card({
        title: ctx.t("settings.overrides"),
        children: el("div", { class: "stack" }, [
          el("div", { class: "form-grid" }, [
            field({
              id: "settings-data-dir",
              label: ctx.t("settings.field.datadir"),
              hint: ctx.t("settings.field.datadir.hint"),
              env: ENV_DATA_DIR,
              input: dataInput,
            }),
            field({
              id: "settings-api-addr",
              label: ctx.t("settings.field.api"),
              hint: ctx.t("settings.field.api.hint"),
              env: ENV_API_ADDR,
              input: apiInput,
            }),
          ]),
          el("div", { class: "row" }, [
            el("button", {
              class: "btn",
              type: "button",
              dataset: { variant: "primary" },
              text: ctx.t("settings.save"),
              onClick: save,
            }),
            el("button", { class: "btn", type: "button", text: ctx.t("settings.reset"), onClick: reset }),
            messageSlot,
          ]),
          notice({
            tone: "info",
            title: ctx.t("settings.restart.title"),
            hints: [
              { text: ctx.t("settings.restart.gui") },
              { text: ctx.t("settings.restart.core") },
            ],
          }),
          el("p", { class: "faint", text: ctx.t("settings.env.note") }),
          envSlot,
        ]),
      }),
      card({
        title: ctx.t("settings.language"),
        children: el("div", { class: "stack" }, [
          langSelect,
          el("p", { class: "faint", text: ctx.t("settings.language.hint") }),
        ]),
      }),
      aboutBlock(ctx.t),
    );

    renderEnv();
    void loadRuntime();

    return {
      dispose() {
        disposed = true;
      },
    };
  },
};

/**
 * @param {(key: string) => string} t
 */
function aboutBlock(t) {
  return card({
    title: t("settings.about"),
    children: el("div", { class: "stack" }, [
      el("div", { class: "about" }, [
        el("img", { src: logoUrl, alt: "", width: "56", height: "56" }),
        el("div", {}, [
          el("div", { class: "name", text: t("app.name") }),
          el("div", { class: "lines" }, [
            el("div", { text: `${t("overview.version")} ${APP_VERSION}` }),
            el("div", { text: APP_LICENSE }),
            el("div", { text: t("settings.about.license") }),
          ]),
        ]),
      ]),
      el("p", { class: "faint", text: t("settings.about.body") }),
    ]),
  });
}
