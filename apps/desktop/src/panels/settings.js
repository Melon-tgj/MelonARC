/**
 * Settings: the four overrides the shell reads from its own file, the language
 * switch and the about block.
 *
 * The overrides used to live in local storage, which only the window could see;
 * they now live in `<config-home>/melonarc/shell.json`, which the shell reads at
 * start-up and which is therefore the only copy that can change where the core
 * is found. The window edits that file through the transport (`shellSettings` /
 * `saveShellSettings`), so the same panel works in the native shell and in the
 * preview bridge.
 *
 * Two different restarts are named separately and never merged into one
 * sentence: data directory and API address are read once by the shell, and core
 * path and configuration are read on every spawn.
 *
 * The language switch is not part of the file: it belongs to this window and is
 * remembered in local storage, through the same entry point the header uses.
 */

import { card, keyValues, notice, pageHead, pill } from "../components/common.js";
import { LOCALES } from "../i18n/index.js";
import { clear, el } from "../lib/dom.js";
import { readShellDraft, setLocale, validateSettings } from "../lib/gui-settings.js";
import { APP_LICENSE, APP_VERSION } from "../version.js";

/** Resolved against this module, so the build can copy `src/` verbatim. */
const logoUrl = new URL("../assets/logo.png", import.meta.url).href;

/** The empty overrides, used by Reset and by a first run. */
const BLANK = Object.freeze({ dataDir: "", apiAddr: "", corePath: "", coreConfig: "" });

export default {
  id: "settings",
  icon: "settings",
  titleKey: "nav.settings",
  order: 60,

  mount(ctx) {
    const runtimeSlot = el("div", { class: "stack" });
    const shellSlot = el("div", { class: "stack" });
    const saveMessage = el("span");
    const coreMessage = el("span");

    let view = null;
    let draft = { ...BLANK };
    let disposed = false;

    const inputs = {
      dataDir: field("dataDir", "settings-data-dir", ctx.t("settings.field.datadir")),
      apiAddr: field("apiAddr", "settings-api-addr", ctx.t("settings.field.api")),
      corePath: field("corePath", "settings-core-path", ctx.t("settings.field.corepath")),
      coreConfig: field("coreConfig", "settings-core-config", ctx.t("settings.field.coreconfig")),
    };

    /**
     * One text field bound to one draft key.
     *
     * The key is bound here rather than looked up from the event target: the
     * field is the only thing that knows which override it edits, and a DOM
     * shim is free to hand the handler a plain `{value}` target.
     *
     * @param {"dataDir" | "apiAddr" | "corePath" | "coreConfig"} key
     * @param {string} id
     * @param {string} label
     */
    function field(key, id, label) {
      return el("input", {
        id,
        class: "field-input mono",
        type: "text",
        "aria-label": label,
        autocomplete: "off",
        spellcheck: "false",
        onInput: (event) => {
          draft[key] = String(event?.target?.value ?? "");
        },
      });
    }

    /** @param {"ok" | "warn" | "bad" | "muted"} tone @param {string} text @param {HTMLElement} slot */
    function showMessage(tone, text, slot) {
      clear(slot);
      slot.append(pill({ text, tone, withDot: false }));
    }

    function syncInputs() {
      for (const key of Object.keys(inputs)) inputs[key].value = draft[key] ?? "";
    }

    /** The settings path, the restart warning and the priority note. */
    function renderShellInfo() {
      clear(shellSlot);
      if (!view) {
        shellSlot.append(
          notice({
            tone: "warn",
            title: ctx.t("settings.unavailable.title"),
            body: ctx.t("settings.unavailable.body"),
          }),
        );
        return;
      }

      shellSlot.append(
        el("p", { class: "faint" }, [
          el("span", { text: `${ctx.t("settings.settingsfile")}: ` }),
          el("span", { class: "mono", text: view.settingsPath || ctx.t("common.na") }),
        ]),
      );

      if (view.restartRequired) {
        shellSlot.append(
          notice({ tone: "warn", title: ctx.t("settings.restart_required"), body: ctx.t("settings.restart_required.body") }),
        );
      }

      shellSlot.append(
        el("p", { class: "faint", text: ctx.t("settings.priority") }),
      );
    }

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

    async function loadShell() {
      const answer = await ctx.api.shellSettings();
      if (disposed) return;
      view = answer;
      draft = readShellDraft(answer, { blank: BLANK });
      syncInputs();
      renderShellInfo();
    }

    async function save() {
      const checked = validateSettings(draft);
      if (checked.errorKey) {
        showMessage("bad", ctx.t(checked.errorKey), saveMessage);
        return;
      }
      draft = checked.values;

      const saved = await ctx.api.saveShellSettings(draft);
      if (!saved) {
        // Nothing is claimed that did not happen: the file is untouched, or the
        // shell refused a value the window's own check let through.
        showMessage("bad", ctx.t("settings.error.write"), saveMessage);
        return;
      }
      view = saved;
      draft = readShellDraft(saved, { blank: BLANK });
      syncInputs();
      renderShellInfo();
      showMessage("ok", ctx.t("settings.saved"), saveMessage);
    }

    async function reset() {
      const saved = await ctx.api.saveShellSettings({ ...BLANK });
      if (!saved) {
        showMessage("bad", ctx.t("settings.error.write"), saveMessage);
        return;
      }
      view = saved;
      draft = { ...BLANK };
      syncInputs();
      renderShellInfo();
      showMessage("muted", ctx.t("settings.reset.done"), saveMessage);
    }

    async function restartCore() {
      const answer = await ctx.api.coreRestart();
      if (!answer) {
        showMessage("bad", ctx.t("settings.core.restart.failed"), coreMessage);
        return;
      }
      showMessage("ok", ctx.t("settings.core.restarted", { state: ctx.t(stateKey(answer.state)) }), coreMessage);
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

    /**
     * @param {{ id: string, label: string, hint: string, input: HTMLElement }} spec
     */
    function labelledField(spec) {
      return el("div", { class: "field" }, [
        el("label", { class: "field-label", for: spec.id }, [el("span", { text: spec.label })]),
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
            labelledField({
              id: "settings-data-dir",
              label: ctx.t("settings.field.datadir"),
              hint: ctx.t("settings.field.datadir.hint"),
              input: inputs.dataDir,
            }),
            labelledField({
              id: "settings-api-addr",
              label: ctx.t("settings.field.api"),
              hint: ctx.t("settings.field.api.hint"),
              input: inputs.apiAddr,
            }),
            labelledField({
              id: "settings-core-path",
              label: ctx.t("settings.field.corepath"),
              hint: ctx.t("settings.field.corepath.hint"),
              input: inputs.corePath,
            }),
            labelledField({
              id: "settings-core-config",
              label: ctx.t("settings.field.coreconfig"),
              hint: ctx.t("settings.field.coreconfig.hint"),
              input: inputs.coreConfig,
            }),
          ]),
          el("div", { class: "row" }, [
            el("button", {
              class: "btn",
              type: "button",
              dataset: { variant: "primary" },
              text: ctx.t("settings.save"),
              onClick: () => void save(),
            }),
            el("button", { class: "btn", type: "button", text: ctx.t("settings.reset"), onClick: () => void reset() }),
            saveMessage,
          ]),
          shellSlot,
          el("div", { class: "row" }, [
            el("button", {
              class: "btn",
              type: "button",
              text: ctx.t("settings.core.restart"),
              onClick: () => void restartCore(),
            }),
            el("span", { class: "faint", text: ctx.t("settings.core.restart.hint") }),
            coreMessage,
          ]),
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

    renderShellInfo();
    void loadRuntime();
    void loadShell();

    return {
      dispose() {
        disposed = true;
      },
    };
  },
};

/**
 * The wire state as an i18n key. An unknown state falls back to the raw word.
 *
 * @param {string} state
 */
function stateKey(state) {
  return ["starting", "running", "stopped", "crashed"].includes(state)
    ? `core.state.${state}`
    : "common.na";
}

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
