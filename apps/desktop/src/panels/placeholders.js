/**
 * The three panels this step reserves but does not implement.
 *
 * They are real registry entries with a real mount, so the navigation already
 * behaves as it will when the features land: the shape of the screen is the
 * deliverable here, and the wording says so instead of showing an empty box.
 */

import { card, pageHead, pill } from "../components/common.js";
import { el } from "../lib/dom.js";
import { APP_LICENSE, APP_VERSION } from "../version.js";

/** Resolved against this module, so the build can copy `src/` verbatim. */
const logoUrl = new URL("../assets/logo.png", import.meta.url).href;

/**
 * @param {{
 *   id: string, icon: string, titleKey: string, order: number,
 *   bodyKey: string, itemKeys: string[], about?: boolean,
 * }} spec
 */
function placeholderPanel(spec) {
  return {
    id: spec.id,
    icon: spec.icon,
    titleKey: spec.titleKey,
    order: spec.order,

    mount(ctx) {
      const { t } = ctx;
      const sections = [
        pageHead({ title: t(spec.titleKey), subtitle: t(spec.bodyKey) }),
        card({
          title: t("placeholder.badge"),
          children: el("div", { class: "placeholder" }, [
            el("div", { class: "placeholder-mark" }, [
              pill({ text: t("placeholder.badge"), tone: "warn", withDot: false }),
            ]),
            el("p", { class: "muted", text: t(spec.bodyKey) }),
            el(
              "ul",
              { class: "placeholder-list" },
              spec.itemKeys.map((key) => el("li", { text: t(key) })),
            ),
          ]),
        }),
      ];

      if (spec.about) sections.push(aboutBlock(t));

      ctx.root.append(...sections);
      return { dispose() {} };
    },
  };
}

/**
 * The about block doubles as the placeholder slot for the chosen mark: the
 * icon is a raster stand-in until the vector version exists.
 *
 * @param {Function} t
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
          ]),
        ]),
      ]),
      el("p", { class: "faint", text: t("settings.about.body") }),
    ]),
  });
}

export const rulesPanel = placeholderPanel({
  id: "rules",
  icon: "rules",
  titleKey: "nav.rules",
  order: 40,
  bodyKey: "placeholder.rules.body",
  itemKeys: ["placeholder.rules.item1", "placeholder.rules.item2", "placeholder.rules.item3"],
});

export const logsPanel = placeholderPanel({
  id: "logs",
  icon: "logs",
  titleKey: "nav.logs",
  order: 50,
  bodyKey: "placeholder.logs.body",
  itemKeys: ["placeholder.logs.item1", "placeholder.logs.item2", "placeholder.logs.item3"],
});

export const settingsPanel = placeholderPanel({
  id: "settings",
  icon: "settings",
  titleKey: "nav.settings",
  order: 60,
  bodyKey: "placeholder.settings.body",
  itemKeys: ["placeholder.settings.item1", "placeholder.settings.item2", "placeholder.settings.item3"],
  about: true,
});
