/**
 * Rules: the compiled rule table, the declared external rule sets, and a hit
 * test over the core's existing explanation endpoint.
 *
 * Everything here is read-only. The rule list comes from /v1/rules, the rule
 * set declarations from the already used /v1/config, and a test asks
 * /v1/rules/explain to classify one name or address. The panel only renders the
 * fields the core returns; a field the core does not expose (an entry count or
 * a refresh time for a rule set, for instance) is not invented here.
 *
 * The hit-test controls are built once and kept across polls: a full re-render
 * on every tick would steal the focus while someone is typing.
 */

import { card, empty, keyValues, pageHead, pill, table } from "../components/common.js";
import { clear, el } from "../lib/dom.js";
import { formatNumber } from "../lib/format.js";
import { createPoll } from "../lib/poll.js";

const RULE_LIMIT = 500;

export default {
  id: "rules",
  icon: "rules",
  titleKey: "nav.rules",
  order: 40,

  mount(ctx) {
    const rulesSlot = el("div");
    const setsSlot = el("div");
    const resultSlot = el("div");

    let rules = null;
    let config = null;
    let result = null;
    let disposed = false;
    let busy = false;
    const query = { name: "", network: "" };

    const input = el("input", {
      class: "field-input",
      type: "text",
      placeholder: ctx.t("rules.test.placeholder"),
      "aria-label": ctx.t("rules.test.label"),
      autocomplete: "off",
      spellcheck: "false",
      onInput: (event) => {
        query.name = String(event?.target?.value ?? "");
      },
      onKeydown: (event) => {
        if (event?.key === "Enter") {
          event?.preventDefault?.();
          void runTest();
        }
      },
    });

    const network = el(
      "select",
      {
        class: "field-select",
        "aria-label": ctx.t("rules.test.network.label"),
        onChange: (event) => {
          query.network = String(event?.target?.value ?? "");
        },
      },
      [
        el("option", { value: "", text: ctx.t("rules.test.network.any") }),
        el("option", { value: "tcp", text: ctx.t("rules.test.network.tcp") }),
        el("option", { value: "udp", text: ctx.t("rules.test.network.udp") }),
      ],
    );

    const runButton = el("button", {
      class: "btn",
      type: "button",
      dataset: { variant: "primary" },
      text: ctx.t("rules.test.run"),
      onClick: () => void runTest(),
    });

    function renderRules() {
      clear(rulesSlot);
      if (!rules) {
        rulesSlot.append(empty(ctx.t("common.error")));
        return;
      }
      const list = Array.isArray(rules.rules) ? rules.rules : [];
      rulesSlot.append(
        table({
          className: "rules",
          columns: [
            { label: ctx.t("rules.column.index") },
            { label: ctx.t("rules.column.type") },
            { label: ctx.t("rules.column.payload") },
            { label: ctx.t("rules.column.target") },
            { label: ctx.t("rules.column.source") },
            { label: ctx.t("rules.column.line") },
            { label: ctx.t("rules.column.no_resolve") },
          ],
          rows: list.map((rule) => [
            el("span", { class: "mono", text: formatNumber(rule.index, ctx.locale) }),
            el("span", { class: "mono", text: rule.type || ctx.t("common.na") }),
            el("span", { class: "wrap", text: rule.payload || ctx.t("common.na") }),
            el("span", { class: "mono", text: rule.target || ctx.t("common.na") }),
            el("span", { class: "mono", text: rule.source || ctx.t("common.na") }),
            el("span", { class: "mono", text: rule.line ? formatNumber(rule.line, ctx.locale) : ctx.t("common.na") }),
            el("span", { text: rule.no_resolve ? ctx.t("common.yes") : ctx.t("common.no") }),
          ]),
          emptyText: ctx.t("rules.empty"),
        }),
      );
      rulesSlot.append(
        el("p", {
          class: "faint",
          text: ctx.t("rules.count", { shown: list.length, total: formatNumber(rules.total ?? list.length, ctx.locale) }),
        }),
      );
    }

    function renderSets() {
      clear(setsSlot);
      if (!config) {
        setsSlot.append(empty(ctx.t("common.error")));
        return;
      }
      const sets = Array.isArray(config.rule_sets) ? config.rule_sets : [];
      setsSlot.append(
        table({
          className: "rule-sets",
          columns: [{ label: ctx.t("rules.sets.name") }, { label: ctx.t("rules.sets.path") }],
          rows: sets.map((set) => [
            el("span", { class: "mono", text: set.name || ctx.t("common.na") }),
            el("span", { class: "mono wrap", text: set.path || ctx.t("common.na") }),
          ]),
          emptyText: ctx.t("rules.sets.empty"),
        }),
      );
      setsSlot.append(el("p", { class: "faint", text: ctx.t("rules.sets.note") }));
    }

    function renderResult() {
      clear(resultSlot);
      if (!result) {
        resultSlot.append(empty(ctx.t("rules.test.idle")));
        return;
      }
      if (result.loading) {
        resultSlot.append(empty(ctx.t("common.loading")));
        return;
      }
      if (result.error) {
        resultSlot.append(
          el("div", { class: "row" }, [pill({ text: result.error, tone: "bad", withDot: false })]),
        );
        return;
      }

      const view = result.view ?? {};
      const head = el("div", { class: "row" }, [
        pill({
          text: ctx.t(view.matched ? "rules.test.matched" : "rules.test.unmatched"),
          tone: view.matched ? "ok" : "muted",
        }),
        view.target ? el("span", { class: "mono", text: `${ctx.t("rules.column.target")}: ${view.target}` }) : null,
      ]);
      resultSlot.append(head);

      const rule = view.rule;
      resultSlot.append(
        rule
          ? keyValues([
              { key: ctx.t("rules.column.index"), value: formatNumber(rule.index, ctx.locale) },
              { key: ctx.t("rules.column.type"), value: rule.type || ctx.t("common.na") },
              { key: ctx.t("rules.column.payload"), value: rule.payload || ctx.t("common.na") },
              { key: ctx.t("rules.column.target"), value: rule.target || ctx.t("common.na") },
              { key: ctx.t("rules.column.source"), value: rule.source || ctx.t("common.na") },
              { key: ctx.t("rules.column.line"), value: rule.line ? formatNumber(rule.line, ctx.locale) : ctx.t("common.na") },
            ])
          : empty(ctx.t("rules.test.no_rule")),
      );

      const resolution = view.resolution;
      if (resolution) {
        const rows = [];
        if (resolution.source) rows.push({ key: ctx.t("rules.resolution.source"), value: resolution.source });
        if (Array.isArray(resolution.addrs) && resolution.addrs.length) {
          rows.push({ key: ctx.t("rules.resolution.addrs"), value: resolution.addrs.join(", ") });
        }
        if (resolution.error) rows.push({ key: ctx.t("rules.resolution.error"), value: resolution.error });
        if (resolution.note) rows.push({ key: ctx.t("rules.resolution.note"), value: resolution.note });
        if (rows.length) {
          resultSlot.append(
            el("div", { class: "stack" }, [
              el("h3", { class: "subhead", text: ctx.t("rules.test.resolution") }),
              keyValues(rows),
            ]),
          );
        }
      }

      const steps = Array.isArray(view.steps) ? view.steps : [];
      resultSlot.append(
        el("h3", { class: "subhead", text: ctx.t("rules.test.steps") }),
        table({
          className: "steps",
          columns: [
            { label: ctx.t("rules.steps.index") },
            { label: ctx.t("rules.steps.type") },
            { label: ctx.t("rules.steps.rule") },
            { label: ctx.t("rules.steps.match") },
            { label: ctx.t("rules.steps.detail") },
          ],
          rows: steps.map((step) => [
            el("span", { class: "mono", text: formatNumber(step.index, ctx.locale) }),
            el("span", { class: "mono", text: step.type || ctx.t("common.na") }),
            el("span", { class: "wrap", text: step.rule || ctx.t("common.na") }),
            el("span", {
              class: step.match ? "match-yes" : "match-no",
              text: ctx.t(step.match ? "common.yes" : "common.no"),
            }),
            el("span", { class: "wrap", text: step.detail || ctx.t("common.na") }),
          ]),
          emptyText: ctx.t("common.empty"),
        }),
      );

      if (view.report) {
        resultSlot.append(
          el("h3", { class: "subhead", text: ctx.t("rules.test.report") }),
          el("pre", { class: "explain-report mono", text: view.report }),
        );
      }
    }

    async function runTest() {
      if (busy) return;
      const raw = String(query.name ?? "").trim();
      if (raw === "") {
        result = { error: ctx.t("rules.test.needed") };
        renderResult();
        return;
      }

      busy = true;
      result = { loading: true };
      renderResult();

      const params = isIP(raw) ? { addr: raw } : { name: raw };
      if (query.network) params.network = query.network;
      try {
        const view = await ctx.api.explain(params);
        ctx.core.noteSuccess();
        result = { view };
      } catch (error) {
        ctx.core.noteFailure(error);
        result = { error: ctx.t("rules.test.failed", { reason: ctx.t(`error.${error?.code}`) }) };
      }
      busy = false;
      if (!disposed) renderResult();
    }

    async function load() {
      const [ruleResult, configResult] = await Promise.all([
        ctx.api.rules(RULE_LIMIT).catch((error) => ({ error })),
        ctx.api.config().catch((error) => ({ error })),
      ]);
      for (const item of [ruleResult, configResult]) {
        if (item?.error) ctx.core.noteFailure(item.error);
      }
      if (!ruleResult?.error || !configResult?.error) ctx.core.noteSuccess();

      rules = ruleResult?.error ? null : ruleResult;
      config = configResult?.error ? null : configResult;
      if (disposed) return;
      renderRules();
      renderSets();
    }

    ctx.root.append(
      pageHead({ title: ctx.t("rules.title"), subtitle: ctx.t("rules.subtitle") }),
      card({
        title: ctx.t("rules.test.title"),
        children: el("div", { class: "stack" }, [
          el("div", { class: "test-row" }, [input, network, runButton]),
          el("p", { class: "faint", text: ctx.t("rules.test.hint") }),
          resultSlot,
        ]),
      }),
      card({ title: ctx.t("rules.list"), children: rulesSlot }),
      card({ title: ctx.t("rules.sets"), children: setsSlot }),
    );

    renderRules();
    renderSets();
    renderResult();
    const poll = createPoll(load, { every: 5000 });
    poll.start();

    return {
      dispose() {
        disposed = true;
        poll.stop();
      },
    };
  },
};

/**
 * Decide whether an input is an address, which the core wants as `addr`.
 * Names go as `name`; the core does its own validation of the address.
 *
 * @param {string} value
 * @returns {boolean}
 */
function isIP(value) {
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(value)) {
    return value.split(".").every((part) => Number(part) <= 255);
  }
  return value.includes(":") && (value.match(/:/g) ?? []).length >= 2 && /^[0-9a-fA-F:.]+$/.test(value);
}
