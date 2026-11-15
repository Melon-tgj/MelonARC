/**
 * Logs: the audit trail and the connection failure record.
 *
 * Both payloads are snapshots kept by the core, oldest first. There is no
 * "level" or "source" field in either wire format, so the two filters work on
 * the fields that are there: audit entries carry `result` and `action`, failure
 * records carry `stage` and `category`. A failure record is by definition a
 * failed outcome, so it matches the "failed" level and no other. No field is
 * invented and no value is rewritten: an unrecognised value is printed as it
 * came, the same rule the connections panel uses.
 *
 * "Pause" holds the snapshot: while paused the panel neither fetches new
 * records nor follows the bottom of the scroll box.
 */

import { card, empty, pageHead, pill, table } from "../components/common.js";
import { clear, el } from "../lib/dom.js";
import { formatTime } from "../lib/format.js";
import { createPoll } from "../lib/poll.js";

const AUDIT_LIMIT = 64;
const FAILURE_LIMIT = 64;

/** Closed sets of field values the core actually emits. */
const LEVELS = Object.freeze(["", "ok", "failed"]);
const SOURCES = Object.freeze(["", "policy.select", "config.reload", "route", "dial"]);

export default {
  id: "logs",
  icon: "logs",
  titleKey: "nav.logs",
  order: 50,

  mount(ctx) {
    const auditSlot = el("div");
    const failureSlot = el("div");
    const statusSlot = el("span");
    const scroll = el("div", { class: "log-scroll" });

    let audit = null;
    let failures = null;
    let level = "";
    let source = "";
    let paused = false;
    let disposed = false;
    let poll = null;

    const levelSelect = el(
      "select",
      {
        class: "field-select",
        "aria-label": ctx.t("logs.filter.level.label"),
        onChange: (event) => {
          level = String(event?.target?.value ?? "");
          renderTables();
        },
      },
      LEVELS.map((value) =>
        el("option", {
          value,
          text: ctx.t(value === "" ? "logs.filter.level.all" : `logs.filter.level.${value}`),
        }),
      ),
    );

    const sourceSelect = el(
      "select",
      {
        class: "field-select",
        "aria-label": ctx.t("logs.filter.source.label"),
        onChange: (event) => {
          source = String(event?.target?.value ?? "");
          renderTables();
        },
      },
      SOURCES.map((value) =>
        el("option", {
          value,
          text: ctx.t(value === "" ? "logs.filter.source.all" : `logs.source.${value}`),
        }),
      ),
    );

    const pauseButton = el("button", {
      class: "btn",
      type: "button",
      text: ctx.t("logs.pause"),
      onClick: () => {
        paused = !paused;
        pauseButton.textContent = ctx.t(paused ? "logs.resume" : "logs.pause");
        renderStatus();
        if (!paused) poll?.refresh();
      },
    });

    function renderStatus() {
      clear(statusSlot);
      statusSlot.append(
        pill({
          text: ctx.t(paused ? "logs.paused" : "logs.live"),
          tone: paused ? "warn" : "ok",
        }),
      );
    }

    /** @param {any} record @param {"audit" | "failure"} kind */
    function levelOf(record, kind) {
      return kind === "audit" ? record.result : "failed";
    }

    /** @param {any} record @param {"audit" | "failure"} kind */
    function sourceOf(record, kind) {
      return kind === "audit" ? record.action : record.stage;
    }

    /** @param {any} record @param {"audit" | "failure"} kind */
    function matches(record, kind) {
      if (level && levelOf(record, kind) !== level) return false;
      if (source && sourceOf(record, kind) !== source) return false;
      return true;
    }

    /** @param {string} prefix @param {string} value @returns {string} */
    function label(prefix, value) {
      if (value === undefined || value === null || value === "") return ctx.t("common.na");
      const key = `${prefix}${value}`;
      const text = ctx.t(key);
      return text === key ? String(value) : text;
    }

    /** @param {number} total @param {number} shown */
    function countLine(total, shown) {
      return el("p", {
        class: "faint",
        text: ctx.t("logs.records", { shown, total }),
      });
    }

    function renderTables() {
      clear(auditSlot);
      clear(failureSlot);

      const auditAll = Array.isArray(audit?.entries) ? audit.entries : [];
      const failureAll = Array.isArray(failures?.failures) ? failures.failures : [];
      const auditRows = auditAll.filter((entry) => matches(entry, "audit"));
      const failureRows = failureAll.filter((entry) => matches(entry, "failure"));

      auditSlot.append(
        audit
          ? table({
              className: "audit",
              columns: [
                { label: ctx.t("logs.column.time") },
                { label: ctx.t("logs.column.action") },
                { label: ctx.t("logs.column.result") },
                { label: ctx.t("logs.column.detail") },
                { label: ctx.t("logs.column.remote") },
              ],
              rows: auditRows.map((entry) => [
                el("span", { class: "time", text: formatTime(entry.time, ctx.locale) }),
                el("span", { class: "mono", text: label("logs.action.", entry.action) }),
                el("span", { class: "mono", text: label("logs.result.", entry.result) }),
                el("span", { class: "wrap", text: entry.detail || ctx.t("common.na") }),
                el("span", { class: "mono", text: entry.remote || ctx.t("common.na") }),
              ]),
              emptyText: ctx.t("logs.audit.empty"),
            })
          : empty(ctx.t("common.error")),
        countLine(auditAll.length, auditRows.length),
      );

      failureSlot.append(
        failures
          ? table({
              className: "log-failures",
              columns: [
                { label: ctx.t("logs.column.time") },
                { label: ctx.t("logs.column.target") },
                { label: ctx.t("logs.column.network") },
                { label: ctx.t("logs.column.stage") },
                { label: ctx.t("logs.column.category") },
                { label: ctx.t("logs.column.policy") },
              ],
              rows: failureRows.map((entry) => [
                el("span", { class: "time", text: formatTime(entry.time, ctx.locale) }),
                el("span", { class: "target", text: entry.target || ctx.t("common.na") }),
                el("span", { class: "mono", text: entry.network || ctx.t("common.na") }),
                el("span", { text: label("logs.source.", entry.stage) }),
                el("span", { text: label("connections.category.", entry.category) }),
                el("span", { class: "mono", text: entry.policy || ctx.t("common.na") }),
              ]),
              emptyText: ctx.t("logs.failures.empty"),
            })
          : empty(ctx.t("common.error")),
        countLine(failureAll.length, failureRows.length),
      );
    }

    function follow() {
      if (paused || typeof scroll.scrollTop !== "number") return;
      scroll.scrollTop = scroll.scrollHeight;
    }

    async function load() {
      if (paused) return;
      const [auditResult, failureResult] = await Promise.all([
        ctx.api.audit(AUDIT_LIMIT).catch((error) => ({ error })),
        ctx.api.failures(FAILURE_LIMIT).catch((error) => ({ error })),
      ]);
      for (const item of [auditResult, failureResult]) {
        if (item?.error) ctx.core.noteFailure(item.error);
      }
      if (!auditResult?.error || !failureResult?.error) ctx.core.noteSuccess();

      audit = auditResult?.error ? null : auditResult;
      failures = failureResult?.error ? null : failureResult;
      if (disposed) return;
      renderTables();
      follow();
    }

    scroll.append(
      el("h3", { class: "subhead", text: ctx.t("logs.audit") }),
      auditSlot,
      el("h3", { class: "subhead", text: ctx.t("logs.failures") }),
      failureSlot,
    );

    ctx.root.append(
      pageHead({
        title: ctx.t("logs.title"),
        subtitle: ctx.t("logs.subtitle"),
        actions: [pauseButton],
      }),
      card({
        title: ctx.t("logs.filters"),
        children: el("div", { class: "log-toolbar" }, [
          el("label", { class: "field-label", text: ctx.t("logs.filter.level.label") }),
          levelSelect,
          el("label", { class: "field-label", text: ctx.t("logs.filter.source.label") }),
          sourceSelect,
          statusSlot,
        ]),
      }),
      card({ title: ctx.t("logs.stream"), children: scroll }),
      el("p", { class: "faint", text: ctx.t("logs.pause.note") }),
    );

    renderStatus();
    renderTables();
    poll = createPoll(load, { every: 4000 });
    poll.start();

    return {
      dispose() {
        disposed = true;
        poll?.stop();
      },
    };
  },
};
