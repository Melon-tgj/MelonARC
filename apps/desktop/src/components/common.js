/**
 * Shared presentational components.
 *
 * Each one takes already translated text and returns a node. They exist so a
 * panel describes *what* it wants to show; the class names they set are styled
 * from tokens.css and base.css only.
 */

import { el } from "../lib/dom.js";

/**
 * @param {{ title?: string, children?: unknown, className?: string }} options
 */
export function card({ title, children, className = "" } = {}) {
  return el("section", { class: `card ${className}`.trim() }, [
    title ? el("h2", { class: "card-title", text: title }) : null,
    children,
  ]);
}

/**
 * @param {{ value: string, unit?: string, label: string }} options
 */
export function stat({ value, unit, label }) {
  return el("div", { class: "card" }, [
    el("div", { class: "stat-value", text: value }, unit ? [el("span", { class: "unit", text: unit })] : []),
    el("div", { class: "stat-label", text: label }),
  ]);
}

/**
 * A state chip. `tone` is one of `ok`, `warn`, `bad`, `muted`.
 *
 * @param {{ text: string, tone?: string, withDot?: boolean }} options
 */
export function pill({ text, tone = "muted", withDot = true }) {
  return el("span", { class: "pill", dataset: { tone } }, [
    withDot ? el("span", { class: "dot" }) : null,
    el("span", { text }),
  ]);
}

/**
 * @param {{ title: string, subtitle?: string, actions?: unknown }} options
 */
export function pageHead({ title, subtitle, actions }) {
  return el("div", { class: "page-head" }, [
    el("h1", { text: title }),
    subtitle ? el("p", { text: subtitle }) : null,
    actions ? el("div", { class: "actions" }, actions) : null,
  ]);
}

/**
 * Key/value rows.
 *
 * @param {Array<{ key: string, value: string }>} rows
 */
export function keyValues(rows) {
  return el(
    "div",
    {},
    rows.map((row) =>
      el("div", { class: "kv" }, [
        el("span", { class: "k", text: row.key }),
        el("span", { class: "v", text: row.value }),
      ]),
    ),
  );
}

/**
 * A table with a fixed head and a body. Columns are labels; the column widths
 * come from the class the caller passes (see panels.css).
 *
 * @param {{
 *   className?: string,
 *   columns: Array<{ label: string, align?: "right" }>,
 *   rows: Array<Array<Node | string>>,
 *   emptyText: string,
 * }} options
 */
export function table({ className = "", columns, rows, emptyText }) {
  if (rows.length === 0) return empty(emptyText);

  return el("div", { class: `table ${className}`.trim() }, [
    el(
      "div",
      { class: "table-row table-head" },
      columns.map((column) => el("span", { class: column.align === "right" ? "num" : "", text: column.label })),
    ),
    el(
      "div",
      { class: "table-body" },
      rows.map((cells) =>
        el(
          "div",
          { class: "table-row" },
          cells.map((cell, index) =>
            el("span", { class: columns[index]?.align === "right" ? "num" : "" }, cell),
          ),
        ),
      ),
    ),
  ]);
}

/**
 * @param {string} text
 */
export function empty(text) {
  return el("div", { class: "empty", text });
}

/**
 * A block that says something important about the whole window.
 *
 * `hints` are plain lines; `mono` marks the ones that are a path or a command,
 * which is why they are not formatted as prose in the catalogue.
 *
 * @param {{ tone: "info" | "ok" | "warn" | "bad", title: string, body?: string,
 *   hints?: Array<{ text: string, mono?: boolean }>, detail?: string, detailLabel?: string,
 *   actions?: unknown }} options
 */
export function notice({ tone = "info", title, body, hints = [], detail = "", detailLabel = "", actions }) {
  return el("div", { class: "notice", dataset: { tone }, role: tone === "bad" ? "alert" : "status" }, [
    el("div", { class: "notice-title", text: title }),
    body ? el("p", { class: "muted", text: body }) : null,
    hints.length
      ? el(
          "ul",
          { class: "notice-hint" },
          hints.map((hint) => el("li", {}, [hint.mono ? el("code", { text: hint.text }) : hint.text])),
        )
      : null,
    detail
      ? el("p", { class: "faint" }, [el("span", { text: `${detailLabel}: ` }), el("span", { class: "mono", text: detail })])
      : null,
    actions ? el("div", { class: "row" }, actions) : null,
  ]);
}
