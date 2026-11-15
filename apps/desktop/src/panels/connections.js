/**
 * Connections: the inbound counters and the records of what was not carried.
 *
 * Both payloads are read-only and already reduced by the core: counters per
 * listener from /v1/inbound, and the failure ring from /v1/failures. The panel
 * adds no interpretation beyond turning a stage and a category into a label —
 * the categories are a closed set, and an unknown one is printed as it came.
 */

import { card, empty, pageHead, stat, table } from "../components/common.js";
import { clear, el } from "../lib/dom.js";
import { formatNumber, formatTime } from "../lib/format.js";
import { createPoll } from "../lib/poll.js";

const FAILURE_LIMIT = 20;

export default {
  id: "connections",
  icon: "connections",
  titleKey: "nav.connections",
  order: 30,

  mount(ctx) {
    const body = el("div");
    ctx.root.append(body);
    let inbound = null;
    let failures = null;
    let disposed = false;

    function render() {
      clear(body);
      body.append(pageHead({ title: ctx.t("connections.title"), subtitle: ctx.t("connections.subtitle") }));

      if (!inbound) {
        body.append(empty(ctx.t("common.error")));
        return;
      }

      const totals = el("div", { class: "card-grid stats" }, [
        stat({ value: formatNumber(inbound.open, ctx.locale), label: ctx.t("connections.totals.open") }),
        stat({ value: formatNumber(inbound.accepted, ctx.locale), label: ctx.t("connections.totals.accepted") }),
        stat({ value: formatNumber(inbound.failures, ctx.locale), label: ctx.t("connections.totals.failures") }),
        stat({ value: formatNumber(inbound.rejected, ctx.locale), label: ctx.t("connections.totals.rejected") }),
        // A core older than this field sends no such key; the `?? 0` is what
        // makes that read as zero instead of an unformattable value. Zero is
        // also the truth for a daemon whose pool never ran out, so the two
        // cases deliberately look the same.
        stat({
          value: formatNumber(inbound.fake_ip_pool_exhausted_queries_total ?? 0, ctx.locale),
          label: ctx.t("connections.totals.fake_ip_exhausted"),
        }),
      ]);

      const listeners = card({
        title: ctx.t("connections.listeners"),
        children: table({
          className: "listeners",
          columns: [
            { label: ctx.t("connections.table.protocol") },
            { label: ctx.t("connections.table.open"), align: "right" },
            { label: ctx.t("connections.table.accepted"), align: "right" },
            { label: ctx.t("connections.table.datagrams"), align: "right" },
          ],
          rows: (inbound.inbounds ?? []).map((item) => [
            el("span", { class: "mono", text: item.protocol }),
            formatNumber(item.open, ctx.locale),
            formatNumber(item.accepted, ctx.locale),
            formatNumber(item.datagram_associations, ctx.locale),
          ]),
          emptyText: ctx.t("common.empty"),
        }),
      });

      const records = failures
        ? table({
            className: "failures",
            columns: [
              { label: ctx.t("connections.table.time") },
              { label: ctx.t("connections.table.target") },
              { label: ctx.t("connections.table.network") },
              { label: ctx.t("connections.table.stage") },
              { label: ctx.t("connections.table.category") },
              { label: ctx.t("connections.table.policy") },
            ],
            rows: (failures.failures ?? []).map((item) => [
              el("span", { class: "time", text: formatTime(item.time, ctx.locale) }),
              el("span", { class: "target", text: item.target }),
              el("span", { class: "mono", text: item.network || "—" }),
              el("span", { text: stageLabel(ctx.t, item.stage) }),
              el("span", { text: categoryLabel(ctx.t, item.category) }),
              el("span", { class: "mono", text: item.policy || "—" }),
            ]),
            emptyText: ctx.t("connections.failures.empty"),
          })
        : empty(ctx.t("common.error"));

      const failureCard = card({
        title: failures
          ? `${ctx.t("connections.failures")} · ${ctx.t("connections.failures.capacity", {
              count: failures.count ?? 0,
              capacity: failures.capacity ?? 0,
            })}`
          : ctx.t("connections.failures"),
        children: records,
      });

      body.append(totals, listeners, failureCard);
    }

    async function load() {
      const [inboundResult, failuresResult] = await Promise.all([
        ctx.api.inbound().catch((error) => ({ error })),
        ctx.api.failures(FAILURE_LIMIT).catch((error) => ({ error })),
      ]);

      if (inboundResult?.error) ctx.core.noteFailure(inboundResult.error);
      if (failuresResult?.error) ctx.core.noteFailure(failuresResult.error);
      if (!inboundResult?.error || !failuresResult?.error) ctx.core.noteSuccess();

      inbound = inboundResult?.error ? null : inboundResult;
      failures = failuresResult?.error ? null : failuresResult;
      if (!disposed) render();
    }

    render();
    const poll = createPoll(load, { every: 4000 });
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
 * @param {Function} t
 * @param {string} stage
 */
function stageLabel(t, stage) {
  const key = `connections.stage.${stage}`;
  const label = t(key);
  return label === key ? stage || "—" : label;
}

/**
 * @param {Function} t
 * @param {string} category
 */
function categoryLabel(t, category) {
  const key = `connections.category.${category}`;
  const label = t(key);
  return label === key ? category || "—" : label;
}
