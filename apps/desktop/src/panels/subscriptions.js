/**
 * Subscriptions: what each provider supplied, and which entries were refused.
 *
 * Two endpoints, read in two steps. The list is a summary — node count, skipped
 * count, when the last refresh finished — and it is polled while the panel is
 * open. The skipped entries are fetched only when someone asks for them: they
 * describe one body, can run to thousands of lines, and nobody reading the
 * summary needs them. Opening a page is therefore a click, not a preload, and
 * closing it drops what was fetched.
 *
 * The core keeps the detail of the last refresh that completed. A refresh that
 * failed kept the nodes it had, so it kept the detail that describes them, which
 * is what the note under the title says.
 */

import { card, empty, pageHead, table } from "../components/common.js";
import { clear, el } from "../lib/dom.js";
import { formatDateTime, formatNumber } from "../lib/format.js";
import { createPoll } from "../lib/poll.js";

/** Entries per page. Small enough to read, large enough to be a page. */
const PAGE_SIZE = 20;

export default {
  id: "subscriptions",
  icon: "subscriptions",
  titleKey: "nav.subscriptions",
  order: 25,

  mount(ctx) {
    const body = el("div");
    ctx.root.append(body);

    let subscriptions = [];
    /** @type {null | { name: string, offset: number, loading: boolean, error: any, page: any }} */
    let detail = null;
    // Every open is stamped, so an answer that arrives after the user closed
    // the page or opened another one is dropped instead of rendered.
    let ticket = 0;
    let disposed = false;

    function render() {
      clear(body);
      body.append(pageHead({ title: ctx.t("subscriptions.title"), subtitle: ctx.t("subscriptions.subtitle") }));

      if (subscriptions.length === 0) {
        body.append(empty(ctx.t("subscriptions.empty")));
        return;
      }

      body.append(
        card({
          title: ctx.t("subscriptions.list"),
          children: table({
            className: "subscriptions",
            columns: [
              { label: ctx.t("subscriptions.column.name") },
              { label: ctx.t("subscriptions.column.nodes"), align: "right" },
              { label: ctx.t("subscriptions.column.skipped"), align: "right" },
              { label: ctx.t("subscriptions.column.fetched") },
              { label: ctx.t("subscriptions.column.next") },
              { label: ctx.t("subscriptions.column.error") },
              { label: "" },
            ],
            rows: subscriptions.map((item) => [
              el("span", { class: "mono name", text: item.name }),
              formatNumber(item.nodes ?? 0, ctx.locale),
              formatNumber(item.skipped ?? 0, ctx.locale),
              el("span", { class: "time", text: formatDateTime(item.fetched_at, ctx.locale) }),
              el("span", { class: "time", text: formatDateTime(item.next_at, ctx.locale) }),
              el("span", { class: "detail", text: item.error ? item.error : "—" }),
              action({
                t: ctx.t,
                open: detail?.name === item.name,
                onShow: () => show(item.name),
                onHide: close,
              }),
            ]),
            emptyText: ctx.t("subscriptions.empty"),
          }),
        }),
      );

      if (detail) body.append(detailCard({ t: ctx.t, locale: ctx.locale, detail, show, close }));
    }

    /** Fetch one page of one subscription's skipped entries. */
    async function show(name, offset = 0) {
      const mine = ++ticket;
      detail = { name, offset, loading: true, error: null, page: detail?.name === name ? detail.page : null };
      render();
      try {
        const page = await ctx.api.subscriptionSkipped(name, { offset, limit: PAGE_SIZE });
        if (mine !== ticket || disposed) return;
        ctx.core.noteSuccess();
        detail = { name, offset, loading: false, error: null, page };
      } catch (error) {
        if (mine !== ticket || disposed) return;
        ctx.core.noteFailure(error);
        detail = { name, offset, loading: false, error, page: null };
      }
      render();
    }

    /** Drop the open page; nothing about it is kept. */
    function close() {
      ticket += 1;
      detail = null;
      render();
    }

    async function load() {
      try {
        const payload = await ctx.api.subscriptions();
        ctx.core.noteSuccess();
        subscriptions = Array.isArray(payload?.subscriptions) ? payload.subscriptions : [];
      } catch (error) {
        ctx.core.noteFailure(error);
        subscriptions = [];
      }
      if (!disposed) render();
    }

    render();
    // A subscription refreshes on an interval of minutes at the shortest, so the
    // summary is not worth asking for more often than this.
    const poll = createPoll(load, { every: 10000 });
    poll.start();

    return {
      dispose() {
        disposed = true;
        ticket += 1;
        poll.stop();
      },
    };
  },
};

/**
 * The button that opens or closes one subscription's detail.
 *
 * @param {{ t: Function, open: boolean, onShow: Function, onHide: Function }} input
 */
function action({ t, open, onShow, onHide }) {
  return el("button", {
    class: "btn",
    type: "button",
    text: t(open ? "subscriptions.action.hide" : "subscriptions.action.show"),
    "aria-expanded": String(open),
    onClick: open ? onHide : onShow,
  });
}

/**
 * One page of the skipped entries, with the two ways to move through it.
 *
 * @param {{ t: Function, locale: string, detail: any, show: Function, close: Function }} input
 */
function detailCard({ t, locale, detail, show, close }) {
  const page = detail.page;
  const children = [];

  if (detail.error) {
    children.push(empty(t("subscriptions.skipped.error", { reason: t(`error.${detail.error.code}`) })));
  } else if (!page) {
    children.push(empty(t("common.loading")));
  } else if (!page.refreshed) {
    children.push(empty(t("subscriptions.skipped.never")));
  } else if ((page.total ?? 0) === 0) {
    children.push(empty(t("subscriptions.skipped.none")));
  } else {
    children.push(
      table({
        className: "skipped",
        columns: [
          { label: t("subscriptions.skipped.column.item"), align: "right" },
          { label: t("subscriptions.skipped.column.reason") },
        ],
        rows: (page.skipped ?? []).map((entry) => [
          formatNumber(entry.item, locale),
          el("span", { class: "reason", text: entry.reason }),
        ]),
        emptyText: t("subscriptions.skipped.none"),
      }),
    );
    children.push(pager({ t, locale, page, show: (offset) => show(detail.name, offset), close }));
  }

  return card({
    className: "skipped-detail",
    title: t("subscriptions.skipped.title", { name: detail.name }),
    children: [el("p", { class: "muted", text: t("subscriptions.skipped.note") }), ...children],
  });
}

/**
 * How much of the list the page covers, and the buttons that walk it.
 *
 * The page size comes from the answer rather than from this file: the core
 * decides what a page is, and the next offset has to be the one it used.
 *
 * @param {{ t: Function, locale: string, page: any, show: Function, close: Function }} input
 */
function pager({ t, locale, page, show, close }) {
  const size = Number(page.limit) > 0 ? Number(page.limit) : PAGE_SIZE;
  const total = Number(page.total) || 0;
  const offset = Number(page.offset) || 0;
  const count = Array.isArray(page.skipped) ? page.skipped.length : 0;
  const from = count === 0 ? offset : offset + 1;
  const to = offset + count;

  return el("div", { class: "row pager" }, [
    el("button", {
      class: "btn",
      type: "button",
      text: t("subscriptions.skipped.previous"),
      disabled: offset <= 0,
      onClick: () => show(Math.max(0, offset - size)),
    }),
    el("span", {
      class: "faint",
      text: t("subscriptions.skipped.range", {
        from: formatNumber(from, locale),
        to: formatNumber(to, locale),
        total: formatNumber(total, locale),
      }),
    }),
    el("button", {
      class: "btn",
      type: "button",
      text: t("subscriptions.skipped.next"),
      disabled: to >= total,
      onClick: () => show(to),
    }),
    el("span", { class: "spacer" }),
    el("button", { class: "btn", type: "button", text: t("subscriptions.skipped.close"), onClick: close }),
  ]);
}
