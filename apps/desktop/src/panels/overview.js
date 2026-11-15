/**
 * Overview: is the core running, where does it listen, what is it routing
 * through right now — and what does the shell say about the process it hosts.
 *
 * Reads /v1/status, /v1/config and /v1/policies. The three are fetched together
 * on every tick; a panel that failed to load one of them still shows the others,
 * because "the core is up but policies could not be read" is information.
 *
 * The supervision card is a different fact from the status card above it: the
 * status card answers "does the API answer", the supervision card answers "what
 * is the shell doing with the process". They are rendered side by side and never
 * merged, because a core the shell cannot even spawn still has a state, and a
 * core someone else started still answers. When the transport cannot report the
 * process at all (`coreStatus` returns null), the whole card is left out.
 */

import { card, empty, keyValues, notice, pageHead, pill, stat } from "../components/common.js";
import { icon } from "../components/icons.js";
import { clear, el } from "../lib/dom.js";
import { formatDateTime, formatDuration } from "../lib/format.js";
import { createPoll } from "../lib/poll.js";

/** The four wire states, translated. An unknown state is shown as it arrived. */
const STATE_KEYS = Object.freeze({
  starting: "core.state.starting",
  running: "core.state.running",
  stopped: "core.state.stopped",
  crashed: "core.state.crashed",
});

const STATE_TONES = Object.freeze({
  starting: "warn",
  running: "ok",
  stopped: "warn",
  crashed: "bad",
});

export default {
  id: "overview",
  icon: "overview",
  titleKey: "nav.overview",
  order: 10,

  mount(ctx) {
    const body = el("div");
    ctx.root.append(body);

    let restarting = false;

    async function restartCore() {
      if (restarting) return;
      restarting = true;
      // The answer already is the new status, but the other cards are stale by
      // then too, so the whole panel is rendered again either way.
      const answer = await ctx.api.coreRestart();
      restarting = false;
      if (!answer) {
        // Nothing to show but the failure: keep the previous picture and let the
        // next tick pick up whatever the shell says now.
        await render({ restartFailed: true });
        return;
      }
      await render();
    }

    async function render({ restartFailed = false } = {}) {
      const [status, config, policies, supervision] = await Promise.all([
        ctx.api.status().catch((error) => ({ error })),
        ctx.api.config().catch((error) => ({ error })),
        ctx.api.policies().catch((error) => ({ error })),
        ctx.api.coreStatus(),
      ]);

      const failures = [status, config, policies].filter((value) => value?.error);
      for (const failure of failures) ctx.core.noteFailure(failure.error);
      if (failures.length < 3) ctx.core.noteSuccess();

      clear(body);
      body.append(
        ...build({
          t: ctx.t,
          locale: ctx.locale,
          status,
          config,
          policies,
          supervision,
          restartFailed,
          onRestart: restartCore,
        }),
      );
    }

    const poll = createPoll(render, { every: 4000 });
    poll.start();

    return {
      dispose() {
        poll.stop();
      },
    };
  },
};

/**
 * @param {{
 *   t: (key: string, vars?: Record<string, string | number>) => string,
 *   locale: string,
 *   status: any, config: any, policies: any, supervision: any,
 *   restartFailed: boolean,
 *   onRestart: () => Promise<void>,
 * }} input
 */
function build({ t, locale, status, config, policies, supervision, restartFailed, onRestart }) {
  const running = !status?.error;
  const groups = Array.isArray(policies?.policies) ? policies.policies : [];
  const proxies = Array.isArray(config?.proxies) ? config.proxies : [];

  const statusCard = el("section", { class: "card" }, [
    el("div", { class: "status-row" }, [
      el("div", { class: "headline" }, [
        el("div", { class: "status-dot", dataset: { tone: running ? "ok" : "muted" } }, [icon("power")]),
        el("div", {}, [
          el("div", { class: "title", text: t(running ? "overview.status.running" : "overview.status.stopped") }),
          el("div", {
            class: "sub",
            text: running
              ? `${t("overview.uptime")} ${formatDuration(status.uptime_seconds)} · ${t("overview.version")} ${status.version}`
              : t("common.error"),
          }),
        ]),
      ]),
      el("div", { class: "row" }, [
        running ? pill({ text: status.version, tone: "ok" }) : pill({ text: t("core.pill.offline"), tone: "bad" }),
        config?.log_level ? pill({ text: config.log_level, tone: "muted", withDot: false }) : null,
      ]),
    ]),
  ]);

  const stats = el("div", { class: "card-grid stats" }, [
    stat({
      value: running ? formatDuration(status.uptime_seconds) : t("common.na"),
      label: t("overview.uptime"),
    }),
    stat({ value: running ? String(status.rule_count) : t("common.na"), label: t("overview.rules") }),
    stat({ value: running ? String(status.policy_count) : t("common.na"), label: t("overview.policies") }),
    stat({ value: config?.error ? t("common.na") : String(proxies.length), label: t("overview.proxies") }),
  ]);

  const listeners = config?.error
    ? card({ title: t("overview.listeners"), children: empty(t("common.error")) })
    : card({
        title: t("overview.listeners"),
        children: keyValues([
          { key: t("overview.listener.api"), value: config.api_listen || t("common.na") },
          { key: t("overview.listener.http"), value: config.http_listen || t("common.na") },
          { key: t("overview.listener.socks5"), value: config.socks5_listen || t("common.na") },
          { key: t("overview.log_level"), value: config.log_level || t("common.na") },
        ]),
      });

  const outbound = groups.length
    ? keyValues(
        groups.map((group) => ({
          key: group.name,
          value: group.active || t("common.na"),
        })),
      )
    : empty(t("overview.outbound.empty"));

  const outboundCard = policies?.error
    ? card({ title: t("overview.outbound"), children: empty(t("common.error")) })
    : card({ title: t("overview.outbound"), children: outbound });

  const configLine = config?.path
    ? el("p", { class: "faint" }, [el("span", { text: `${t("overview.config")}: ` }), el("span", { class: "mono", text: config.path })])
    : null;

  const supervisionCard = supervision
    ? buildSupervision({ t, locale, supervision, restartFailed, onRestart })
    : null;

  return [
    pageHead({ title: t("overview.title"), subtitle: t("overview.subtitle") }),
    statusCard,
    supervisionCard,
    stats,
    el("div", { class: "card-grid two" }, [listeners, outboundCard]),
    configLine,
  ];
}

/**
 * The process card: four states, pid, start time, restart count, and the way out
 * of a stopped or crashed core.
 *
 * @param {{
 *   t: (key: string, vars?: Record<string, string | number>) => string,
 *   locale: string,
 *   supervision: any,
 *   restartFailed: boolean,
 *   onRestart: () => Promise<void>,
 * }} input
 */
function buildSupervision({ t, locale, supervision, restartFailed, onRestart }) {
  const state = String(supervision.state ?? "");
  const tone = STATE_TONES[state] ?? "muted";
  const labelKey = STATE_KEYS[state];
  const label = labelKey ? t(labelKey) : state || t("common.na");
  const needsAttention = state === "stopped" || state === "crashed" || restartFailed;

  const restart = el("button", {
    class: "btn",
    type: "button",
    dataset: { variant: "primary" },
    text: t("overview.supervision.restart"),
    onClick: () => void onRestart(),
  });

  const blocked = notice({
    tone: state === "crashed" || restartFailed ? "bad" : "warn",
    title: restartFailed
      ? t("overview.supervision.restart.failed")
      : t(state === "crashed" ? "overview.supervision.crashed" : "overview.supervision.stopped"),
    body: supervision.detail || t("common.na"),
    actions: [restart],
  });

  return card({
    title: t("overview.supervision"),
    children: el("div", { class: "stack" }, [
      el("div", { class: "status-row" }, [
        el("div", { class: "headline" }, [
          el("div", { class: "status-dot", dataset: { tone } }, [icon("power")]),
          el("div", {}, [
            el("div", { class: "title", text: label }),
            el("div", { class: "sub", text: t("overview.supervision.note") }),
          ]),
        ]),
      ]),
      keyValues([
        {
          key: t("overview.supervision.pid"),
          value: supervision.pid == null ? t("common.na") : String(supervision.pid),
        },
        {
          key: t("overview.supervision.started"),
          value:
            supervision.startedAtUnixMs == null
              ? t("common.na")
              : formatDateTime(new Date(supervision.startedAtUnixMs).toISOString(), locale),
        },
        { key: t("overview.supervision.restarts"), value: String(supervision.restarts ?? 0) },
      ]),
      needsAttention ? blocked : null,
    ]),
  });
}
