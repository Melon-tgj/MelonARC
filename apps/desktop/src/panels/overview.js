/**
 * Overview: is the core running, where does it listen, what is it routing
 * through right now.
 *
 * Reads /v1/status, /v1/config and /v1/policies. The three are fetched together
 * on every tick; a panel that failed to load one of them still shows the others,
 * because "the core is up but policies could not be read" is information.
 */

import { card, empty, keyValues, pageHead, pill, stat } from "../components/common.js";
import { icon } from "../components/icons.js";
import { clear, el } from "../lib/dom.js";
import { formatDuration } from "../lib/format.js";
import { createPoll } from "../lib/poll.js";

export default {
  id: "overview",
  icon: "overview",
  titleKey: "nav.overview",
  order: 10,

  mount(ctx) {
    const body = el("div");
    ctx.root.append(body);

    async function render() {
      const [status, config, policies] = await Promise.all([
        ctx.api.status().catch((error) => ({ error })),
        ctx.api.config().catch((error) => ({ error })),
        ctx.api.policies().catch((error) => ({ error })),
      ]);

      const failures = [status, config, policies].filter((value) => value?.error);
      for (const failure of failures) ctx.core.noteFailure(failure.error);
      if (failures.length < 3) ctx.core.noteSuccess();

      clear(body);
      body.append(...build({ t: ctx.t, status, config, policies }));
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
 * @param {{ t: (key: string, vars?: Record<string, string | number>) => string, status: any, config: any, policies: any }} input
 */
function build({ t, status, config, policies }) {
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

  return [pageHead({ title: t("overview.title"), subtitle: t("overview.subtitle") }), statusCard, stats, el("div", { class: "card-grid two" }, [listeners, outboundCard]), configLine];
}
