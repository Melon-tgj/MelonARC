/**
 * Nodes and policies: the groups, their members, and the manual switch.
 *
 * The only write in this step is the pin (POST /v1/policies/select). It is
 * offered for `select` groups only: asking the core to pin a `url-test` group
 * would be refused, so the button is not there in the first place. Health comes
 * from the same payload, so a switch does not need a second request.
 */

import { empty, pageHead, pill } from "../components/common.js";
import { clear, el } from "../lib/dom.js";
import { formatLatency } from "../lib/format.js";
import { createPoll } from "../lib/poll.js";

export default {
  id: "policies",
  icon: "policies",
  titleKey: "nav.policies",
  order: 20,

  mount(ctx) {
    const body = el("div");
    ctx.root.append(body);

    /** @type {Map<string, { tone: string, text: string }>} */
    const messages = new Map();
    /** @type {Map<string, ReturnType<typeof setTimeout>>} */
    const timers = new Map();
    let groups = [];
    let disposed = false;

    function flash(group, tone, text) {
      messages.set(group, { tone, text });
      const previous = timers.get(group);
      if (previous) clearTimeout(previous);
      timers.set(
        group,
        setTimeout(() => {
          messages.delete(group);
          timers.delete(group);
          if (!disposed) render();
        }, 6000),
      );
    }

    async function pin(group, member) {
      flash(group.name, "warn", ctx.t("policies.pin.pending"));
      render();
      try {
        const view = await ctx.api.selectPolicy(group.name, member);
        ctx.core.noteSuccess();
        const target = groups.find((item) => item.name === group.name);
        if (target) target.active = view?.active ?? member;
        flash(group.name, "ok", ctx.t("policies.pin.ok", { member: view?.active ?? member }));
      } catch (error) {
        ctx.core.noteFailure(error);
        flash(group.name, "bad", ctx.t("policies.pin.failed", { reason: ctx.t(`error.${error.code}`) }));
      }
      if (!disposed) render();
    }

    function render() {
      clear(body);
      body.append(pageHead({ title: ctx.t("policies.title"), subtitle: ctx.t("policies.subtitle") }));

      if (groups.length === 0) {
        body.append(empty(ctx.t("policies.empty")));
        return;
      }
      for (const group of groups) body.append(groupBlock({ t: ctx.t, group, message: messages.get(group.name), onPin: pin }));
    }

    async function load() {
      try {
        const payload = await ctx.api.policies();
        ctx.core.noteSuccess();
        groups = Array.isArray(payload?.policies) ? payload.policies : [];
      } catch (error) {
        ctx.core.noteFailure(error);
        groups = [];
      }
      if (!disposed) render();
    }

    render();
    const poll = createPoll(load, { every: 5000 });
    poll.start();

    return {
      dispose() {
        disposed = true;
        poll.stop();
        for (const timer of timers.values()) clearTimeout(timer);
        timers.clear();
      },
    };
  },
};

/**
 * @param {{ t: Function, group: any, message?: { tone: string, text: string }, onPin: Function }} input
 */
function groupBlock({ t, group, message, onPin }) {
  const pinnable = group.type === "select";
  const members = Array.isArray(group.members) ? group.members : [];

  const head = el("div", { class: "group-head" }, [
    el("span", { class: "name", text: group.name }),
    pill({ text: t(pinnable ? "policies.group.manual" : "policies.group.auto"), tone: pinnable ? "muted" : "ok", withDot: false }),
    el("span", { class: "active" }, [
      el("span", { text: `${t("policies.group.current")}: ` }),
      el("strong", { text: group.active || t("common.na") }),
    ]),
  ]);

  const grid = el(
    "div",
    { class: "member-grid" },
    members.map((member) => memberCard({ t, group, member, pinnable, onPin })),
  );

  const footer = el("div", { class: "group-actions" }, [
    message
      ? el("span", { class: "pill", dataset: { tone: message.tone } }, [el("span", { text: message.text })])
      : el("span", { text: t(pinnable ? "policies.group.pin_hint" : "policies.group.readonly") }),
  ]);

  return el("section", { class: "card group" }, [head, grid, footer]);
}

/**
 * @param {{ t: Function, group: any, member: any, pinnable: boolean, onPin: Function }} input
 */
function memberCard({ t, group, member, pinnable, onPin }) {
  const active = group.active === member.name;
  const health = !member.checked ? "unprobed" : member.healthy ? "ok" : "bad";
  const healthLabel = t(
    health === "ok" ? "policies.member.healthy" : health === "bad" ? "policies.member.unhealthy" : "policies.member.unprobed",
  );

  const meta = [healthLabel];
  if (member.failures > 0) meta.push(t("policies.member.failures", { count: member.failures }));

  const props = {
    class: "member",
    type: "button",
    dataset: { selectable: String(pinnable), health },
    "aria-pressed": String(active),
  };
  if (pinnable && !active) props.onClick = () => onPin(group, member.name);
  if (!pinnable || active) props.disabled = true;

  return el("button", props, [
    el("span", { class: "marker" }),
    el("span", { class: "body" }, [
      el("span", { class: "name", text: member.name }),
      el("span", { class: "meta", text: meta.join(" · ") }),
    ]),
    member.latency_ms > 0
      ? el("span", { class: "aside" }, [
          el("span", { text: formatLatency(member.latency_ms) }),
          el("span", { class: "unit", text: t("policies.member.latency") }),
        ])
      : null,
  ]);
}
