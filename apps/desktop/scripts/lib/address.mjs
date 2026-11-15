/**
 * Validation for the two browser-facing, credentialed hops: the development
 * preview bridge and the address it forwards to.
 *
 * The token is added by the bridge, never by the page. Everything that could
 * steer that request off this machine is checked here before a socket is
 * opened: the address is judged by IP type (not by a textual prefix),
 * `localhost` is resolved and every answer verified, and the connection uses
 * the verified IP literal so a later DNS answer cannot change the destination.
 *
 * Development only. None of this is part of a distribution.
 */

import { BlockList, isIP } from "node:net";
import { lookup as dnsLookup } from "node:dns/promises";

import { parseAddress } from "./paths.mjs";

/** IP-type loopback test. A name is never accepted by this function. */
const LOOPBACK = new BlockList();
LOOPBACK.addSubnet("127.0.0.0", 8, "ipv4");
LOOPBACK.addAddress("::1", "ipv6");

export function isLoopbackIP(host) {
  const family = isIP(host);
  if (family === 4) return LOOPBACK.check(host, "ipv4");
  if (family === 6) return LOOPBACK.check(host, "ipv6");
  return false;
}

const defaultLookup = async (host) => {
  const answers = await dnsLookup(host, { all: true });
  return answers.map((answer) => answer.address);
};

/**
 * Turn a configured `host:port` into a verified loopback endpoint.
 *
 * @param {string} address
 * @param {{ lookup?: (host: string) => Promise<string[]> }} [options]
 * @returns {Promise<{ host: string, port: number, label: string }>}
 *   `host` is an IP literal to dial; `label` is its canonical host:port form.
 */
export async function resolveAddress(address, { lookup = defaultLookup } = {}) {
  const { host, port, label } = parseAddress(address);
  let verified;

  if (isIP(host)) {
    if (!isLoopbackIP(host)) {
      throw new Error(`api address ${label} is not a loopback address; the token never leaves this machine`);
    }
    verified = host;
  } else if (host.toLowerCase() === "localhost") {
    const answers = await lookup(host);
    if (!Array.isArray(answers) || answers.length === 0) {
      throw new Error("localhost resolved to no address");
    }
    for (const answer of answers) {
      if (!isLoopbackIP(answer)) {
        throw new Error(`localhost resolved to ${answer}, which is not loopback; refusing to send the token`);
      }
    }
    // Prefer IPv4: the core binds 127.0.0.1 by default.
    verified = answers.find((answer) => isIP(answer) === 4) ?? answers[0];
  } else {
    throw new Error(`api address ${label} is neither a loopback IP nor localhost; the token never leaves this machine`);
  }

  const canonical = isIP(verified) === 6 ? `[${verified}]` : verified;
  return { host: verified, port, label: `${canonical}:${port}` };
}

/** Writes the core accepts. Anything else must not be able to reach it. */
const WRITE_ENDPOINTS = new Set(["/v1/policies/select", "/v1/config/reload"]);

/**
 * Limit what the bridge may forward. The core has its own authentication, but
 * a development bridge should not become a general-purpose write relay.
 *
 * @param {{ method?: string, path?: string }} request
 * @returns {{ ok: boolean, code?: string }}
 */
export function validateBridgeTarget({ method = "", path = "" } = {}) {
  const verb = String(method).toUpperCase();
  if (verb !== "GET" && verb !== "POST") return { ok: false, code: "bad_method" };
  if (!path.startsWith("/") || path.startsWith("//")) return { ok: false, code: "bad_path" };
  if (/[\u0000-\u001f\u007f\\]/.test(path)) return { ok: false, code: "bad_path" };
  if (verb === "POST" && !WRITE_ENDPOINTS.has(path.split("?")[0])) {
    return { ok: false, code: "write_not_allowed" };
  }
  return { ok: true };
}

/**
 * Validate the Host and browser Origin of a request to the bridge. The Host
 * check rejects DNS rebinding (an attacker-controlled name reaching a server
 * bound to loopback); the Origin check is the write authorisation for a page.
 *
 * @param {{ hostHeader?: string, originHeader?: string, port: number, method?: string }} request
 * @returns {{ ok: boolean, code?: string }}
 */
export function validateBridgeRequest({ hostHeader, originHeader, port, method = "GET" } = {}) {
  const hosts = new Set([`127.0.0.1:${port}`, `localhost:${port}`, `[::1]:${port}`]);
  if (!hostHeader || !hosts.has(String(hostHeader).toLowerCase())) {
    return { ok: false, code: "bad_host" };
  }

  const origins = new Set([
    `http://127.0.0.1:${port}`,
    `http://localhost:${port}`,
    `http://[::1]:${port}`,
  ]);
  const write = String(method).toUpperCase() === "POST";
  if (!originHeader) {
    if (write) return { ok: false, code: "missing_origin" };
  } else if (!origins.has(String(originHeader))) {
    return { ok: false, code: "bad_origin" };
  }
  return { ok: true };
}

/**
 * Build the upstream request. No agent and no proxy are configured: Node's
 * `http` client does not consult the environment proxy on its own, and a
 * credentialed request must never be relayed. Redirects are not followed.
 *
 * @param {{ api: { host: string, port: number, label: string }, method: string,
 *           path: string, contentType?: string, contentLength?: string }} options
 */
export function upstreamRequestOptions({ api, method, path, contentType, contentLength }) {
  const headers = {
    host: api.label,
    connection: "close",
    "accept-encoding": "identity",
  };
  if (contentType) headers["content-type"] = contentType;
  if (contentLength) headers["content-length"] = contentLength;
  return { host: api.host, port: api.port, method, path, headers };
}

/** The preview bridge is development only; a production bundle must not start it. */
export function assertDevelopmentOnly(env = process.env) {
  if (env.NODE_ENV === "production") {
    throw new Error("the preview bridge is development only and must not run in a production build");
  }
}
