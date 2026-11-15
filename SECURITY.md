# Security policy

MelonARC is a proxy client: it holds credentials for remote servers, it reads a file
that says where traffic goes, and it runs with the privileges needed to take over a
machine's routing. A bug in it can expose a subscription, a password or the list of
hosts somebody visited. Please report those privately.

## Reporting a vulnerability

Use GitHub's private reporting: open the repository page, choose **Security**, then
**Report a vulnerability**. That opens an advisory that only the maintainers can see.
If your account cannot use that form, open a public issue that contains **no details** —
just say you have a security report and ask for a private channel — and a maintainer will
reply with one.

Please include:

- the version the core reports (`melonarc-core -check` prints it, `melonarc-cli version`
  prints the client's, and the API's `/healthz` reports it), and how it was built
  (release archive or `go build` from a commit);
- the platform: OS and version, architecture, and whether the report involves TUN, the
  system proxy, an inbound listener or the local API;
- the smallest reproduction you can manage — the configuration lines, the commands, the
  order of events;
- the configuration file **redacted**: keep the structure (sections, rule types, option
  names), replace servers, ports, passwords, UUIDs and `psk` values;
- what you expected and what happened, with the log lines that show it.

## Please do not put these in a public issue

- credentials of any kind: proxy passwords, `psk`, UUIDs, the local API token;
- subscription links — they are credentials, and a link is enough to fetch one;
- your access history or the hostnames in it;
- a configuration file that has not been redacted.

If you have already posted any of these, rotate the credential first and treat the
posting as the incident; deleting the comment does not un-publish it.

## Supported versions

There is no stable release yet. Only the newest 0.x preview receives fixes, and it is a
preview: it is not covered by a response-time commitment, and no version of it is
declared safe for a threat model it has not been tested against. `README.md` records what
has actually been verified, including the outbounds that must be treated as unusable.

## What to expect

This is a personal project maintained in its author's spare time. Reports are read, and
a report that describes a real exposure will be answered — but there is **no fixed
deadline**, no bounty, and no guarantee that a fix ships within a particular window.
What you can count on:

- an acknowledgement that the report arrived, with a first read of it;
- a decision: accepted, needs more information, or out of scope, and why;
- if accepted, a fix in the next preview and a note in `DEVLOG.md` describing what
  changed. Advisories are published once a fixed build exists, and credit is given unless
  you ask otherwise.

## Scope

In scope: the core daemon (`cmd/melonarc-core`, `internal/`), the CLI (`cmd/melonarc-cli`,
`internal/cli`), and the desktop shell's handling of the token and of the core process.
Out of scope: vulnerabilities in the reference implementations used only by the
interoperability tests (they are never linked or redistributed — see
`docs/interop-testing.md`), and the security of the remote servers a user configures.
