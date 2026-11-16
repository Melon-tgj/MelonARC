# MelonARC 0.1.0-preview.1 — release notes (DRAFT)

> **Draft, not a release.** No tag, no release object and no upload was created for
> this version. This file is the text a future preview announcement would use; it is
> kept in the tree so the claims can be reviewed against the code before anything is
> published. `scripts/build-release.sh 0.1.0-preview.1` produces the archive locally.
> Every claim below is bounded by `README.md` — the support matrix there is the single
> source of truth.

**Status: 0.x source preview, not a stable release.** MelonARC is an open-source,
cross-platform rule-based proxy client. This archive is a Linux x86_64 source-preview
build of the Go core and its CLI. Native installers, a compiled desktop shell and
end-to-end validation on the release targets do not exist yet. Do not read the feature
list as a promise of working combinations.

## What is in the archive

`melonarc-0.1.0-preview.1-linux-amd64.tar.gz` contains one directory. A second
archive, `melonarc-0.1.0-preview.1-linux-arm64.tar.gz`, has exactly the same
layout with linux/arm64 binaries (for ARM machines and ARM virtual machines):

```
melonarc-0.1.0-preview.1-linux-amd64/
  melonarc-core                 core daemon
  melonarc-cli                  client for the local API
  melonarc.conf                 example configuration (from examples/melonarc.conf)
  LICENSE                       the project's GPLv3 text
  THIRD-PARTY-NOTICES.md        index of components, versions and licences
  licenses/                     full third-party licence texts, one file per linked module
  README.md                     full support matrix and known gaps
  SECURITY.md                   how to report a vulnerability
```

`licenses/` holds 17 bundles (24 licence files) copied verbatim from the local Go
module cache for exactly the modules linked into `melonarc-core`; each bundle is named
`<module>@<version>.txt` with `/` written as `_`. `melonarc-cli` links no third-party
module. The archive is not claimed to be bit-reproducible: tar records modification
times and gzip records the time it ran, so use the SHA-256 printed by the build of the
archive you actually have, not a digest copied from an earlier run.

## Install and run from the tar

There is no installer. Unpack it, edit one file, and run two binaries. Linux
x86_64 and arm64; no Windows binary and no desktop application are in either
archive.

```sh
tar -xzf melonarc-0.1.0-preview.1-linux-amd64.tar.gz   # or ...-linux-arm64.tar.gz
cd melonarc-0.1.0-preview.1-linux-amd64                # matching directory
```

`melonarc.conf` is deliberately fictional and is the same file as
`examples/melonarc.conf`: loopback-only listeners (`http-listen 127.0.0.1:7890`,
`socks5-listen 127.0.0.1:7891`, `api-listen 127.0.0.1:7946`), `data-dir =
./melonarc-data` relative to the config file, one placeholder SOCKS5 outbound at the
documentation address `203.0.113.10` with placeholder credentials, `select` /
`url-test` / `fallback` groups, seven rules ending in `FINAL`, and one `[Host]` mapping.
All addresses come from RFC 5737 documentation ranges and all names from RFC 2606
reserved example domains. **Replace the `[Proxy]` entry with your own node before
use**; nothing in the shipped file reaches a real server.

Validate the file without starting anything:

```sh
./melonarc-core -config ./melonarc.conf -check
```

The first line is `melonarc-core 0.1.0-preview.1`, which also tells you which build
validated the file. `-check` does not create the data directory, write a token or open
a listener. `./melonarc-cli version` reports `melonarc-cli 0.1.0-preview.1`.

Then start the daemon in the foreground:

```sh
./melonarc-core -config ./melonarc.conf
```

On first start it writes the API token to `./melonarc-data/api-token` (mode 0600) and
its observation history into the same directory. The CLI reads the token from
`-token`, then `MELONARC_TOKEN`, then the token file of the data directory:

```sh
./melonarc-cli -data-dir ./melonarc-data version
./melonarc-cli -data-dir ./melonarc-data status
```

Point applications at `127.0.0.1:7890` (HTTP) or `127.0.0.1:7891` (SOCKS5). Keep
these on loopback — an inbound listening on every interface is an open relay. The
local API is loopback-only by design. `melonarc-cli help` lists the remaining commands
(`policies`, `select`, `reload`, `explain`, `audit`, `history`).

Nothing in this procedure has been exercised as a packaged installation end to end:
there is no service unit, no tray, no auto-start, no signed artefact, and no recorded
run that goes from an installed copy through an inbound listener to an outbound.

## What has actually been verified

Status words are the ones defined in `README.md` (Verified / Project record /
Unit-tested only / Unusable / Unverified). This table is a summary, not a substitute
for that matrix.

| Area | Status |
|---|---|
| Shadowsocks legacy AEAD (`aes-256-gcm`) and 2022 suites | **Verified** 4/4 TCP and UDP business by the 2026-11-15 external review on macOS arm64 against a pinned reference server. The other two legacy AEAD suites still need their own cases. |
| VMess (AEAD), Trojan, VLESS + TLS | **Verified** 3/3 TCP and UDP business in the same review, with a pinned reference server. Scope is exactly those three configured cases. |
| VLESS + REALITY | **Project record** for TCP (stage 16, 16 KiB round trip against a pinned reference server). UDP is **Unverified**. Only the Chrome-shaped ClientHello template (`HelloChrome_Auto` on the pinned uTLS version) was carried through real interop; this is **not** a fingerprint claim, other browser templates were not verified, and the implementation deliberately deviates from the template in two extension fields. The VLESS `xtls-rprx-vision` flow is rejected at configuration time. |
| Snell v4 / v5 | **Project record** for TCP (stage 11); UDP **Unverified**. |
| SOCKS5 (+TLS), HTTP / HTTPS outbounds | **Unit-tested only**; UDP **Unverified**. Not part of the reference-server matrix. |
| Hysteria2 and TUIC v5 | **Unusable** — defects found by the external review were repaired in stage 15, but no traffic has been carried against a reference server since. The core warns at startup when either is configured, and accepts it; a warning is not a pass. Both must be excluded from any stable claim or stable package. |
| Linux x86_64 | Source build, `go build` / `go vet` / `go test`, `gofmt` and the offline frontend suite pass in this workspace. No installer, no packaged release, no long-running soak test. |
| Windows x86_64 | **Cross-compile only.** Nothing has been executed natively; the Windows TUN device entry still returns "session not implemented". |
| Desktop application | Frontend offline and live-core suites pass, but the frontend is **not in this archive**. The Rust shell has never been compiled here (no `rustc` / `cargo` / WebKitGTK, no `Cargo.lock`, no native window or native IPC test). Process hosting, the single-instance lock and the shell settings file exist only as source. |

Not claimed anywhere in this note:

- **Hysteria2 / TUIC usable.** They are unusable until their real interoperability is
  re-run on a machine where a QUIC first flight can leave the host.
- **REALITY verified beyond one Chrome template.** No general fingerprint
  compatibility, no REALITY UDP evidence.
- **A desktop build.** No compiled native shell, no installer, no tray, no signed
  artefacts on either release target.
- **Performance.** The five performance targets in the development document have
  **not been measured on real hardware**. The published rule-match numbers are
  microbenchmarks on a fixed rule set from different machines and stages; they cannot
  be extrapolated into throughput, tail latency, memory footprint or cross-platform
  compliance.
- **CI.** A workflow with a separate interop job is written but **has never run on
  Actions**; no run has checked the reference release asset names and no release tag
  has machine reports behind it. Fuzz targets and seed corpora exist but have only run
  in bounded local sessions.

## Known issues and limits

- No end-to-end evidence from a packaged installation, and no long-run,
  public-network, multi-process or crash-recovery results.
- The Linux TUN inbound is IPv4-only user-space TCP in source; zero-window,
  retransmission, reordering, half-close and long-connection behaviour are not
  validated. Windows TUN is not implemented.
- System-proxy restore only returns fields still equal to what this program wrote;
  the Linux backend covers gsettings desktop environments only. No validation of a
  settings-refresh broadcast to already-running Windows applications.
- Observation history rewrites all three SQLite tables on each flush; one full flush
  costs about 40 ms in the stage 19 measurement. This is accepted for the preview.
- The VLESS `xtls-rprx-vision` flow and any configuration that uses Hysteria2 / TUIC
  are not usable; the latter only produce a warning.
- A configuration with an unknown or unreadable history file is preserved unchanged
  with writes suspended, so an older history is never overwritten.
- `README.md` § Other known gaps carries the full list; `docs/pre-release-checklist.md`
  lists what is still blocked before a binary can be published.

## Feedback and security reports

This is a personal project maintained in spare time. Only the newest 0.x preview
receives fixes; it has no fixed response deadline, no bounty and no guarantee that a
fix ships within a particular window.

For **security issues**, follow `SECURITY.md`: open the repository page, choose
**Security**, then **Report a vulnerability**. If that form is unavailable, open a
public issue containing **no details** and ask for a private channel. Include the
version (`-check` banner, `melonarc-cli version`, `/healthz`), the platform, the
smallest reproduction, a redacted configuration and the relevant log lines. Never put
credentials, subscription links, access history or an unredacted configuration in a
public issue; if any were already posted, rotate them first — deleting a comment does
not un-publish it. Note that private vulnerability reporting may not be enabled on the
repository yet (checklist A4), which is why the no-details public issue fallback
matters.

For ordinary bugs and questions, use the repository's issue tracker with the same
redaction care. `README.md`, `THIRD-PARTY-NOTICES.md` and `DEVLOG.md` record the
evidence behind every status above.

## Licence

GNU General Public License, version 3; full text in `LICENSE`. Third-party components,
their versions and their licences are indexed in `THIRD-PARTY-NOTICES.md`, and their
full licence texts ship in `licenses/`.
