# MelonARC 0.1.0-preview.1 — release notes (DRAFT)

> **Draft, not a release.** No tag, no release object and no upload was created for
> this version. This file is the text a future preview announcement would use; it is
> kept in the tree so the claims can be reviewed against the code before anything is
> published. `scripts/build-release.sh 0.1.0-preview.1` produces the archive locally.
> Every claim below is bounded by `README.md` — the support matrix there is the single
> source of truth.

**Status: 0.x source preview, not a stable release.** MelonARC is an open-source,
cross-platform rule-based proxy client. The intended preview assets are three,
all to be built from one source commit: the `linux-amd64` and `linux-arm64` Go
core archives and a macOS arm64 system-proxy client DMG with a native SwiftUI +
AppKit shell. CI builds the macOS shell and its core sidecar with Xcode 26.3 /
Swift 6.2.4; build 48 is the regression baseline and its candidate DMG layout
was accepted in the user's macOS 27 arm64 VM. That DMG is ad-hoc signed, not
notarized. Gatekeeper first-open, system-proxy end-to-end and macOS 13 checks
are still pending, and the Windows/Linux desktop shell is not built. Do not read
the feature list as a promise of working combinations.

## What is in the archives

`melonarc-0.1.0-preview.1-linux-amd64.tar.gz` contains one directory. The
`melonarc-0.1.0-preview.1-linux-arm64.tar.gz` archive has exactly the same
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
module. The archives are not claimed to be bit-reproducible: tar records modification
times and gzip records the time it ran, so use the SHA-256 printed by the build of the
archive you actually have, not a digest copied from an earlier run.

The third asset is an arm64 DMG containing `MelonARC.app`: the native SwiftUI +
AppKit shell and the Go core as a sidecar. It provides system proxy mode only;
macOS TUN is not implemented. Its minimum deployment target is 13.0, with only
macOS 27 exercised so far and 13.x still pending. CI freezes it as
`melonarc-0.1.0-preview-candidate.<build>-macos-arm64.dmg` (build 48 is the
current regression baseline), ad-hoc signed and not notarized. The exact
candidate name, source commit, build number and SHA-256 of the DMG file itself
are recorded in `candidate.json` and its `.sha256` sidecar; verify the bytes you
actually download. The candidate file name is not the public tag: the tag is
`v0.1.0-preview.1`, the app short version stays `0.1.0`, and its
`CFBundleVersion` is the actual CI build number.

## Install and run

There is no installer. Unpack a Linux tarball, edit one file and run two
binaries; on macOS, drag the app from the DMG to Applications. Linux x86_64 and
arm64 are covered by the two tarballs, macOS arm64 by the DMG. No Windows binary
or Windows/Linux desktop shell is in any of the three assets.

For an ad-hoc signed, unnotarized DMG, first open the app with a right-click →
**Open**; if Gatekeeper blocks it, use **System Settings → Privacy & Security →
Open Anyway**. This first-open path is a stage-4 acceptance item and has not yet
been exercised in a clean VM. The shell supervises the Go core and operates in
system proxy mode; macOS TUN is not implemented.

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

No packaged installation has been exercised end to end: the Linux tarballs have
no service unit, tray or auto-start; the macOS DMG's Gatekeeper first-open,
system proxy end-to-end and macOS 13 behavior are still pending VM acceptance.
There is no recorded run that goes from an installed copy through an inbound
listener to an outbound, and no notarised artefact.

## What has actually been verified

Status words are the ones defined in `README.md` (Verified / Project record /
Unit-tested only / Unusable / Unverified). This table is a summary, not a substitute
for that matrix. No protocol sits in the Unusable row today; the word is kept because
the matrix defines it and a future regression can put a row back there.

| Area | Status |
|---|---|
| Shadowsocks legacy AEAD (`aes-256-gcm`) and 2022 suites | **Verified** 4/4 TCP and UDP business by the 2026-11-15 external review on macOS arm64 against a pinned reference server. The other two legacy AEAD suites still need their own cases. |
| VMess (AEAD), Trojan, VLESS + TLS | **Verified** 3/3 TCP and UDP business in the same review, with a pinned reference server. Scope is exactly those three configured cases. |
| VLESS + REALITY | **Project record** for TCP (stage 16, 16 KiB round trip against a pinned reference server). UDP is **Unverified**. Only the Chrome-shaped ClientHello template (`HelloChrome_Auto` on the pinned uTLS version) was carried through real interop; this is **not** a fingerprint claim, other browser templates were not verified, and the implementation deliberately deviates from the template in two extension fields. The VLESS `xtls-rprx-vision` flow is rejected at configuration time. |
| Snell v4 / v5 | **Verified** (CI, 2026-11-16) for TCP and UDP business. Stage 11 first carried TCP for both versions against a pinned Snell reference server. The full interop gate then ran in CI (GitHub Actions, ubuntu, 2026-11-16) against snell-server 5.0.0 with both version configurations, and every Snell case passes. One earlier run in that series failed only the two UDP subtests on an identical code tree and passed on the next, so that failure is recorded as transient (`docs/pre-release-checklist.md` B6). |
| SOCKS5 (+TLS), HTTP / HTTPS outbounds | **Unit-tested only**; UDP **Unverified**. Not part of the reference-server matrix. |
| Hysteria2 and TUIC v5 | **Verified** (CI, 2026-11-16) for TCP and UDP business. The 2026-11-15 external review failed every echo attempt against Hysteria 2.13.0 (the HTTP/3 stage reported a QPACK field-section decode failure, error 512) and against tuic-server 1.0.0 (authentication failure from a text-formatted UUID exporter label); stage 15 repaired both and added known-answer tests. The gate re-ran in CI (GitHub Actions, ubuntu, 2026-11-16) with all seven reference slots filled, and every Hysteria2 and TUIC case passes. Neither is on the core's unusable list any more, so a configuration that uses them starts without a warning. |
| Linux x86_64 | Source build, `go build` / `go vet` / `go test`, `gofmt` and the offline frontend suite pass in this workspace. The amd64 release tarball is built and unpacked locally with version and `-check` readback; no installer and no long-running soak test. |
| Linux arm64 | The arm64 tarball is cross-built from the same commit with the same layout and licence texts. Only cross-build evidence is available here; no native arm64 execution was performed. |
| Windows x86_64 | **Cross-compile only.** Nothing has been executed natively; the Windows TUN device entry still returns "session not implemented". |
| macOS arm64 | CI builds and ad-hoc signs the native SwiftUI + AppKit shell and the Go core sidecar; build 48's candidate DMG layout was accepted in the user's macOS 27 arm64 VM. Minimum deployment target 13.0, only macOS 27 exercised. Gatekeeper first-open, system-proxy end-to-end and macOS 13 checks are **pending**. |
| Desktop application | Frontend offline and live-core suites pass; the frontend is not in the Linux tarballs. The native macOS arm64 shell is built by CI and shipped in the DMG. The Tauri shell intended for Windows/Linux has never been compiled here (no `rustc` / `cargo` / WebKitGTK, no `Cargo.lock`, no native window or native IPC test); on those platforms process hosting, the single-instance lock and the shell settings file exist only as source. |

Not claimed anywhere in this note:

- **Hysteria2 / TUIC beyond the cases the interop suite configures.** The 2026-11-16
  pass is one configuration per protocol against its pinned server — password auth for
  Hysteria2; `cubic` congestion control, `h3` ALPN and 0-RTT off for TUIC — carrying
  32 KiB over TCP and a single datagram over UDP. No other obfuscation,
  congestion-control or certificate setting was exercised.
- **REALITY verified beyond one Chrome template.** No general fingerprint
  compatibility, no REALITY UDP evidence.
- **A Windows/Linux desktop build.** Their Tauri shell is still uncompiled, with no
  installer or tray. The macOS arm64 DMG exists but is ad-hoc signed and not
  notarized; Gatekeeper first-open in a clean VM and system-proxy end-to-end are
  still pending.
- **macOS 13 or macOS TUN.** The deployment floor is 13.0, but only macOS 27 has
  been exercised; 13.x is pending, and macOS TUN is not implemented.
- **Performance.** The five performance targets in the development document have
  **not been measured on real hardware**. The published rule-match numbers are
  microbenchmarks on a fixed rule set from different machines and stages; they cannot
  be extrapolated into throughput, tail latency, memory footprint or cross-platform
  compliance.
- **CI beyond the runs it has had.** The workflow first ran on Actions on 2026-11-16;
  the fifth run was the first with all three jobs green, after four fix rounds in the
  steps that fetch and check the reference implementations. No release tag has machine
  reports behind it. Fuzz targets and seed corpora exist but have only run in bounded
  local sessions.

## Known issues and limits

- No end-to-end evidence from a packaged installation, and no long-run,
  public-network, multi-process or crash-recovery results.
- The Linux TUN inbound is IPv4-only user-space TCP in source; zero-window,
  retransmission, reordering, half-close and long-connection behaviour are not
  validated. Windows and macOS TUN are not implemented; the macOS client offers
  system proxy mode only.
- The macOS DMG is ad-hoc signed and unnotarized, so first open needs the
  Gatekeeper exception described above. Only the build 48 layout has been
  accepted in the user's macOS 27 arm64 VM; system-proxy takeover/restore,
  abnormal exit, first-open and macOS 13 remain stage 4/5 acceptance items.
- System-proxy restore only returns fields still equal to what this program wrote;
  the Linux backend covers gsettings desktop environments only. No validation of a
  settings-refresh broadcast to already-running Windows applications.
- Observation history rewrites all three SQLite tables on each flush; one full flush
  costs about 40 ms in the stage 19 measurement. This is accepted for the preview.
- The VLESS `xtls-rprx-vision` flow is rejected at configuration time and is not usable.
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
not un-publish it. Private vulnerability reporting is enabled on the repository
(2026-11-16); the no-details fallback stays for mirrors and forks where that form is
unavailable.

For ordinary bugs and questions, use the repository's issue tracker with the same
redaction care. `README.md`, `THIRD-PARTY-NOTICES.md` and `DEVLOG.md` record the
evidence behind every status above.

## Licence

GNU General Public License, version 3; full text in `LICENSE`. Third-party components,
their versions and their licences are indexed in `THIRD-PARTY-NOTICES.md`, and their
full licence texts ship in `licenses/`.
