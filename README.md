# MelonARC

MelonARC (Adaptive Routing Core) is an open-source, cross-platform rule-based proxy client. It dispatches traffic to different outbound protocols according to user-defined rules, with the core daemon and the UI kept strictly separate.

**Status: 0.x source preview, not a stable release.** The Go core, the local API, the CLI and the desktop frontend are implemented; native installers, a compiled desktop shell and end-to-end validation on the release targets are not. The support matrix below is the single source of truth for what has actually been verified. Do not read the feature list as a promise of working combinations.

## Support matrix

### What the words mean

- **Verified** — an independent outbound client carried a payload through a pinned-version reference server to an independent echo endpoint, and the returned bytes were compared. The environment and the reference version are named in the row.
- **Project record** — a pass recorded in `DEVLOG.md` with a pinned reference version, in this project's own test harness. Not independently re-run by the external review.
- **Unit-tested only** — known-answer, negative and in-process tests pass, but no traffic has been carried to a reference server.
- **Unusable** — defects found by the external review were repaired, but no traffic has been carried against a reference server since. The repair landing does not make the protocol usable: it is excluded from any stable claim and must not be offered in a stable package.
- **Unverified** — no evidence of that combination in either environment.

"TCP business" and "UDP business" mean the payload the proxy carried, not the transport underneath it. For QUIC outbounds the TCP business travels over a QUIC stream.

### Outbound protocols

| Outbound | TCP business | UDP business | Evidence and boundary |
|---|---|---|---|
| Shadowsocks legacy AEAD (`aes-256-gcm`) and 2022 suites (`blake3-aes-128-gcm`, `blake3-aes-256-gcm`, `blake3-chacha20-poly1305`) | **Verified** 4/4 | **Verified** 4/4 | External review, 2026-11-15, macOS arm64, shadowsocks-rust 1.25.0, original repository interop cases. The other two legacy AEAD suites still need their own cases. |
| VMess (AEAD), Trojan, VLESS + TLS | **Verified** 3/3 | **Verified** 3/3 | Same review, Xray-core 26.11.9, original repository interop cases. Scope is exactly those three configured cases. |
| VLESS + REALITY | **Project record** (stage 16 TCP, 16 KiB round trip) | **Unverified** | Stage 16 replaced the hand-written TLS 1.3 handshake with the pinned uTLS client (`v1.8.3-0.20261108164504-a13c59ffe98b`, the version Xray-core 26.11.9 locks) behind an adapter that only does the REALITY credential work. A scripted peer proves the server authentication segment cannot be skipped, duplicated or reordered, and that a wrong signature, a wrong credential, a trusted-site certificate or a wrong Finished each close the connection before a single VLESS byte. Interop was re-run against Xray-core 26.11.9 (binary SHA-256 `e87bce58…6a66d`): TCP 16 KiB round trip passes. UDP has no evidence yet. |
| Snell v4 / v5 | **Project record** (stage 11 TCP, both versions) | **Unverified** | Stage 11 against a pinned Snell reference server. The 2026-11-16 CI run passes Snell TCP for both versions but fails the v4 and v5 UDP subtests against snell-server 5.0.0; the client framing matches two public implementations byte-for-byte and the session setup was verified locally against the real 4.1.1 and 5.0.0 servers up to this sandbox's `sendto` wall, so the failing leg is only observable in CI. Diagnosis is open (checklist B6); UDP stays unverified until it passes. |
| SOCKS5 (+TLS), HTTP / HTTPS outbounds | **Unit-tested only** | **Unverified** | Covered by this project's tests; not part of the external reference-server matrix. |
| Hysteria2 | **Verified** | **Verified** | External review (2026-11-15): three rounds, all echo attempts failed against pinned Hysteria 2.13.0; the HTTP/3 stage reported QPACK field-section decode failure (error 512). Stage 15 repaired the HTTP/3 header blocks and added known-answer tests. Re-run in CI (GitHub Actions, ubuntu, 2026-11-16) with all seven reference slots filled: the Hysteria2 interop cases pass, TCP and UDP business alike. |
| TUIC v5 | **Verified** | **Verified** | External review (2026-11-15): three rounds, all echo attempts failed against pinned tuic-server 1.0.0; the server logged an authentication failure caused by a text-formatted UUID exporter label. Stage 15 repaired the label and added known-answer tests. Re-run in CI (GitHub Actions, ubuntu, 2026-11-16) with all seven reference slots filled: the TUIC interop cases pass, TCP and UDP business alike. |

Stage 15 repaired the QUIC test fixture, the TUIC exporter label and the HTTP/3 QPACK header blocks, and added known-answer tests for each. The local sandbox rejects `sendto` on unconnected datagram sockets, so a QUIC first flight cannot leave this machine; the re-run therefore happened in CI (GitHub Actions, 2026-11-16), where both protocols passed against the pinned reference servers, as the two rows above record. One interop item remains open: the Snell UDP subtests (v4 and v5) fail in that same CI run while Snell TCP passes — see the Snell row and `docs/pre-release-checklist.md` item B6.

The VLESS `xtls-rprx-vision` flow is rejected at configuration time and is not supported.

### Platforms and build artefacts

| Target | Status | Evidence and boundary |
|---|---|---|
| Linux x86_64 | Source build and tests pass in this workspace | `go build ./...`, `go vet ./...`, `go test ./...`, `gofmt` and the offline frontend suite run here. No installer, no packaged release, no long-running soak test. |
| Windows x86_64 | **Cross-compile only** | `GOOS=windows go build ./cmd/... ./internal/...` succeeds; the external review also built `CGO_ENABLED=0` for both targets. Nothing has been executed natively: no installer, no runtime test, no device session. The Windows TUN device entry still returns "session not implemented". |
| macOS arm64 | External review host only | The 2026-11-15 review ran on macOS arm64 with Go 1.27.4 and Node 24.20.0. It is not a declared release target. |
| Desktop application | Frontend tested, native shell **not built** | The frontend offline and live-core suites pass. The Rust shell has not been compiled here (no `rustc`/`cargo`/WebKitGTK), `Cargo.lock` is absent, and there are no native window screenshots or native IPC tests. Its newest job — starting, supervising and stopping the core process — exists only as source: process hosting, the single-instance lock and the shell settings file have **not** been executed. |

The development document's promise of a dual-platform installable build with a resident tray, working system proxy and TUN, every protocol connected and all performance figures measured is **not met**. Treat it as a future acceptance criterion, not a description of this tree.

### Components

| Component | Status | Boundary |
|---|---|---|
| HTTP / SOCKS5 inbounds, local DNS, indexed rule engine, policy groups, reload, local API, CLI | Implemented and unit/integration tested in this workspace | Full inbound-to-outbound forwarding on a clean target installation has not been recorded. |
| TUN inbound | Linux: implemented in source, IPv4 user-space TCP only; Windows: device session unimplemented | Zero-window, retransmission, reordering, half-close and long-connection behaviour are not validated. |
| System proxy | Takes over and restores a persisted snapshot | Restore returns only fields still equal to what this program wrote, and deletes values that were absent before. No validation of a settings-refresh broadcast to already-running Windows applications; the Linux backend covers the gsettings desktop environments only. |
| Observation history | Bounded local tables in SQLite, through a pure-Go driver (`modernc.org/sqlite` v1.62.0) | The three tables are rewritten whole on each flush. A file whose schema is unknown, or that cannot be read, is preserved unchanged with writes suspended, so a history this build does not understand is never replaced. |
| Desktop frontend | Six registered panels, two locales, offline and live-core tests pass | Runs against a development preview bridge only; that bridge is development-only and must not ship in a production package. The panel that reports the core's process state reads it from the shell, so in the browser it shows either the bridge's own child (with `--core`) or a real probe of a core somebody else started — never a pid the bridge invented. |

### Performance

The five performance targets in the development document **have not been measured on real hardware**. The published rule-match numbers are microbenchmarks on a fixed rule set from different machines and different stages; they cannot be extrapolated into throughput, tail latency, memory footprint or cross-platform compliance. Every release number needs a dedicated wired test rig, pinned builds and configuration hashes, interleaved direct/proxy runs and the raw samples kept with the release record.

### Other known gaps

- No native installer, tray, auto-start or signed artefacts on either release target.
- No end-to-end evidence from a packaged installation through an inbound listener to an outbound protocol.
- No long-run, public-network, multi-process or crash-recovery results.
- The desktop shell's data directory and API address still require a restart of the GUI to take effect; the core binary path and core configuration take effect on the next core start (the settings panel can restart the core).
- Fuzz targets and their seed corpora exist for the configuration parser, share links, subscription bodies and DNS responses. Each has only been run in bounded local sessions; no CI job runs them yet.
- A CI workflow with a separate interop job is written, but it has never run on Actions: no run has yet checked the reference release asset names, and no release tag has machine reports behind it.

## Source-level scope

The following is what exists in the source tree. Its verification status is the matrix above.

### Inbound
- HTTP / SOCKS5 proxy service (local listener, optional authentication)
- System proxy settings, following the core's start and stop
- TUN mode (Linux: tun device plus route configuration; Windows: device binding only)

### Outbound protocols
- Shadowsocks (including the 2022 cipher suites)
- VMess (AEAD)
- VLESS (including REALITY; the XTLS-Vision flow is not accepted)
- Trojan
- Snell v4 / v5
- Hysteria2, TUIC v5 — verified against the pinned reference servers in CI (2026-11-16)
- SOCKS5 (including the TLS variant)
- HTTP / HTTPS

### Rule engine
- Rule types: DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD, DOMAIN-SET, IP-CIDR, IP-CIDR6, GEOIP, IP-ASN, RULE-SET, DEST-PORT, PROTOCOL, FINAL
- External rule sets (RULE-SET / DOMAIN-SET): scheduled updates, local indexing, circular reference detection
- Whole-configuration validation before saving: rule set references exist, policy references exist, FINAL present; an invalid configuration never takes effect
- Rule match explanation: given a domain or IP, print the matched rule and the decision path (CLI first)

### Policy groups
- Select (manual choice)
- URL-Test (periodic latency probing, picks the fastest)
- Fallback (ordered failover)

### Configuration and import
- Native configuration: INI-style sectioned plain text (`[General]` / `[Proxy]` / `[Proxy Group]` / `[Rule]` / `[Host]`), hand-editable and version-control friendly
- Share link import: `vmess://`, `vless://`, `ss://`, `trojan://`, `hysteria2://`, `tuic://` and similar
- Subscription import with scheduled updates
- GeoIP / ASN databases: mmdb format compatible

### Interface and observability
- Main window: configuration switching, outbound and policy group lists with switching, connection list, traffic series, log viewer
- Connection logs and traffic statistics persisted locally (bounded tables)

Details of each stage, the reference versions and the remaining work are recorded in `DEVLOG.md`.

## Repository layout

```
cmd/melonarc-core   core daemon entry point
cmd/melonarc-cli    command line client entry point
apps/desktop        desktop frontend and the (not yet compiled) native shell
internal/           core packages (config, rules, policy, outbound, inbound, dns, api, cli, datadir, store, sysproxy)
spikes/             technology validation prototypes and their results
docs/               design and development documents
```

## Build

Go 1.27 or newer is required.

```
go build ./...
GOOS=windows go build ./cmd/... ./internal/...
```

The second command is a cross-compile check only; it does not produce a validated Windows build.

## License

MelonARC is licensed under the GNU General Public License, version 3. The full license text is in [LICENSE](LICENSE).

Third-party components may only be added if their license is compatible with the GPLv3, and each one is registered with its version, license and purpose in `DEVLOG.md`. [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) lists what reaches a shipped binary, with the licence read from each component's own copy, and names the one part still unaudited (the Rust shell). It ships in the release archive.
