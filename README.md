# MelonARC

MelonARC (Adaptive Routing Core) is an open-source, cross-platform rule-based proxy client. It dispatches traffic to different outbound protocols according to user-defined rules, with the core daemon and the UI kept strictly separate.

**Status: 0.x source preview, not a stable release.** The Go core, the local API, the CLI and the desktop frontend are implemented; native installers, a compiled desktop shell and end-to-end validation on the release targets are not. The support matrix below is the single source of truth for what has actually been verified. Do not read the feature list as a promise of working combinations.

## Support matrix

### What the words mean

- **Verified** — an independent outbound client carried a payload through a pinned-version reference server to an independent echo endpoint, and the returned bytes were compared. The environment and the reference version are named in the row.
- **Project record** — a pass recorded in `DEVLOG.md` with a pinned reference version, in this project's own test harness. Not independently re-run by the external review.
- **Unit-tested only** — known-answer, negative and in-process tests pass, but no traffic has been carried to a reference server.
- **Known failing** — repeated attempts against a real reference server failed. Excluded from any stable claim.
- **Unverified** — no evidence of that combination in either environment.

"TCP business" and "UDP business" mean the payload the proxy carried, not the transport underneath it. For QUIC outbounds the TCP business travels over a QUIC stream.

### Outbound protocols

| Outbound | TCP business | UDP business | Evidence and boundary |
|---|---|---|---|
| Shadowsocks legacy AEAD (`aes-256-gcm`) and 2022 suites (`blake3-aes-128-gcm`, `blake3-aes-256-gcm`, `blake3-chacha20-poly1305`) | **Verified** 4/4 | **Verified** 4/4 | External review, 2026-11-15, macOS arm64, shadowsocks-rust 1.25.0, original repository interop cases. The other two legacy AEAD suites still need their own cases. |
| VMess (AEAD), Trojan, VLESS + TLS | **Verified** 3/3 | **Verified** 3/3 | Same review, Xray-core 26.11.9, original repository interop cases. Scope is exactly those three configured cases. |
| VLESS + REALITY | **Project record** (stage 11 TCP, 16 KiB round trip) | **Unverified** | Stage 11 against Xray-core 26.11.9, in this project's harness. The external review found the handshake skipped the server `CertificateVerify` signature check; stage 15 adds signature verification with known-answer and full-handshake tests against an independent standard-library TLS server, but has **not** re-run upstream interop. |
| Snell v4 / v5 | **Project record** (stage 11 TCP, both versions) | **Unverified** | Stage 11 against a pinned Snell reference server. UDP needs a target machine able to run that reference endpoint. |
| SOCKS5 (+TLS), HTTP / HTTPS outbounds | **Unit-tested only** | **Unverified** | Covered by this project's tests; not part of the external reference-server matrix. |
| Hysteria2 | **Known failing — fix in progress** | **Known failing — fix in progress** | External review: three rounds, all echo attempts failed against pinned Hysteria 2.13.0; the HTTP/3 stage reported QPACK field-section decode failure (error 512). |
| TUIC v5 | **Known failing — fix in progress** | **Known failing — fix in progress** | External review: three rounds, all echo attempts failed against pinned tuic-server 1.0.0; the server logged an authentication failure caused by a text-formatted UUID exporter label. |

Stage 15 repaired the QUIC test fixture, the TUIC exporter label and the HTTP/3 QPACK header blocks, and added known-answer tests for each. **Those fixes are not reported as interoperability passes.** The local sandbox rejects `sendto` on unconnected datagram sockets, so a QUIC first flight cannot leave this machine; local acceptance only proves that the dial path reaches that boundary. Re-running both protocols against the pinned reference servers on a suitable machine is still required. Until then both outbounds must be treated as unusable, and no stable package may offer them.

The VLESS `xtls-rprx-vision` flow is rejected at configuration time and is not supported.

### Platforms and build artefacts

| Target | Status | Evidence and boundary |
|---|---|---|
| Linux x86_64 | Source build and tests pass in this workspace | `go build ./...`, `go vet ./...`, `go test ./...`, `gofmt` and the offline frontend suite run here. No installer, no packaged release, no long-running soak test. |
| Windows x86_64 | **Cross-compile only** | `GOOS=windows go build ./cmd/... ./internal/...` succeeds; the external review also built `CGO_ENABLED=0` for both targets. Nothing has been executed natively: no installer, no runtime test, no device session. The Windows TUN device entry still returns "session not implemented". |
| macOS arm64 | External review host only | The 2026-11-15 review ran on macOS arm64 with Go 1.27.4 and Node 24.20.0. It is not a declared release target. |
| Desktop application | Frontend tested, native shell **not built** | The frontend offline and live-core suites pass. The Rust shell has not been compiled here (no `rustc`/`cargo`/WebKitGTK), `Cargo.lock` is absent, and there are no native window screenshots or native IPC tests. |

The development document's promise of a dual-platform installable build with a resident tray, working system proxy and TUN, every protocol connected and all performance figures measured is **not met**. Treat it as a future acceptance criterion, not a description of this tree.

### Components

| Component | Status | Boundary |
|---|---|---|
| HTTP / SOCKS5 inbounds, local DNS, indexed rule engine, policy groups, reload, local API, CLI | Implemented and unit/integration tested in this workspace | Full inbound-to-outbound forwarding on a clean target installation has not been recorded. |
| TUN inbound | Linux: implemented in source, IPv4 user-space TCP only; Windows: device session unimplemented | Zero-window, retransmission, reordering, half-close and long-connection behaviour are not validated. |
| System proxy | Takes over and restores a persisted snapshot | Restore returns only fields still equal to what this program wrote, and deletes values that were absent before. No validation of a settings-refresh broadcast to already-running Windows applications; the Linux backend covers the gsettings desktop environments only. |
| Observation history | Bounded local tables, self-written file writer | Unknown schema or corrupt files are preserved unchanged with writes suspended. A migration to a maintained database driver is planned. |
| Desktop frontend | Six registered panels, two locales, offline and live-core tests pass | Runs against a development preview bridge only; that bridge is development-only and must not ship in a production package. |

### Performance

The five performance targets in the development document **have not been measured on real hardware**. The published rule-match numbers are microbenchmarks on a fixed rule set from different machines and different stages; they cannot be extrapolated into throughput, tail latency, memory footprint or cross-platform compliance. Every release number needs a dedicated wired test rig, pinned builds and configuration hashes, interleaved direct/proxy runs and the raw samples kept with the release record.

### Other known gaps

- No native installer, tray, auto-start or signed artefacts on either release target.
- No end-to-end evidence from a packaged installation through an inbound listener to an outbound protocol.
- No long-run, public-network, multi-process or crash-recovery results.
- The desktop shell's settings still require a restart of the GUI to take effect.
- No fuzz corpus, no independent CI interop job, and no version-linked machine reports for release tags.

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
- Hysteria2, TUIC v5 — known failing, fix in progress
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

Third-party components may only be added if their license is compatible with the GPLv3, and each one is registered with its version, license and purpose in `DEVLOG.md`. Before publishing binaries, the full transitive licence and notice obligations of the shipped artefacts still need to be audited.
