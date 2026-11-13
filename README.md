# MelonARC

MelonARC (Adaptive Routing Core) is an open-source, cross-platform rule-based proxy client that dispatches traffic to different outbound protocols according to user-defined rules, with the core daemon and the UI kept strictly separate.

**Status: MVP in development.** Nothing here is usable yet; the repository currently holds the project scaffold and the technology validation spikes under `spikes/`.

## MVP scope

### Platforms and form factor
- Windows and Linux desktop (x86_64)
- Core daemon, desktop UI and a basic CLI, as three separate parts

### Inbound
- HTTP / SOCKS5 proxy service (local listener, optional authentication)
- System proxy settings, following the core's start and stop
- TUN mode taking over all traffic (Windows: Wintun; Linux: tun device plus route configuration)

### Outbound protocols
- Shadowsocks (including the 2022 cipher suites)
- VMess (AEAD)
- VLESS (including REALITY and the XTLS-Vision flow)
- Trojan
- Snell v4 / v5
- Hysteria2
- TUIC v5
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
- Main window: configuration switching, outbound and policy group lists with switching, live connection list, up/down traffic charts, log viewer
- System tray: start/stop, mode switching, node switching
- Frosted-glass look (translucency plus background blur) with spring-curve motion, all assets original
- Connection logs and traffic statistics persisted locally (SQLite)

## Repository layout

```
cmd/melonarc-core   core daemon entry point
cmd/melonarc-cli    command line client entry point
internal/           core packages (config, rules, policy, outbound, inbound, dns, api, store)
spikes/             technology validation prototypes and their results
docs/               design and development documents
```

## Build

Go 1.27 or newer is required.

```
go build ./...
```

## License

MelonARC is licensed under the GNU General Public License, version 3. The full license text is in [LICENSE](LICENSE).

Third-party components may only be added if their license is compatible with the GPLv3, and each one is registered with its version, license and purpose.
