# Third-Party Notices

What this file is: every third-party component this repository builds on, the version
this tree selects, the licence that component ships, and whether its code ends up in the
binaries `scripts/build-release.sh` produces.

MelonARC itself is distributed under GPL-3.0-only (see LICENSE); this file lists only
third-party components and does not change the licence of any of them.

- **Checked on** 2026-11-15 (stage 21), Linux/x86_64, Go 1.27.4, against the module cache
  of that toolchain. The four module-graph-only modules that were unverified then were
  downloaded and read on 2026-11-16 (stage 24); see section 2.
- **Checked how** the licence of each module was read from the `LICENSE`, `LICENCE`,
  `COPYING` and `NOTICE` files that ship **inside that exact version** of the module in
  the local module cache (`$GOMODCACHE/<module>@<version>/`). Nothing here is written
  from memory or from a project's web page. Where a module ships several licence files
  (the SQLite driver does), each one is named. The four modules fetched in stage 24 were
  read the same way, after `go mod download` placed that exact version in the cache.
- **Scope** the two binaries this repository releases (`melonarc-core`, `melonarc-cli`),
  the desktop frontend, and the desktop shell. Test-only and build-only material is
  listed separately and marked as not distributed.

## How the module list was produced

`go list -m all` is the usual way to enumerate a module graph, and it does not run in
this workspace: the machine has no route to the module proxy, and the module cache holds
the `.mod`/`.zip` files the build needs but not every `.info` file the command prints.
Stage 16 recorded the same limitation. The list below was produced from three sources
that do work offline, and they agree with each other:

1. `go mod graph` (109 edges, `GOPROXY=off`), with the selected version of each module
   computed by the usual minimal-version-selection rule over those edges;
2. the `dep` lines of `go version -m` on both release binaries — this is the
   authoritative answer to "what is in the artefact";
3. the `require` blocks of `go.mod`, for the direct dependencies.

The result is 45 modules, of which **17 are linked into the shipped binaries**. The other
28 are in the module graph but contribute no code to the artefact; they are listed in
section 2 so that a reader comparing this file against `go.sum` or an SBOM is not left
wondering about the difference.

## 1. Modules linked into the shipped binaries

All 17 are linked into `melonarc-core`. `melonarc-cli` links none of them: it is a client
for the local API and needs only the standard library.

| Module | Version | Licence | What it does in this product |
|---|---|---|---|
| `github.com/dustin/go-humanize` | v1.1.0 | MIT | `modernc.org/libc`: number and time formatting |
| `github.com/google/uuid` | v1.6.0 | BSD-3-Clause | `modernc.org/libc`: UUID type |
| `github.com/klauspost/compress` | v1.20.1 | BSD-3-Clause; the `gzhttp/` subset is Apache-2.0 and is not imported | `utls` imports `zstd` for the certificate-compression extension |
| `github.com/klauspost/cpuid/v2` | v2.0.9 | MIT | `lukechampine.com/blake3`: runtime CPU feature detection (AVX2/AVX-512 code paths) |
| `github.com/molecule-man/go-brrr` | v1.2.0 | MIT | `utls` imports brotli for the same extension |
| `github.com/oschwald/maxminddb-golang` | v1.13.1 | ISC | reads the MaxMind DB files behind `GEOIP` / `IP-ASN` rules |
| `github.com/quic-go/quic-go` | v0.65.0 | MIT | QUIC transport for the Hysteria2 and TUIC outbounds |
| `github.com/refraction-networking/utls` | v1.8.3-0.20261108164504-a13c59ffe98b | BSD-3-Clause | TLS 1.3 client handshake for the REALITY adapter (pinned to the version a reference implementation locks) |
| `github.com/remyoudompheng/bigfft` | v0.0.0-20230129092748-24d4a6f8daec | BSD-3-Clause | `modernc.org/mathutil`: FFT multiplication |
| `golang.org/x/crypto` | v0.57.0 | BSD-3-Clause | `argon2`, `chacha20poly1305`, `blake2b` in the Shadowsocks and Hysteria2 paths |
| `golang.org/x/net` | v0.59.0 | BSD-3-Clause | `http2/hpack` Huffman table for the HTTP/3 header blocks |
| `golang.org/x/sys` | v0.50.0 | BSD-3-Clause | ioctl, poll and rtnetlink constants for the TUN inbound; also the driver's syscall surface |
| `lukechampine.com/blake3` | v1.4.1 | MIT | Shadowsocks 2022 subkey derivation, hash and keyed hash |
| `modernc.org/libc` | v1.80.1 | BSD-3-Clause | transpiled C runtime the SQLite driver runs on |
| `modernc.org/mathutil` | v1.7.1 | BSD-3-Clause | driver dependency: big integers and bit operations |
| `modernc.org/memory` | v1.12.1 | BSD-3-Clause; the logo file `LICENSE-LOGO` is an attribution reference, not a licence over code | driver dependency: allocator |
| `modernc.org/sqlite` | v1.62.0 | BSD-3-Clause | `database/sql` driver for the observation history |

Two notes on that table:

- `modernc.org/sqlite` also ships `LICENSE-SQLITE` (public domain) and
  `LICENSE-SQLITE_VEC` (MIT); the C code those cover is section 3.
- `github.com/mattn/go-isatty` and `github.com/ncruces/go-strftime` are required by
  `go.mod` but **not** linked into a linux/amd64 binary; they are in section 2.

## 2. In the module graph, not in the artefact

Nothing in this table is compiled into either shipped binary, so no notice obligation
attaches to them. They are listed because `go.sum`, an SBOM generated from the module
graph and a `go list -m all` on a connected machine will all report them.

| Module | Version | Licence | Why it is not in the binary |
|---|---|---|---|
| `github.com/davecgh/go-spew` | v1.1.1 | ISC (stage 24, from `LICENSE`) | test-only dependency of another module |
| `github.com/google/pprof` | v0.0.0-20261016150608-1facf8f91b50 | Apache-2.0 | test-only dependency of the SQLite driver |
| `github.com/hashicorp/golang-lru/v2` | v2.0.7 | MPL-2.0 | module-graph-only dependency of `modernc.org/libc`; file-level copyleft, and no file of it is linked |
| `github.com/jordanlewis/gcassert` | v0.0.0-20250430164644-389ef753e22e | MIT (stage 24, from `LICENSE.txt`) | test-only tooling of another module |
| `github.com/mattn/go-isatty` | v0.0.24 | MIT | required by `go.mod` for other targets; no package of it is reached on linux/amd64 |
| `github.com/ncruces/go-strftime` | v1.1.0 | MIT | same |
| `github.com/pmezard/go-difflib` | v1.0.0 | BSD-3-Clause (stage 24, from `LICENSE`) | test-only dependency of another module |
| `github.com/quic-go/go-ossfuzz-seeds` | v0.1.0 | MIT | fuzz corpus module of `quic-go` |
| `github.com/quic-go/qpack` | v0.6.0 | MIT (stage 24, from `LICENSE.md`) | `quic-go` uses its own copy; no package of this module is linked |
| `github.com/stretchr/testify` | v1.12.1 | MIT | test-only dependency of other modules |
| `go.uber.org/mock` | v0.5.2 | Apache-2.0 | test-only dependency of other modules |
| `go.yaml.in/yaml/v3` | v3.0.5 | Apache-2.0, with the module's `NOTICE` | tooling dependency of other modules |
| `golang.org/x/mod` | v0.42.0 | BSD-3-Clause | module-graph-only dependency of `modernc.org/libc` |
| `golang.org/x/sync` | v0.24.0 | BSD-3-Clause | same |
| `golang.org/x/term` | v0.46.0 | BSD-3-Clause | tooling dependency of other modules |
| `golang.org/x/text` | v0.42.0 | BSD-3-Clause | module-graph-only dependency of `golang.org/x/net` |
| `golang.org/x/tools` | v0.52.0 | BSD-3-Clause | module-graph-only dependency of `modernc.org/libc` |
| `gopkg.in/yaml.v3` | v3.0.1 | Apache-2.0, with the module's `NOTICE` | tooling dependency of other modules |
| `modernc.org/cc/v4` | v4.30.6-0.20261101114202-1b9d1a076f6b | BSD-3-Clause | transpiler used to produce the driver's Go code, upstream; not compiled here |
| `modernc.org/ccgo/v4` | v4.38.1 | BSD-3-Clause | same |
| `modernc.org/fileutil` | v1.4.0 | BSD-3-Clause | module-graph-only dependency of `modernc.org/libc` |
| `modernc.org/gc/v2` | v2.6.5 | BSD-3-Clause | same |
| `modernc.org/gc/v3` | v3.2.0 | BSD-3-Clause | same |
| `modernc.org/goabi0` | v0.2.0 | BSD-3-Clause | same |
| `modernc.org/opt` | v0.2.0 | BSD-3-Clause | same |
| `modernc.org/sortutil` | v1.2.1 | BSD-3-Clause | same |
| `modernc.org/strutil` | v1.2.1 | BSD-3-Clause | same |
| `modernc.org/token` | v1.1.0 | BSD-3-Clause | same |

Four modules could not be checked at stage 21 because the module cache held no copy, and
were marked "not verified here" rather than guessed. Stage 24 (2026-11-16) ran
`go mod download` for all four; the module proxy was reachable on this run, and each
licence was then read from that exact version's own file in the cache: `LICENSE`
(go-spew, ISC; go-difflib, BSD-3-Clause), `LICENSE.md` (qpack, MIT) and `LICENSE.txt`
(gcassert, MIT). None of the four is linked into either shipped binary, so this closes
an accounting gap, not a distribution obligation. **No Go-module row is now unverified**;
the Rust shell in section 5 still awaits a networked build that produces `Cargo.lock`.

## 3. C code the SQLite driver carries into the binary

`modernc.org/sqlite` is not a binding: the SQLite C sources were translated to Go and
committed into the module, so the C code is compiled as Go. The driver's own
`LICENSE-3RD-PARTY.md` accounts for every body of code that reaches a program importing
it. The parts that reach ours:

| Component | Version | Licence | In the binary |
|---|---|---|---|
| SQLite | 3.54.1 (translated into `modernc.org/sqlite/lib`) | public domain (`LICENSE-SQLITE` in the module) | yes |
| musl libc | — (through `modernc.org/libc`) | MIT | yes |
| Go runtime / `go-netdb` | — (through `modernc.org/libc`) | BSD-3-Clause / MIT | yes |
| NixOS/nixpkgs | — (through `modernc.org/libc`) | MIT | yes |
| `sqlite-vec` | v0.1.9 (`LICENSE-SQLITE_VEC`, MIT) | MIT | **no**: linked only when `modernc.org/sqlite/vec` is imported, which this repository does not |
| SQLite `test_demovfs.c` | — (`LICENSE-SQLITE`, public domain) | public domain | **no**: linked only when `modernc.org/sqlite/vfs` is imported, which this repository does not |

## 4. Desktop frontend (`apps/desktop`)

**No npm runtime or build dependencies.** `package-lock.json` contains the package itself
and no `node_modules/` entry, and `npm ci` needs no package registry. The build
(`scripts/build.mjs`) uses only `node:fs`, `node:path` and `node:url`; the tests use
`node:test` and `node:assert`. Nothing from npm is copied into `dist/`.

The artwork (the logo and the icon set under `src/` and `src-tauri/icons/`) is drawn for
this project. No third-party icon set, font file or image is redistributed.

## 5. Desktop shell (`apps/desktop/src-tauri`)

`Cargo.toml` declares three crates. There is no `Cargo.lock` in the tree and no local
cargo registry in this workspace, so **their licences were not read from a local copy**
and no transitive dependency can be enumerated yet.

| Crate | Requirement | Kind | Licence status |
|---|---|---|---|
| `tauri-build` | `2` | build dependency | not verified locally |
| `tauri` | `2` | dependency | not verified locally |
| `serde` | `1` (feature `derive`) | dependency | not verified locally |

The first build that can reach crates.io has to generate `Cargo.lock`, and this section
has to be rewritten from the locked versions — **transitive dependencies remain to be
reviewed after the first networked build produces `Cargo.lock`**. Until then the shell is
source only: it has never been compiled here, and no artefact in this repository contains
it.

## 6. What this file does not do

- It is an **index**, not a copy of the full licence texts. Since stage 24 the archive
  carries them too: `licenses/<module>@<version>.txt` (with `/` written as `_` in the
  filename), one bundle per module linked into `melonarc-core`. Each bundle holds every
  `LICENSE*` / `LICENCE*` / `COPYING*` / `NOTICE*` file that exact version ships, copied
  verbatim from the local Go module cache by `scripts/build-release.sh`, with the source
  filename above each section. The project's own `LICENSE` stays at the archive root.
  See `docs/pre-release-checklist.md` B2.
- It does not decide which GNU GPL version the project is released under; that is the
  copyright holder's decision, and the current divergence between the manifests is
  recorded in `DEVLOG.md` (stage 21).
- It does not cover the reference implementations used to test interoperability
  (`docs/interop-testing.md`). Those are downloaded to a directory outside the repository,
  are never linked, and are never redistributed.
