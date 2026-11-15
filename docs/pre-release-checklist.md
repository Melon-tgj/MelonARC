# Pre-release checklist

Everything that stands between this tree and a public 0.x preview, item by item, with
what is blocked, who can unblock it and how. Written at stage 21 (2026-11-15), when
`scripts/build-release.sh` started producing `dist-release/melonarc-<version>-linux-amd64.tar.gz`.

State words used below:

- **blocked** — cannot be done in this workspace, by this agent, or without a decision.
- **ready** — done, with the evidence named.
- **owner decision** — nothing to build; somebody has to choose.

## A. Before the repository becomes public

| # | Item | State | What blocks it, who, how |
|---|---|---|---|
| A1 | Six image assets are in local history but were never part of the published snapshot | **blocked** | `apps/desktop/src-tauri/icons/{32x32,128x128,128x128@2x,icon}.png`, `icons/icon.ico` and `apps/desktop/src/assets/logo.png` are tracked here, but the snapshot this repository was pushed from did not carry them, so a clone of the remote has a `tauri.conf.json` pointing at files that do not exist and desktop packaging cannot start. This workspace has no remote configured and this stage may not push. Owner: push the branch, or move the icons to a release asset and point the build at it. Check with `git ls-tree -r HEAD --name-only apps/desktop/src-tauri/icons apps/desktop/src/assets` on a fresh clone. |
| A2 | `Cargo.lock` does not exist | **blocked** | Needs one networked `cargo build` / `cargo generate-lockfile` on a machine with rustc ≥ 1.89 and WebKitGTK 4.1. Owner: any machine with those. Then commit the lock and rewrite `THIRD-PARTY-NOTICES.md` section 5 from the locked versions. |
| A3 | CI has never run on Actions | **blocked** | Three jobs are written and statically checked only. The Snell step fails by design until `SNELL_ZIP_URL` / `SNELL_ZIP_SHA256` repository variables are set; the asset names and globs for `tuic-server`, `snell-server` and hysteria's `app/v2.13.0` tag have never been fetched, so the first run may 404. Owner: push a branch and watch the run. Expect the asset globs to need a fix. The other expected fix from stage 20 is gone: stage 22 renamed the two fixture-only QUIC cases to `TestQUICFixture*`, so their skip on a runner that allows `sendto` no longer counts against the interop job (see `DEVLOG.md`, stage 20, left-over 2 and stage 22); `scripts/check-interop.sh` and its strict rule for real `TestInterop*` cases are unchanged. |
| A4 | The private vulnerability channel is not enabled | **blocked** | `SECURITY.md` points at Security → *Report a vulnerability*. That form only appears once **Private vulnerability reporting** is enabled in the repository settings, which a commit cannot do. Owner: Settings → Code security → enable it, open the form once to confirm it works, and decide who watches the advisory inbox. |
| A5 | Licence scope: `GPL-3.0-only` (decision closed) | **ready (resolved)** | The copyright owner decided on 2026-11-15: **GPL-3.0-only** for the whole tree. Root `LICENSE` (the GPLv3 full text) and `README.md` ("version 3") already read as only and were left intact. Stage 23 aligned the four metadata fields — `apps/desktop/package.json` (`license`), `apps/desktop/src-tauri/Cargo.toml` (`[package] license`), `apps/desktop/src-tauri/tauri.conf.json` (`bundle.license`), `apps/desktop/src/version.js` (`APP_LICENSE`) — to the SPDX string `GPL-3.0-only`, and kept `package-lock.json` and the `build.test.mjs` assertion in sync. The stage 21 divergence is closed; see `DEVLOG.md`, stage 23. |
| A6 | Redaction scan | **blocked (partly)** | Stage 21 scanned the working tree and all 50 reachable commits for key blocks, bearer tokens, credentialed URLs, token-bearing links, key-file names, private absolute paths and real IP shapes. Everything found was a fixture or a documentation example. Two loose ends: (a) four modules' licences could not be read (no local copy — needs a networked machine), and (b) the sub-check for literal `password=<value>` occurrences was withheld by the environment during the scan and has to be re-run before publishing. Details and the classification table are in `DEVLOG.md`, stage 21. |
| A7 | Private paths in the development log | **owner decision** | `DEVLOG.md` and `docs/interop-testing.md` name `/home/hatch/interop-bin` as the directory the reference binaries were laid out in; the desktop tests use `/home/melon` and `/Users/melon` as fixture home directories. No credential is involved, but the strings name accounts. Owner: decide whether to keep them (they document how the evidence was produced) or rewrite them to `$HOME` before the repository is opened. Not changed in stage 21: the log is a record, not a draft. |

## B. Before a binary is published

| # | Item | State | What blocks it, who, how |
|---|---|---|---|
| B1 | Release archive builds reproducibly enough to identify | **ready** | `scripts/build-release.sh 0.1.0-preview.1` produced `dist-release/melonarc-0.1.0-preview.1-linux-amd64.tar.gz` (9,765,930 bytes, sha256 printed by the script). The shipped core validates the shipped `melonarc.conf` with `-check`, and both binaries report the injected version. |
| B2 | Third-party licence *texts* are not in the archive | **blocked** | `THIRD-PARTY-NOTICES.md` names every component, version and licence (read from each module's own copy), but the archive carries only the project's `LICENSE` and that file. GPLv3 §6 wants the notices with the binary; whether full texts must be bundled is a legal reading. Owner/decision: either add the licence texts of the 17 linked modules to the archive, or point at a source offer in the release notes. |
| B3 | Four modules have no verified licence line | **blocked** | `davecgh/go-spew`, `pmezard/go-difflib`, `quic-go/qpack`, `jordanlewis/gcassert` are in the module graph but have no copy in this machine's module cache. None is linked into a binary, so nothing is being distributed unlicensed — but the table rows say "not verified". Owner: a machine with module proxy access runs `go mod download` and re-reads the four files. |
| B4 | Rust shell never compiled, installed or exercised over IPC | **blocked** | No `rustc`/`cargo`/WebKitGTK here. Needs `cargo test --locked`, `cargo build --release --locked`, a native window, and a run of the process-hosting, single-instance-lock and settings-file paths. Owner: a Linux or Windows machine with the Tauri prerequisites. Until then the shell is source only and is not in the archive. |
| B5 | Hysteria2 / TUIC: real interoperability not re-verified | **blocked** | The stage 15 repairs are in place and unit-tested, but no traffic has crossed a reference server since. This sandbox forbids `sendto` on unconnected datagram sockets, so a QUIC first flight cannot leave the machine (`docs/interop-testing.md` states the requirement). Owner: any environment that allows it; run `scripts/check-interop.sh` with all seven slots filled. Only then may the README matrix move those rows off "Unusable". |

## C. Before the release targets are claimed

| # | Item | State | What blocks it, who, how |
|---|---|---|---|
| C1 | Windows was never executed natively | **blocked** | The Windows TUN device entry still returns "session not implemented"; the system-proxy registry backend, the token file and the history migration have only been cross-compiled, never run. Owner: a Windows x86_64 machine. Start with `-check`, then the system proxy, then the token file, then the history migration with the base64 fixture from stage 19. |
| C2 | Five performance targets not measured on real hardware | **blocked** | Throughput, rule-match latency at 100k rules, added connection latency, and idle/1000-connection memory all need a wired rig with pinned builds and interleaved direct/proxy runs. `README.md` says so; nothing in this stage changes that. Owner: the same environment as B5. |
| C3 | A packaged installation has never been exercised end to end | **blocked** | Needs an installer (A1 + B4) and a machine to install it on. Owner: after A1, A2 and B4. |

## D. Known costs accepted for the preview

| # | Item | State | Note |
|---|---|---|---|
| D1 | One full history flush costs ~40 ms (was 10–14 ms) | **ready (accepted)** | Stage 19 measurement, `BenchmarkFlushFullHistory`. At one flush per 30 s that is 0.13% duty cycle; the preview may ship with it. Revisit if the retention size grows. |
| D2 | Each flush rewrites all three tables | **ready (accepted)** | Design, not an accident: the in-memory tables are the only truth. An incremental writer is a separate design, not a bug fix. |
| D3 | Fuzz targets run only in bounded local sessions | **ready (noted)** | Four targets, seed corpora committed, 75 s per target in stage 20. No scheduled fuzz job yet; that is on the stage 20 follow-up list. |
