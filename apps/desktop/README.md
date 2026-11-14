# MelonARC desktop shell

Tauri 2 window for the MelonARC core. This is the skeleton of the interface, not
the finished interface: three panels read real data from the core, three panels
reserve their place, and everything else is structure meant to be extended.

## Build and run

The frontend has no dependencies at all, which is what makes the lockfile the
whole graph and the build offline-safe:

```sh
npm ci          # nothing to download; reads package-lock.json
npm run build   # copies src/ + locales/ into dist/ and checks the result
npm test        # node --test, no test framework installed
```

`npm run build -- --root <path>` builds a checkout at another location; by default
the app root is derived from the script's own path.

The native window needs Rust and the Tauri system libraries (Linux:
`libwebkit2gtk-4.1-dev`, `libgtk-3-dev`, `librsvg2-dev`, `libayatana-appindicator3-dev`):

```sh
cd src-tauri
cargo run                  # builds dist/ first through beforeDevCommand… or:
cargo build --release      # with `npm run build` run beforehand
```

`cargo` writes `Cargo.lock` on the first build; commit it then. It is not in the
repository yet because this step was developed on a machine without a Rust
toolchain (see the stage 13 entry in `DEVLOG.md`).

## Looking at the interface without the native shell

`npm run preview` serves `dist/` and stands in for the shell at `/bridge`: it
reads `<data-dir>/api-token` itself and forwards to `http://127.0.0.1:7946`. The
token therefore never reaches the page, exactly as in the real window.

```sh
npm run build && npm run preview
# then open http://127.0.0.1:5173/
```

Flags: `--port`, `--api`, `--data-dir`, `--root`. Defaults come from
`MELONARC_API_ADDR` / `MELONARC_DATA_DIR`, then the same rules the core uses.
The shell does not parse the core's configuration file: if the core was started
with a non-default `data-dir` or `api-listen`, set the matching override here
(or in the native shell's environment), otherwise the window cannot find the
token or the API.

## Layout

```
src/
  theme/      tokens.css (the only place colours, spacing, radii, glass and
              motion are written), base.css, panels.css
  components/ presentational pieces: card, pill, stat, table, notice, icons
  panels/     registry.js (the extension point) + one module per panel
  api/        client.js (endpoints), bridge.js (tauri | preview | none)
  i18n/       loader, locale detection, translator
  lib/        dom, formatting, polling, shared core state
locales/      zh-CN.json, en.json — every string the user can read
src-tauri/    the shell: two commands, one token read, one HTTP client
scripts/      build.mjs, dev-preview.mjs
test/         node --test files, including a live-core integration test
```

## Adding things

- **A panel**: create `src/panels/<name>.js` exporting `{ id, icon, titleKey,
  order, mount }`, then add one entry in `panels/registry.js`. The sidebar, the
  routing and the hash handling pick it up; no other file changes.
- **A language**: add `locales/<id>.json` with the same keys and one line in
  `LOCALES` in `src/i18n/index.js`. The language's own name lives in its pack
  as `meta.self`, so the switcher needs no change. `npm test` fails if a key is
  missing.
- **A colour or a gap**: add or change a semantic token in `theme/tokens.css`.
  Panels never carry values, only class names.

## Two rules that are easy to break

1. The token never enters the page. If a feature needs a new endpoint, it goes
   through `api_request` in `src-tauri/src/api.rs`, not through `fetch`.
2. Nothing in `src/` contains a sentence: text comes from `locales/`. The test
   suite scans for CJK characters outside `locales/` to keep it that way.
