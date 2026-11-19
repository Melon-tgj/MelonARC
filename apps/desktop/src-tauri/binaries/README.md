# Sidecar slot

`tauri.conf.json` declares `"externalBin": ["binaries/melonarc-core"]`. The bundler
therefore expects a core binary here, named with the target triple appended:

| target | file |
| --- | --- |
| `aarch64-apple-darwin` | `melonarc-core-aarch64-apple-darwin` |
| `x86_64-unknown-linux-gnu` | `melonarc-core-x86_64-unknown-linux-gnu` |
| `x86_64-pc-windows-msvc` | `melonarc-core-x86_64-pc-windows-msvc.exe` |

From the repository root, for the macOS preview:

```
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" \
  -o apps/desktop/src-tauri/binaries/melonarc-core-aarch64-apple-darwin \
  ./cmd/melonarc-core
```

The macOS CI job does exactly this. The bundler strips the triple suffix and
copies the file to `MelonARC.app/Contents/MacOS/melonarc-core`, which is the
first place `settings::core_search_paths` looks (next to the shell's own
executable). A plain `cargo run` does not need this file; `tauri build` does.

Binaries are ignored by git — this note is the only tracked file here.
