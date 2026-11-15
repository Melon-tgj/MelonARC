// Package version holds the one version string the product reports.
//
// The core, the CLI and the local API all answer with this value, so a release
// build cannot end up with one program claiming a version the other one does
// not. It is set at link time:
//
//	go build -trimpath -ldflags "-s -w -X github.com/melon-tgj/melonarc/internal/version.Version=0.1.0-preview.1"
//
// A plain `go build` reports Default, which is the version a source checkout
// identifies itself as. scripts/build-release.sh is the caller that injects a
// release number.
package version

// Default is what a build with no injection reports.
const Default = "0.1.0-dev"

// Version is the version this build reports.
//
// It is a variable rather than a constant because a release build writes it
// with the linker's -X flag. Every reader imports this one, which is what keeps
// `status`, `healthz`, `version` and the desktop about block from disagreeing.
var Version = Default
