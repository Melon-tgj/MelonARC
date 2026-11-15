package version

import (
	"strings"
	"testing"
)

// A version string ends up in JSON, in terminal output and in a file name of
// the release archive: anything with a line break or a control character in it
// breaks one of those.
func TestVersionIsOnePrintableLine(t *testing.T) {
	if Version == "" {
		t.Fatal("Version is empty")
	}
	if strings.TrimSpace(Version) != Version {
		t.Fatalf("Version %q has surrounding space", Version)
	}
	for _, r := range Version {
		if r < 0x20 || r == 0x7f {
			t.Fatalf("Version %q contains a control character", Version)
		}
	}
}

// The linker writes Version with -X, which only works on a variable. Assigning
// to it is the test: a constant would not compile, and a value the compiler
// kept elsewhere would not read back.
func TestVersionIsWritableByTheLinker(t *testing.T) {
	original := Version
	t.Cleanup(func() { Version = original })

	Version = "0.0.0-linker-test"
	if Version != "0.0.0-linker-test" {
		t.Fatalf("Version = %q after assignment", Version)
	}
}

// The placeholder is part of the contract: a source build says 0.1.0-dev, and
// the release script is the only thing that says otherwise.
func TestPlaceholderIsTheDocumentedOne(t *testing.T) {
	if Default != "0.1.0-dev" {
		t.Fatalf("Default = %q, want 0.1.0-dev", Default)
	}
	if Version != Default {
		t.Logf("this build was linked with Version = %q", Version)
	}
}
