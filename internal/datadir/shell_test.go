package datadir

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// TestTheShellAgreesOnTheNames pins the part of the contract the window has to
// repeat from this package.
//
// The window cannot ask the core where the token is: it starts the core and then
// reads the file, so both sides have to spell the directory name and the file
// name the same way. They live in different languages, so nothing but a test can
// notice when one of them is renamed. The check reads the shell's source rather
// than a copy of the values, because a copy is what drifts.
func TestTheShellAgreesOnTheNames(t *testing.T) {
	path := filepath.Join("..", "..", "apps", "desktop", "src-tauri", "src", "settings.rs")
	source, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		t.Skipf("the desktop sources are not part of this tree: %v", err)
	}
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	for _, want := range []struct {
		constant string
		value    string
	}{
		// `pub const DEFAULT_DIR_NAME: &str = "melonarc";`
		{constant: "DEFAULT_DIR_NAME", value: DefaultDirName},
		// `pub const TOKEN_FILE: &str = "api-token";`
		{constant: "TOKEN_FILE", value: TokenFile},
	} {
		got, err := rustStringConst(source, want.constant)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if got != want.value {
			t.Errorf("the shell's %s is %q, this package uses %q", want.constant, got, want.value)
		}
	}
}

// rustStringConst reads the value of a `pub const NAME: &str = "…";` line.
func rustStringConst(source []byte, name string) (string, error) {
	pattern := regexp.MustCompile(`(?m)^pub const ` + name + `\s*:\s*&str\s*=\s*"([^"]*)"\s*;`)
	match := pattern.FindSubmatch(source)
	if match == nil {
		return "", fmt.Errorf("no definition of %s", name)
	}
	return string(match[1]), nil
}
