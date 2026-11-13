package datadir

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestResolveUsesTheDefaultDirectory(t *testing.T) {
	want, err := Default()
	if err != nil {
		t.Skipf("this environment has no configuration directory: %v", err)
	}
	got, err := Resolve("/base", "")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != want {
		t.Errorf("Resolve(\"\") = %q, want the default %q", got, want)
	}
	if !filepath.IsAbs(got) {
		t.Errorf("the default directory %q is not absolute", got)
	}
}

func TestResolveJoinsARelativePathToTheBase(t *testing.T) {
	base := t.TempDir()
	got, err := Resolve(base, filepath.Join("state", "core"))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if want := filepath.Join(base, "state", "core"); got != want {
		t.Errorf("Resolve = %q, want %q", got, want)
	}
}

func TestResolveKeepsAnAbsolutePath(t *testing.T) {
	absolute := t.TempDir()
	got, err := Resolve("/somewhere/else", absolute)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != filepath.Clean(absolute) {
		t.Errorf("Resolve = %q, want %q", got, absolute)
	}
}

func TestResolveRejectsARelativePathWithoutABase(t *testing.T) {
	if _, err := Resolve("", "state"); err == nil {
		t.Fatal("Resolve accepted a relative path with no base directory")
	}
}

func TestWriteTokenCreatesTheDirectoryWithARestrictedFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "core")
	const token = "c2VjcmV0LXRva2Vu"

	path, err := WriteToken(dir, token)
	if err != nil {
		t.Fatalf("WriteToken: %v", err)
	}
	if want := filepath.Join(dir, TokenFile); path != want {
		t.Errorf("WriteToken returned %q, want %q", path, want)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if runtime.GOOS != "windows" {
		if got := info.Mode().Perm(); got != 0o600 {
			t.Errorf("token file mode = %o, want 600", got)
		}
		if dirInfo, err := os.Stat(dir); err == nil {
			if got := dirInfo.Mode().Perm(); got != 0o700 {
				t.Errorf("data directory mode = %o, want 700", got)
			}
		}
	}

	got, err := ReadToken(dir)
	if err != nil {
		t.Fatalf("ReadToken: %v", err)
	}
	if got != token {
		t.Errorf("ReadToken = %q, want %q", got, token)
	}
}

func TestWriteTokenReplacesThePreviousFile(t *testing.T) {
	dir := t.TempDir()
	if _, err := WriteToken(dir, "first-token"); err != nil {
		t.Fatalf("WriteToken: %v", err)
	}
	path, err := WriteToken(dir, "second-token")
	if err != nil {
		t.Fatalf("WriteToken: %v", err)
	}
	got, err := ReadToken(dir)
	if err != nil {
		t.Fatalf("ReadToken: %v", err)
	}
	if got != "second-token" {
		t.Errorf("ReadToken = %q, want the replacement", got)
	}

	// The atomic replacement must not leave the temporary file behind.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	if len(entries) != 1 || entries[0].Name() != TokenFile {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("data directory holds %v, want only %s (path %s)", names, TokenFile, path)
	}
}

func TestReadTokenRejectsAMissingFile(t *testing.T) {
	dir := t.TempDir()
	_, err := ReadToken(dir)
	if err == nil {
		t.Fatal("ReadToken accepted a missing file")
	}
	if !strings.Contains(err.Error(), TokenPath(dir)) {
		t.Errorf("error %q does not name the file", err)
	}
}

func TestReadTokenRejectsAnEmptyFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(TokenPath(dir), nil, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := ReadToken(dir); err == nil {
		t.Fatal("ReadToken accepted an empty file")
	}
}

func TestWriteTokenRejectsUnusableValues(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{name: "empty", token: ""},
		{name: "space", token: "two words"},
		{name: "newline", token: "line\nbreak"},
		{name: "control character", token: "token\x01"},
		{name: "too long", token: strings.Repeat("a", MaxTokenLen+1)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if _, err := WriteToken(dir, tc.token); err == nil {
				t.Fatalf("WriteToken accepted %q", tc.token)
			}
			if _, err := os.Stat(TokenPath(dir)); !os.IsNotExist(err) {
				t.Error("a rejected token still left a file behind")
			}
		})
	}
}
