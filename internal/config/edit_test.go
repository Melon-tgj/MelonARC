package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpdateGeneralFileKeepsOtherLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "melonarc.conf")
	original := `[General]
# a comment that must survive
log-level = info ; keep this note
system-proxy = off

[Rule]
FINAL,direct
`
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	level := "warn"
	on := true
	if err := UpdateGeneralFile(path, GeneralPatch{LogLevel: &level, SystemProxy: &on}); err != nil {
		t.Fatalf("update: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, want := range []string{
		"# a comment that must survive",
		"log-level = warn ; keep this note",
		"system-proxy = on",
		"FINAL,direct",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("edited file lost %q:\n%s", want, text)
		}
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.General.LogLevel != "warn" || !cfg.General.SystemProxy {
		t.Fatalf("loaded general = %+v", cfg.General)
	}
}

func TestUpdateGeneralFileInsertsMissingKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "melonarc.conf")
	if err := os.WriteFile(path, []byte("[General]\n\n[Rule]\nFINAL,direct\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	on := true
	if err := UpdateGeneralFile(path, GeneralPatch{SystemProxy: &on}); err != nil {
		t.Fatalf("update: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if strings.Index(text, "system-proxy = on") > strings.Index(text, "[Rule]") {
		t.Fatalf("the key was inserted outside [General]:\n%s", text)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !cfg.General.SystemProxy {
		t.Fatal("the inserted key was not applied")
	}
}

func TestUpdateGeneralFileRejectsAnInvalidPatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "melonarc.conf")
	original := "[General]\nlog-level = info\n\n[Rule]\nFINAL,direct\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	level := "shout"
	if err := UpdateGeneralFile(path, GeneralPatch{LogLevel: &level}); err == nil {
		t.Fatal("an invalid level was accepted")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != original {
		t.Fatalf("a rejected patch changed the file:\n%s", body)
	}
}
