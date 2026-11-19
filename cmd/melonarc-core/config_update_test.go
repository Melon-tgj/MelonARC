package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/melon-tgj/melonarc/internal/api"
	"github.com/melon-tgj/melonarc/internal/config"
)

func TestUpdateConfigWritesTheFileAndNamesRestarts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "melonarc.conf")
	text := "[General]\nlog-level = info\nsystem-proxy = off\n\n[Rule]\nFINAL,direct\n"
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Path = path
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	state := &daemonState{cfg: cfg}
	level := "warn"
	on := true
	view, err := state.UpdateConfig(context.Background(), api.ConfigUpdateRequest{
		LogLevel: &level, SystemProxy: &on,
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if view.Path != path || view.LogLevel != "warn" || !view.SystemProxy {
		t.Fatalf("view = %+v", view)
	}
	if len(view.RestartRequired) != 1 || view.RestartRequired[0] != "system-proxy" {
		t.Fatalf("restart = %+v", view.RestartRequired)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(body); got == text {
		t.Fatal("the configuration file was not changed")
	}
}

func TestUpdateConfigWithoutAFileIsRefused(t *testing.T) {
	cfg, err := config.Parse([]byte("[General]\nlog-level = info\n\n[Rule]\nFINAL,direct\n"))
	if err != nil {
		t.Fatal(err)
	}
	on := true
	if _, err := (&daemonState{cfg: cfg}).UpdateConfig(context.Background(), api.ConfigUpdateRequest{SystemProxy: &on}); err == nil {
		t.Fatal("a memory-only configuration accepted a write")
	}
}
