package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func TestEditSubscriptionAddsAndRoundTrips(t *testing.T) {
	original := `[General]
log-level = info

[Proxy]
node = ss, 127.0.0.1, 8388, encrypt-method=aes-256-gcm, password=p=a=s=s

[Rule]
FINAL,node
`
	patch := SubscriptionPatch{
		Name:     "daily",
		URL:      "https://example.com/sub?token=abc",
		Interval: 12 * time.Hour,
	}
	updated, changed, err := EditSubscription([]byte(original), patch)
	if err != nil {
		t.Fatalf("edit: %v", err)
	}
	if !changed {
		t.Fatal("the first edit reported no change")
	}
	for _, want := range []string{
		"log-level = info",
		"[Subscription]",
		"daily = https://example.com/sub?token=abc interval=43200",
		"FINAL,node",
	} {
		if !strings.Contains(string(updated), want) {
			t.Fatalf("edited configuration lost %q:\n%s", want, updated)
		}
	}
	cfg, err := Parse(updated)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cfg.Subscriptions) != 1 || cfg.Subscriptions[0].Name != "daily" ||
		cfg.Subscriptions[0].Interval != 12*time.Hour {
		t.Fatalf("parsed subscriptions = %+v", cfg.Subscriptions)
	}
	again, changed, err := EditSubscription(updated, patch)
	if err != nil {
		t.Fatalf("second edit: %v", err)
	}
	if changed || string(again) != string(updated) {
		t.Fatalf("a retried create was not idempotent:\n%s", again)
	}
}

func TestEditSubscriptionRejectsDifferentDeclaration(t *testing.T) {
	original := "[Subscription]\ndaily = https://example.com/a interval=21600\n"
	_, _, err := EditSubscription([]byte(original), SubscriptionPatch{
		Name: "daily", URL: "https://example.com/a", Interval: 12 * time.Hour,
	})
	var conflict *SubscriptionConflict
	if !errors.As(err, &conflict) {
		t.Fatalf("expected a subscription conflict, got %v", err)
	}
}

func TestEditSubscriptionRejectsUnsafeValues(t *testing.T) {
	original := "[Rule]\nFINAL,direct\n"
	for name, patch := range map[string]SubscriptionPatch{
		"newline in url": {Name: "a", URL: "https://example.com/a\nFINAL,direct"},
		"invalid name":   {Name: "has space", URL: "https://example.com/a"},
		"short interval": {Name: "a", URL: "https://example.com/a", Interval: time.Second},
	} {
		updated, changed, err := EditSubscription([]byte(original), patch)
		if err == nil {
			t.Fatalf("%s: accepted an unsafe patch", name)
		}
		if changed || updated != nil {
			t.Fatalf("%s: returned an edit for a rejected patch", name)
		}
	}
}

func TestReplaceFileRejectsConcurrentChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "melonarc.conf")
	original := []byte("[General]\nlog-level = info\n\n[Rule]\nFINAL,direct\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	edited := []byte("[General]\nlog-level = info\n\n[Subscription]\na = https://example.com/a interval=21600\n\n[Rule]\nFINAL,direct\n")
	if err := os.WriteFile(path, []byte("[General]\nlog-level = info\n\n[Rule]\nFINAL,REJECT\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ReplaceFile(path, original, edited); !errors.Is(err, ErrConfigChanged) {
		t.Fatalf("expected ErrConfigChanged, got %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "a = https://example.com/a") {
		t.Fatalf("a stale commit overwrote the file:\n%s", body)
	}
}
