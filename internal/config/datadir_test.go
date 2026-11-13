package config

import (
	"strings"
	"testing"
)

// TestParseDataDir checks the data directory setting: a relative value is kept
// as written so that the resolver can join it to the configuration directory,
// and it validates like any other path.
func TestParseDataDir(t *testing.T) {
	in := `[General]
data-dir = ./state

[Rule]
FINAL,DIRECT
`
	cfg, err := Parse([]byte(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.General.DataDir != "./state" {
		t.Fatalf("data-dir = %q, want the value as written", cfg.General.DataDir)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

// TestParseDefaultsLeaveTheDataDirUnset keeps the default out of the parser:
// the platform directory is a runtime decision, not a configuration default.
func TestParseDefaultsLeaveTheDataDirUnset(t *testing.T) {
	cfg, err := Parse([]byte("[Rule]\nFINAL,DIRECT\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.General.DataDir != "" {
		t.Fatalf("data-dir defaults to %q, want it unset", cfg.General.DataDir)
	}
}

func TestValidateRejectsAnUnusableDataDir(t *testing.T) {
	tests := []struct {
		name string
		dir  string
		want string
	}{
		{name: "control character", dir: "state\x01dir", want: "control characters"},
		{name: "too long", dir: strings.Repeat("a", maxDataDirLen+1), want: "longer than"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Parse([]byte("[Rule]\nFINAL,DIRECT\n"))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			cfg.General.DataDir = tc.dir
			err = cfg.Validate()
			if err == nil {
				t.Fatal("Validate accepted the data directory")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}
