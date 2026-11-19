package main

import (
	"context"
	"testing"

	"github.com/melon-tgj/melonarc/internal/api"
	"github.com/melon-tgj/melonarc/internal/config"
	"github.com/melon-tgj/melonarc/internal/sysproxy"
)

// fixedProxyStatus is a controller stand-in with a fixed runtime answer. It
// lets the state computation be tested without a desktop proxy to write to.
type fixedProxyStatus struct{ status sysproxy.Status }

func (f fixedProxyStatus) Status() sysproxy.Status { return f.status }

// TestSystemProxyStatePrecedence pins the order in which the four states are
// chosen. A retained, unrecoverable takeover is the one a user must not miss,
// so it wins over a pending restart and an applied takeover; a pending restart
// wins over a takeover that is still in force; applied wins over the config
// value, because it describes what actually happened this run.
func TestSystemProxyStatePrecedence(t *testing.T) {
	tests := []struct {
		name       string
		configured bool
		pending    []string
		status     sysproxy.Status
		want       string
	}{
		{
			name:   "off by default",
			status: sysproxy.Status{},
			want:   api.SystemProxyOff,
		},
		{
			name:       "configured but not applied",
			configured: true,
			status:     sysproxy.Status{},
			want:       api.SystemProxyConfigured,
		},
		{
			name:       "applied this run",
			configured: true,
			status:     sysproxy.Status{Applied: true},
			want:       api.SystemProxyApplied,
		},
		{
			name:       "pending restart beats applied",
			configured: true,
			pending:    []string{"http-listen", "system-proxy"},
			status:     sysproxy.Status{Applied: true},
			want:       api.SystemProxyPendingRestart,
		},
		{
			name:       "unrelated pending restart does not win",
			configured: true,
			pending:    []string{"http-listen"},
			status:     sysproxy.Status{Applied: true},
			want:       api.SystemProxyApplied,
		},
		{
			name:       "recovery failure wins over everything",
			configured: true,
			pending:    []string{"system-proxy"},
			status:     sysproxy.Status{Applied: true, RecoveryFailed: true, Detail: "record kept"},
			want:       api.SystemProxyRecoveryFailed,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			state := &daemonState{proxyStatus: fixedProxyStatus{status: tc.status}}
			got := state.systemProxyStateView(tc.configured, tc.pending)
			if got.State != tc.want {
				t.Errorf("state = %q, want %q (%+v)", got.State, tc.want, got)
			}
			if got.Configured != tc.configured {
				t.Errorf("configured = %t, want %t", got.Configured, tc.configured)
			}
			if got.Applied != tc.status.Applied {
				t.Errorf("applied = %t, want %t", got.Applied, tc.status.Applied)
			}
			if got.RecoveryFailed != tc.status.RecoveryFailed || got.Detail != tc.status.Detail {
				t.Errorf("recovery = (%t, %q), want (%t, %q)",
					got.RecoveryFailed, got.Detail, tc.status.RecoveryFailed, tc.status.Detail)
			}
		})
	}
}

// TestConfigWithoutProxyStatusIsOff keeps a daemon built without a controller
// (a test, or a platform where none was made) honest: it reports nothing
// applied rather than guessing from the configured value.
func TestConfigWithoutProxyStatusIsOff(t *testing.T) {
	cfg, err := config.Parse([]byte("[General]\nhttp-listen = 127.0.0.1:7890\n[Rule]\nFINAL,DIRECT\n"))
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	state := &daemonState{cfg: cfg}
	view := state.Config(context.Background())
	if view.SystemProxyState.State != api.SystemProxyOff || view.SystemProxyState.Applied {
		t.Fatalf("state = %+v", view.SystemProxyState)
	}
}
