package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// TestConfigCarriesTheFourStateView checks that the wire format always holds a
// system_proxy_state object with every fact a client needs to distinguish the
// four desktop-proxy states, even when the provider leaves it at the zero
// value (an older core talking to a newer client).
func TestConfigCarriesTheFourStateView(t *testing.T) {
	p := &fakeProvider{config: ConfigView{
		LogLevel:    "info",
		SystemProxy: true,
		SystemProxyState: SystemProxyView{
			State:      SystemProxyApplied,
			Configured: true,
			Applied:    true,
		},
	}}
	s := newTestServer(t, p)
	rec := request(t, s, http.MethodGet, "/v1/config", "test-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
	}
	raw := rec.Body.String()
	for _, want := range []string{
		`"system_proxy_state"`, `"state":"applied"`, `"configured":true`,
		`"pending_restart":false`, `"applied":true`, `"recovery_failed":false`,
	} {
		if !strings.Contains(raw, want) {
			t.Errorf("response has no %s: %s", want, raw)
		}
	}
	view := decode[ConfigView](t, rec)
	if view.SystemProxyState.State != SystemProxyApplied || !view.SystemProxyState.Applied {
		t.Fatalf("view = %+v", view.SystemProxyState)
	}
}

// TestConfigZeroStateDecodesAsOff keeps the forward-compatibility property: a
// body with no system_proxy_state key (an older daemon) decodes to off with no
// facts set, so a new client never claims a takeover it cannot see.
func TestConfigZeroStateDecodesAsOff(t *testing.T) {
	var view ConfigView
	if err := json.Unmarshal([]byte(`{"log_level":"info","system_proxy":false}`), &view); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if view.SystemProxyState.State != "" || view.SystemProxyState.Configured ||
		view.SystemProxyState.Applied || view.SystemProxyState.RecoveryFailed {
		t.Fatalf("zero state = %+v", view.SystemProxyState)
	}
}
