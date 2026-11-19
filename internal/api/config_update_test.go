package api

import (
	"net/http"
	"strings"
	"testing"
)

func TestConfigUpdateEndpoint(t *testing.T) {
	p := &fakeProvider{updateView: ConfigUpdateView{
		Path:        "/tmp/melonarc.conf",
		LogLevel:    "warn",
		SystemProxy: true,
	}}
	s := newTestServer(t, p)
	rec := post(t, s, "/v1/config/update", "test-token", `{"log_level":"warn","system_proxy":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
	}
	view := decode[ConfigUpdateView](t, rec)
	if view.LogLevel != "warn" || !view.SystemProxy {
		t.Fatalf("view = %+v", view)
	}
	if p.lastUpdate.LogLevel == nil || *p.lastUpdate.LogLevel != "warn" {
		t.Fatalf("log level did not reach the provider: %+v", p.lastUpdate)
	}
	if p.lastUpdate.SystemProxy == nil || !*p.lastUpdate.SystemProxy {
		t.Fatalf("system proxy did not reach the provider: %+v", p.lastUpdate)
	}
	entries := auditOf(t, s)
	if len(entries) != 1 || entries[0].Action != ActionConfigUpdate || entries[0].Result != ResultOK {
		t.Fatalf("audit = %+v", entries)
	}
}

func TestConfigUpdateKeepsAnExplicitFalse(t *testing.T) {
	p := &fakeProvider{updateView: ConfigUpdateView{Path: "/tmp/melonarc.conf"}}
	s := newTestServer(t, p)
	rec := post(t, s, "/v1/config/update", "test-token", `{"system_proxy":false}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
	}
	if p.lastUpdate.LogLevel != nil {
		t.Errorf("an omitted log level was set: %+v", p.lastUpdate)
	}
	if p.lastUpdate.SystemProxy == nil || *p.lastUpdate.SystemProxy {
		t.Fatalf("an explicit false did not reach the provider: %+v", p.lastUpdate)
	}
}

func TestConfigUpdateValidatesTheBody(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{name: "empty", body: `{}`, want: "at least one setting"},
		{name: "unknown field", body: `{"systemProxy":true}`, want: "unknown field"},
		{name: "bad level", body: `{"log_level":"shout"}`, want: "log_level"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := &fakeProvider{}
			s := newTestServer(t, p)
			rec := post(t, s, "/v1/config/update", "test-token", tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
			}
			body := decode[errorView](t, rec)
			if body.Error.Code != "bad_request" {
				t.Fatalf("code = %q", body.Error.Code)
			}
			if !strings.Contains(body.Error.Message, tc.want) {
				t.Fatalf("message %q does not mention %q", body.Error.Message, tc.want)
			}
			if p.lastUpdate.LogLevel != nil || p.lastUpdate.SystemProxy != nil {
				t.Fatalf("a rejected body reached the provider: %+v", p.lastUpdate)
			}
		})
	}
}
