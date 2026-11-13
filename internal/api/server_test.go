package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeProvider serves fixed views so the transport can be tested on its own.
type fakeProvider struct {
	status     StatusView
	config     ConfigView
	rules      RuleListView
	policies   []PolicyView
	explain    ExplainView
	explainErr error
	lastLimit  int
	lastReq    ExplainRequest
}

func (f *fakeProvider) Status(context.Context) StatusView { return f.status }
func (f *fakeProvider) Config(context.Context) ConfigView { return f.config }
func (f *fakeProvider) Rules(_ context.Context, limit int) RuleListView {
	f.lastLimit = limit
	return f.rules
}
func (f *fakeProvider) Policies(context.Context) []PolicyView { return f.policies }
func (f *fakeProvider) Explain(_ context.Context, req ExplainRequest) (ExplainView, error) {
	f.lastReq = req
	return f.explain, f.explainErr
}

func newTestServer(t *testing.T, p Provider) *Server {
	t.Helper()
	s, err := New(Options{Addr: "127.0.0.1:0", Token: "test-token", Provider: p, Version: "test"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = s.Close(ctx)
	})
	return s
}

// request runs one request through the router without opening a socket.
func request(t *testing.T, s *Server, method, target, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	s.http.Handler.ServeHTTP(rec, req)
	return rec
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	return v
}

func TestNewRejectsNonLoopback(t *testing.T) {
	tests := []struct {
		name string
		addr string
	}{
		{name: "all interfaces", addr: "0.0.0.0:7946"},
		{name: "empty host", addr: ":7946"},
		{name: "lan address", addr: "192.168.1.5:7946"},
		{name: "hostname", addr: "example.com:7946"},
		{name: "missing port", addr: "127.0.0.1"},
		{name: "bad port", addr: "127.0.0.1:http"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(Options{Addr: tc.addr, Provider: &fakeProvider{}}); err == nil {
				t.Fatalf("New accepted %q", tc.addr)
			}
		})
	}
}

func TestNewAcceptsLoopback(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:0", "localhost:0", "[::1]:0"} {
		s, err := New(Options{Addr: addr, Provider: &fakeProvider{}})
		if err != nil {
			t.Fatalf("New(%q): %v", addr, err)
		}
		if !strings.Contains(s.URL(), "://") {
			t.Errorf("URL = %q", s.URL())
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_ = s.Close(ctx)
		cancel()
	}
}

func TestNewRequiresProvider(t *testing.T) {
	if _, err := New(Options{Addr: "127.0.0.1:0"}); err == nil {
		t.Fatal("a server without a provider must be rejected")
	}
}

func TestTokenIsRandom(t *testing.T) {
	makeServer := func() *Server {
		s, err := New(Options{Addr: "127.0.0.1:0", Provider: &fakeProvider{}})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		t.Cleanup(func() {
			_ = s.Close(ctx)
			cancel()
		})
		return s
	}
	a, b := makeServer(), makeServer()
	if a.Token() == b.Token() {
		t.Fatal("two servers share a token")
	}
	if len(a.Token()) < 40 {
		t.Fatalf("token %q is too short", a.Token())
	}
}

func TestAuthorisation(t *testing.T) {
	p := &fakeProvider{status: StatusView{RuleCount: 7}}
	s := newTestServer(t, p)

	tests := []struct {
		name   string
		header string
		want   int
	}{
		{name: "no header", header: "", want: http.StatusUnauthorized},
		{name: "wrong token", header: "Bearer nope", want: http.StatusUnauthorized},
		{name: "empty bearer", header: "Bearer ", want: http.StatusUnauthorized},
		{name: "basic scheme", header: "Basic test-token", want: http.StatusUnauthorized},
		{name: "correct", header: "Bearer test-token", want: http.StatusOK},
		{name: "correct lower case scheme", header: "bearer test-token", want: http.StatusOK},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			rec := httptest.NewRecorder()
			s.http.Handler.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (%s)", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

func TestUnauthorisedBody(t *testing.T) {
	s := newTestServer(t, &fakeProvider{})
	rec := request(t, s, http.MethodGet, "/v1/status", "")
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("content type = %q", ct)
	}
	body := decode[errorView](t, rec)
	if body.Error.Code != "unauthorized" {
		t.Fatalf("error = %+v", body.Error)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got == "" {
		t.Error("a 401 should carry a challenge")
	}
}

func TestHealth(t *testing.T) {
	s := newTestServer(t, &fakeProvider{})
	rec := request(t, s, http.MethodGet, "/healthz", "test-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := decode[HealthView](t, rec)
	if body.Status != "ok" || body.Version != "test" || body.UptimeSeconds < 0 {
		t.Fatalf("health = %+v", body)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q", got)
	}
}

func TestStatusFallsBackToServerMetadata(t *testing.T) {
	s := newTestServer(t, &fakeProvider{status: StatusView{RuleCount: 3, PolicyCount: 2}})
	rec := request(t, s, http.MethodGet, "/v1/status", "test-token")
	body := decode[StatusView](t, rec)
	if body.Version != "test" {
		t.Errorf("version = %q", body.Version)
	}
	if body.StartedAt.IsZero() || body.UptimeSeconds <= 0 {
		t.Errorf("timestamps are missing: %+v", body)
	}
	if body.RuleCount != 3 || body.PolicyCount != 2 {
		t.Errorf("counts = %+v", body)
	}
}

func TestConfigEndpoint(t *testing.T) {
	p := &fakeProvider{config: ConfigView{
		Path:     "/etc/melonarc/config.conf",
		LogLevel: "info",
		Proxies:  []ProxyView{{Name: "a", Type: "ss", Server: "203.0.113.1", Port: 8388}},
		Groups:   []GroupView{{Name: "G", Type: "select", Members: []string{"a"}}},
	}}
	s := newTestServer(t, p)
	rec := request(t, s, http.MethodGet, "/v1/config", "test-token")
	body := decode[ConfigView](t, rec)
	if body.LogLevel != "info" || len(body.Proxies) != 1 || body.Proxies[0].Port != 8388 {
		t.Fatalf("config = %+v", body)
	}
	if strings.Contains(rec.Body.String(), "password") {
		t.Error("the configuration view must not carry credentials")
	}
}

func TestRulesEndpoint(t *testing.T) {
	p := &fakeProvider{rules: RuleListView{
		Total: 2,
		Limit: 1,
		Rules: []RuleView{{Index: 0, Type: "DOMAIN", Payload: "a.example.com", Target: "DIRECT"}},
	}}
	s := newTestServer(t, p)

	rec := request(t, s, http.MethodGet, "/v1/rules?limit=1", "test-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if p.lastLimit != 1 {
		t.Errorf("provider saw limit %d", p.lastLimit)
	}
	body := decode[RuleListView](t, rec)
	if body.Total != 2 || len(body.Rules) != 1 || body.Rules[0].Payload != "a.example.com" {
		t.Fatalf("rules = %+v", body)
	}

	for _, bad := range []string{"-1", "abc", "999999"} {
		rec := request(t, s, http.MethodGet, "/v1/rules?limit="+bad, "test-token")
		if rec.Code != http.StatusBadRequest {
			t.Errorf("limit=%s gave %d, want 400", bad, rec.Code)
		}
	}
}

func TestPoliciesEndpoint(t *testing.T) {
	p := &fakeProvider{policies: []PolicyView{{
		Name: "Auto", Type: "url-test", Active: "b",
		Members: []MemberView{{Name: "a", Healthy: false, Checked: true}, {Name: "b", Healthy: true, Checked: true, LatencyMS: 12.5}},
	}}}
	s := newTestServer(t, p)
	rec := request(t, s, http.MethodGet, "/v1/policies", "test-token")
	var body struct {
		Policies []PolicyView `json:"policies"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Policies) != 1 || body.Policies[0].Active != "b" {
		t.Fatalf("policies = %+v", body.Policies)
	}
	if body.Policies[0].Members[1].LatencyMS != 12.5 {
		t.Fatalf("latency = %+v", body.Policies[0].Members[1])
	}
}

func TestPoliciesEmptyIsAnArray(t *testing.T) {
	s := newTestServer(t, &fakeProvider{})
	rec := request(t, s, http.MethodGet, "/v1/policies", "test-token")
	if got := strings.TrimSpace(rec.Body.String()); got != `{"policies":[]}` {
		t.Fatalf("body = %s", got)
	}
}

func TestExplainEndpoint(t *testing.T) {
	p := &fakeProvider{explain: ExplainView{
		Matched: true,
		Target:  "Proxy",
		Steps:   []StepView{{Type: "DOMAIN", Match: true, Detail: "exact entry"}},
	}}
	s := newTestServer(t, p)

	rec := request(t, s, http.MethodGet, "/v1/rules/explain?name=a.example.com&port=443&network=TCP", "test-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
	}
	body := decode[ExplainView](t, rec)
	if !body.Matched || body.Target != "Proxy" || len(body.Steps) != 1 {
		t.Fatalf("explain = %+v", body)
	}
	if p.lastReq.Name != "a.example.com" || p.lastReq.Port != 443 || p.lastReq.Network != "tcp" {
		t.Fatalf("request = %+v", p.lastReq)
	}
}

func TestExplainBadRequests(t *testing.T) {
	s := newTestServer(t, &fakeProvider{})
	tests := []string{
		"/v1/rules/explain",
		"/v1/rules/explain?port=70000",
		"/v1/rules/explain?addr=not-an-ip",
		"/v1/rules/explain?network=sctp",
	}
	for _, target := range tests {
		rec := request(t, s, http.MethodGet, target, "test-token")
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s gave %d, want 400 (%s)", target, rec.Code, rec.Body.String())
		}
	}
}

func TestExplainProviderFailure(t *testing.T) {
	p := &fakeProvider{explainErr: errors.New("boom")}
	s := newTestServer(t, p)
	rec := request(t, s, http.MethodGet, "/v1/rules/explain?name=a.example.com", "test-token")
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d", rec.Code)
	}
	if body := decode[errorView](t, rec); body.Error.Code != "explain_failed" {
		t.Fatalf("error = %+v", body.Error)
	}
}

func TestUnknownPath(t *testing.T) {
	s := newTestServer(t, &fakeProvider{})
	rec := request(t, s, http.MethodGet, "/v1/nope", "test-token")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d", rec.Code)
	}
	if body := decode[errorView](t, rec); body.Error.Code != "not_found" {
		t.Fatalf("error = %+v", body.Error)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	s := newTestServer(t, &fakeProvider{})
	for _, method := range []string{http.MethodPost, http.MethodDelete} {
		rec := request(t, s, method, "/v1/config", "test-token")
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s gave %d, want 405", method, rec.Code)
		}
		if got := rec.Header().Get("Allow"); got != http.MethodGet {
			t.Errorf("Allow = %q", got)
		}
		if body := decode[errorView](t, rec); body.Error.Code != "method_not_allowed" {
			t.Errorf("error = %+v", body.Error)
		}
	}
}

// TestServeOverTCP exercises the real listener, not just the handler tree.
func TestServeOverTCP(t *testing.T) {
	s := newTestServer(t, &fakeProvider{status: StatusView{RuleCount: 1}})
	done := s.Start()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = s.Close(ctx)
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("the server did not stop")
		}
	}()

	req, err := http.NewRequest(http.MethodGet, s.URL()+"/healthz", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+s.Token())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d (%s)", resp.StatusCode, body)
	}
	var health HealthView
	if err := json.Unmarshal(body, &health); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	if health.Status != "ok" {
		t.Fatalf("health = %+v", health)
	}

	// The listener is bound to loopback, so the port is reachable on 127.0.0.1
	// but the address never appears as a wildcard bind.
	if !strings.HasPrefix(s.Addr(), "127.0.0.1:") {
		t.Fatalf("address = %q", s.Addr())
	}
}
