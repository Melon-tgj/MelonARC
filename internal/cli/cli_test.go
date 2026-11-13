package cli

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/melon-tgj/melonarc/internal/api"
	"github.com/melon-tgj/melonarc/internal/datadir"
)

const testToken = "test-token"

// runCLI runs the client and returns its exit code and streams.
func runCLI(args ...string) (code int, stdout, stderr string) {
	var out, errOut bytes.Buffer
	code = Run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

// startCore serves the given routes behind the token check the real API uses.
func startCore(t *testing.T, token string, routes map[string]http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	for path, handle := range routes {
		mux.HandleFunc(path, handle)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":{"code":"unauthorized","message":"a valid bearer token is required"}}`))
			return
		}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// writeJSON answers with a JSON encoding of v.
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func TestRunRequiresACommand(t *testing.T) {
	code, _, stderr := runCLI()
	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(stderr, "usage:") {
		t.Errorf("stderr = %q, want the usage text", stderr)
	}
}

func TestUnknownCommand(t *testing.T) {
	code, _, stderr := runCLI("switch", "manual", "a")
	if code != exitUsage {
		t.Fatalf("exit code = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(stderr, `unknown command "switch"`) {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestArgumentCounts(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "select without arguments", args: []string{"select"}, want: "select needs a group and a member"},
		{name: "select with one argument", args: []string{"select", "manual"}, want: "select needs a group and a member"},
		{name: "select with three arguments", args: []string{"select", "manual", "a", "b"}, want: "select needs a group and a member"},
		{name: "explain without a target", args: []string{"explain"}, want: "explain needs one destination"},
		{name: "status with an argument", args: []string{"status", "now"}, want: "status takes no arguments"},
		{name: "reload with an argument", args: []string{"reload", "now"}, want: "reload takes no arguments"},
		{name: "audit with a bad limit", args: []string{"audit", "many"}, want: "not a non-negative number"},
		{name: "audit with two limits", args: []string{"audit", "1", "2"}, want: "at most one limit"},
		{name: "unknown network", args: []string{"-network", "sctp", "explain", "example.com"}, want: "neither tcp nor udp"},
		{name: "bad explain target", args: []string{"explain", "example.com:99999"}, want: "outside 1-65535"},
		{name: "non-positive timeout", args: []string{"-timeout", "0s", "status"}, want: "-timeout must be positive"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, _, stderr := runCLI(tc.args...)
			if code != exitUsage {
				t.Fatalf("exit code = %d, want %d (stderr %q)", code, exitUsage, stderr)
			}
			if !strings.Contains(stderr, tc.want) {
				t.Errorf("stderr = %q, want it to mention %q", stderr, tc.want)
			}
		})
	}
}

// TestStatusSummarizesTheReadOnlyEndpoints drives the command through a client
// stack: the four views are combined into one answer, and every request carries
// the token.
func TestStatusSummarizesTheReadOnlyEndpoints(t *testing.T) {
	var requests int
	core := startCore(t, testToken, map[string]http.HandlerFunc{
		"/healthz": func(w http.ResponseWriter, _ *http.Request) {
			requests++
			writeJSON(w, api.HealthView{Status: "ok", Version: "9.9.9", UptimeSeconds: 125})
		},
		"/v1/status": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, api.StatusView{ConfigPath: "/etc/melonarc.ini", RuleCount: 7, PolicyCount: 2})
		},
		"/v1/inbound": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, api.InboundView{
				Inbounds: []api.InboundStatsView{{Protocol: "http"}, {Protocol: "socks5"}},
				Open:     1, Accepted: 4, Failures: 1, Rejected: 2,
			})
		},
		"/v1/dns": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, api.DNSView{Succeeded: 9, CacheHits: 3, CacheMisses: 2, Entries: 5})
		},
	})

	code, stdout, stderr := runCLI("-api", core.URL, "-token", testToken, "status")
	if code != exitOK {
		t.Fatalf("exit code = %d (stderr %q)", code, stderr)
	}
	for _, want := range []string{"9.9.9", "/etc/melonarc.ini", "2m5s", "http + socks5", "9 resolved"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout does not mention %q:\n%s", want, stdout)
		}
	}
	if requests != 1 {
		t.Errorf("health was read %d times, want 1", requests)
	}

	code, stdout, stderr = runCLI("-api", core.URL, "-token", testToken, "-json", "status")
	if code != exitOK {
		t.Fatalf("exit code = %d (stderr %q)", code, stderr)
	}
	var report statusReport
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("decode %q: %v", stdout, err)
	}
	if report.Health.Version != "9.9.9" || report.Inbound.Accepted != 4 {
		t.Errorf("report = %+v", report)
	}
}

// TestTokenComesFromTheDataDirectory is the reason the token file exists: the
// CLI needs no argument once the core has written it.
func TestTokenComesFromTheDataDirectory(t *testing.T) {
	dir := t.TempDir()
	if _, err := datadir.WriteToken(dir, testToken); err != nil {
		t.Fatalf("WriteToken: %v", err)
	}
	core := startCore(t, testToken, map[string]http.HandlerFunc{
		"/healthz":    func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, api.HealthView{Version: "1"}) },
		"/v1/status":  func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, api.StatusView{}) },
		"/v1/inbound": func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, api.InboundView{}) },
		"/v1/dns":     func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, api.DNSView{}) },
	})

	code, stdout, stderr := runCLI("-api", core.URL, "-data-dir", dir, "status")
	if code != exitOK {
		t.Fatalf("exit code = %d (stderr %q)", code, stderr)
	}
	if !strings.Contains(stdout, "uptime") {
		t.Errorf("stdout = %q", stdout)
	}
}

func TestMissingTokenIsActionable(t *testing.T) {
	dir := t.TempDir()
	code, _, stderr := runCLI("-api", "127.0.0.1:7946", "-data-dir", dir, "status")
	if code != exitFailure {
		t.Fatalf("exit code = %d, want %d", code, exitFailure)
	}
	for _, want := range []string{"no API token at", datadir.TokenPath(dir), "melonarc-core"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr %q does not mention %q", stderr, want)
		}
	}
}

func TestUnreachableCoreIsActionable(t *testing.T) {
	// A port nothing listens on: the core is not running.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := listener.Addr().String()
	_ = listener.Close()

	code, _, stderr := runCLI("-api", addr, "-token", testToken, "status")
	if code != exitFailure {
		t.Fatalf("exit code = %d, want %d", code, exitFailure)
	}
	for _, want := range []string{"no core is listening", "melonarc-core"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr %q does not mention %q", stderr, want)
		}
	}
}

// TestStaleTokenIsExplained covers the one failure a token file makes likely: the
// file is from a previous run of the daemon.
func TestStaleTokenIsExplained(t *testing.T) {
	dir := t.TempDir()
	if _, err := datadir.WriteToken(dir, "stale-token"); err != nil {
		t.Fatalf("WriteToken: %v", err)
	}
	core := startCore(t, testToken, map[string]http.HandlerFunc{
		"/healthz": func(w http.ResponseWriter, _ *http.Request) {},
	})

	code, _, stderr := runCLI("-api", core.URL, "-data-dir", dir, "status")
	if code != exitFailure {
		t.Fatalf("exit code = %d, want %d", code, exitFailure)
	}
	for _, want := range []string{"rejected the token", "new one on every start", datadir.TokenPath(dir)} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr %q does not mention %q", stderr, want)
		}
	}
}

func TestSelectPostsTheSwitch(t *testing.T) {
	var got struct {
		Group  string `json:"group"`
		Member string `json:"member"`
	}
	core := startCore(t, testToken, map[string]http.HandlerFunc{
		"/v1/policies/select": func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				t.Errorf("method = %s, want POST", r.Method)
			}
			if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
				t.Errorf("decode body: %v", err)
			}
			writeJSON(w, api.SelectView{Group: got.Group, Previous: "a", Active: got.Member})
		},
	})

	code, stdout, stderr := runCLI("-api", core.URL, "-token", testToken, "select", "manual", "b")
	if code != exitOK {
		t.Fatalf("exit code = %d (stderr %q)", code, stderr)
	}
	if got.Group != "manual" || got.Member != "b" {
		t.Errorf("the core received %+v", got)
	}
	if strings.TrimSpace(stdout) != "manual: a -> b" {
		t.Errorf("stdout = %q", stdout)
	}
}

func TestReloadReportsWhatApplied(t *testing.T) {
	core := startCore(t, testToken, map[string]http.HandlerFunc{
		"/v1/config/reload": func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				t.Errorf("method = %s, want POST", r.Method)
			}
			writeJSON(w, api.ReloadView{
				OK: true, Path: "/etc/melonarc.ini", RuleCount: 12, ProxyCount: 3,
				GroupCount: 2, HostCount: 1, RestartRequired: []string{"http-listen"},
			})
		},
	})

	code, stdout, stderr := runCLI("-api", core.URL, "-token", testToken, "reload")
	if code != exitOK {
		t.Fatalf("exit code = %d (stderr %q)", code, stderr)
	}
	for _, want := range []string{"reloaded /etc/melonarc.ini", "rules 12", "restart required for: http-listen"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout = %q, want it to mention %q", stdout, want)
		}
	}
}

// TestReloadRejectionIsPrintedVerbatim keeps the daemon's explanation intact: the
// problems and the sentence saying nothing changed are the useful part.
func TestReloadRejectionIsPrintedVerbatim(t *testing.T) {
	core := startCore(t, testToken, map[string]http.HandlerFunc{
		"/v1/config/reload": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnprocessableEntity)
			writeJSON(w, map[string]any{"error": map[string]string{
				"code":    "reload_rejected",
				"message": "1 configuration problem(s):\n  - [Rule] line 3: bad rule\nthe previous configuration is still in force",
			}})
		},
	})

	code, _, stderr := runCLI("-api", core.URL, "-token", testToken, "reload")
	if code != exitFailure {
		t.Fatalf("exit code = %d, want %d", code, exitFailure)
	}
	for _, want := range []string{"reload_rejected", "[Rule] line 3", "still in force"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr = %q, want it to mention %q", stderr, want)
		}
	}
}

func TestExplainDerivesTheQuery(t *testing.T) {
	var query string
	core := startCore(t, testToken, map[string]http.HandlerFunc{
		"/v1/rules/explain": func(w http.ResponseWriter, r *http.Request) {
			query = r.URL.RawQuery
			writeJSON(w, api.ExplainView{
				Matched: true,
				Target:  "manual",
				Report:  "decision: manual\n  rule 3: DOMAIN-SUFFIX,example.com",
			})
		},
	})

	code, stdout, stderr := runCLI("-api", core.URL, "-token", testToken, "explain", "Example.COM:443")
	if code != exitOK {
		t.Fatalf("exit code = %d (stderr %q)", code, stderr)
	}
	for _, want := range []string{"name=Example.COM", "port=443", "network=tcp"} {
		if !strings.Contains(query, want) {
			t.Errorf("query %q does not carry %q", query, want)
		}
	}
	if !strings.Contains(stdout, "decision: manual") {
		t.Errorf("stdout = %q, want the report of the core", stdout)
	}
}

func TestAuditListsTheWrites(t *testing.T) {
	core := startCore(t, testToken, map[string]http.HandlerFunc{
		"/v1/audit": func(w http.ResponseWriter, r *http.Request) {
			if got := r.URL.Query().Get("limit"); got != "5" {
				t.Errorf("limit = %q, want 5", got)
			}
			writeJSON(w, api.AuditListView{
				Capacity: 64,
				Count:    1,
				Entries: []api.AuditView{{
					Time: "2026-11-13T14:00:00Z", Action: api.ActionConfigReload,
					Result: api.ResultOK, Detail: "12 rules", Remote: "127.0.0.1",
				}},
			})
		},
	})

	code, stdout, stderr := runCLI("-api", core.URL, "-token", testToken, "audit", "5")
	if code != exitOK {
		t.Fatalf("exit code = %d (stderr %q)", code, stderr)
	}
	for _, want := range []string{"config.reload", "ok", "127.0.0.1", "12 rules"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout = %q, want it to mention %q", stdout, want)
		}
	}
}

// TestAuditKeepsARecordOnOneRow covers the detail of a refused reload, which
// carries line breaks: the table must not fall apart into extra rows.
func TestAuditKeepsARecordOnOneRow(t *testing.T) {
	core := startCore(t, testToken, map[string]http.HandlerFunc{
		"/v1/audit": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, api.AuditListView{
				Capacity: 64,
				Count:    1,
				Entries: []api.AuditView{{
					Time: "2026-11-13T14:00:00Z", Action: api.ActionConfigReload,
					Result: api.ResultFailed, Detail: "1 problem\n  - [Rule] line 3\nthe previous configuration is still in force",
				}},
			})
		},
	})

	code, stdout, stderr := runCLI("-api", core.URL, "-token", testToken, "audit")
	if code != exitOK {
		t.Fatalf("exit code = %d (stderr %q)", code, stderr)
	}
	if rows := strings.Count(strings.TrimSpace(stdout), "\n"); rows != 1 {
		t.Errorf("the table has %d line breaks, want one row plus the header:\n%s", rows, stdout)
	}
	if !strings.Contains(stdout, "the previous configuration is still in force") {
		t.Errorf("stdout = %q", stdout)
	}
}

func TestSplitTarget(t *testing.T) {
	tests := []struct {
		in       string
		wantHost string
		wantPort int
		wantErr  bool
	}{
		{in: "example.com:443", wantHost: "example.com", wantPort: 443},
		{in: "example.com", wantHost: "example.com"},
		{in: "127.0.0.1:80", wantHost: "127.0.0.1", wantPort: 80},
		{in: "127.0.0.1", wantHost: "127.0.0.1"},
		{in: "[::1]:8080", wantHost: "::1", wantPort: 8080},
		{in: "[::1]", wantHost: "::1"},
		{in: "::1", wantHost: "::1"},
		{in: "  example.com:80  ", wantHost: "example.com", wantPort: 80},
		{in: "", wantErr: true},
		{in: "example.com:0", wantErr: true},
		{in: "example.com:http", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			host, port, err := splitTarget(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("splitTarget(%q) = %q, %d, want an error", tc.in, host, port)
				}
				return
			}
			if err != nil {
				t.Fatalf("splitTarget(%q): %v", tc.in, err)
			}
			if host != tc.wantHost || port != tc.wantPort {
				t.Errorf("splitTarget(%q) = %q, %d, want %q, %d", tc.in, host, port, tc.wantHost, tc.wantPort)
			}
		})
	}
}

func TestAPIBaseNormalisation(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{in: "", want: "http://" + api.DefaultAddr},
		{in: "127.0.0.1:9000", want: "http://127.0.0.1:9000"},
		{in: "http://127.0.0.1:9000/", want: "http://127.0.0.1:9000"},
		{in: "https://core.example", want: "https://core.example"},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, err := apiBase(tc.in)
			if err != nil {
				t.Fatalf("apiBase(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("apiBase(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
	for _, bad := range []string{"ftp://core", "http://", "://x"} {
		if _, err := apiBase(bad); err == nil {
			t.Errorf("apiBase accepted %q", bad)
		}
	}
}
