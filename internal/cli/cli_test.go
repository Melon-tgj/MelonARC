package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/melon-tgj/melonarc/internal/api"
	"github.com/melon-tgj/melonarc/internal/datadir"
	"github.com/melon-tgj/melonarc/internal/version"
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
		{name: "subscriptions with a bad offset", args: []string{"subscriptions", "airport", "many"}, want: "not a non-negative offset"},
		{name: "subscriptions with a bad limit", args: []string{"subscriptions", "airport", "0", "many"}, want: "not a non-negative limit"},
		{name: "subscriptions with too many arguments", args: []string{"subscriptions", "a", "0", "1", "2"}, want: "at most a name, an offset and a limit"},
		{name: "subscriptions with an empty name", args: []string{"subscriptions", " "}, want: "name is empty"},
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

// TestStatusShowsTheExhaustedPoolCounter drives the counter through the client.
// The two payloads are written as JSON on purpose: one is what this build's
// core sends, the other is what a core that predates the field sends, and both
// have to print a number and exit zero.
func TestStatusShowsTheExhaustedPoolCounter(t *testing.T) {
	cases := []struct {
		name  string
		body  string
		want  string
		value uint64
	}{
		{
			name: "this build's core",
			body: `{"inbounds":[{"protocol":"http"}],"open":1,"accepted":2,"failures":0,"rejected":0,` +
				`"fake_ip_pool_exhausted_queries_total":4,"failure_log_capacity":64,"failure_log_count":0}`,
			want:  "4 fake-IP pool exhausted",
			value: 4,
		},
		{
			name: "a core without the field",
			body: `{"inbounds":[{"protocol":"http"}],"open":1,"accepted":2,"failures":0,"rejected":0,` +
				`"failure_log_capacity":64,"failure_log_count":0}`,
			want:  "0 fake-IP pool exhausted",
			value: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			core := startCore(t, testToken, map[string]http.HandlerFunc{
				"/healthz":    func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, api.HealthView{Version: "1"}) },
				"/v1/status":  func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, api.StatusView{}) },
				"/v1/inbound": func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(tc.body)) },
				"/v1/dns":     func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, api.DNSView{}) },
			})

			code, stdout, stderr := runCLI("-api", core.URL, "-token", testToken, "status")
			if code != exitOK {
				t.Fatalf("exit code = %d (stderr %q)", code, stderr)
			}
			if !strings.Contains(stdout, tc.want) {
				t.Errorf("stdout does not mention %q:\n%s", tc.want, stdout)
			}

			code, stdout, stderr = runCLI("-api", core.URL, "-token", testToken, "-json", "status")
			if code != exitOK {
				t.Fatalf("json exit code = %d (stderr %q)", code, stderr)
			}
			var report statusReport
			if err := json.Unmarshal([]byte(stdout), &report); err != nil {
				t.Fatalf("decode %q: %v", stdout, err)
			}
			if got := report.Inbound.FakeIPPoolExhaustedQueriesTotal; got != tc.value {
				t.Errorf("json pool counter = %d, want %d", got, tc.value)
			}
		})
	}
}

// TestDescribeInboundAlwaysNamesThePool keeps the line self-describing: the
// number is meaningless without the word that says what ran out.
func TestDescribeInboundAlwaysNamesThePool(t *testing.T) {
	line := describeInbound(api.InboundView{})
	if !strings.Contains(line, "none;") || !strings.Contains(line, "0 fake-IP pool exhausted") {
		t.Fatalf("line = %q", line)
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

// TestReloadReportsWhatStillWaitsForARestart covers the cumulative answer: a
// reload that changes nothing may still have settings pending from an earlier
// one, and that is exactly what a client cannot see from restart_required alone.
func TestReloadReportsWhatStillWaitsForARestart(t *testing.T) {
	core := startCore(t, testToken, map[string]http.HandlerFunc{
		"/v1/config/reload": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, api.ReloadView{
				OK: true, Path: "/etc/melonarc.ini", RuleCount: 12, ProxyCount: 3,
				GroupCount: 2, HostCount: 1,
				PendingRestart:   []string{"http-listen", "socks5-listen"},
				SelectionDropped: []string{"manual: airport/gone is not a member any more, using airport/new"},
			})
		},
	})

	code, stdout, stderr := runCLI("-api", core.URL, "-token", testToken, "reload")
	if code != exitOK {
		t.Fatalf("exit code = %d (stderr %q)", code, stderr)
	}
	for _, want := range []string{
		"still waiting for a restart: http-listen, socks5-listen",
		"selection not restored: manual: airport/gone",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout = %q, want it to mention %q", stdout, want)
		}
	}
	if strings.Contains(stdout, "restart required for:") {
		t.Errorf("stdout = %q, want no per-reload line when nothing changed now", stdout)
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
		{in: "127.9.8.7:9000", want: "http://127.9.8.7:9000"},
		{in: "[::1]:9000", want: "http://[::1]:9000"},
		{in: "http://[0:0:0:0:0:0:0:1]:9000", want: "http://[::1]:9000"},
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
	for _, bad := range []string{
		"ftp://core", "http://", "://x",
		"https://core.example", "https://127.0.0.1:9000",
		"http://192.168.1.10:9000", "http://10.0.0.1:9000", "http://[2001:db8::1]:9000",
		"http://example.com:9000", "http://user@127.0.0.1:9000",
		"http://127.0.0.1:9000/other", "http://127.0.0.1:9000/?q=1", "http://127.0.0.1",
	} {
		if _, err := apiBase(bad); err == nil {
			t.Errorf("apiBase accepted %q", bad)
		}
	}
}

// TestAPIBaseRejectsNonLoopbackByIPType pins the difference from the old string
// check: 127.x is loopback by type, while a name that merely starts with "127."
// or a private address is not.
func TestAPIBaseRejectsNonLoopbackByIPType(t *testing.T) {
	for _, bad := range []string{
		"127.example.com:9000", "127.0.0.1.example.com:9000",
		"172.16.0.1:9000", "169.254.169.254:9000", "0.0.0.0:9000", "[::2]:9000",
	} {
		if _, err := apiBase(bad); err == nil {
			t.Errorf("apiBase accepted %q", bad)
		}
	}
	for _, good := range []string{"127.1.2.3:9000", "127.255.255.254:9000"} {
		if _, err := apiBase(good); err != nil {
			t.Errorf("apiBase rejected the loopback literal %q: %v", good, err)
		}
	}
}

// TestLocalhostMustResolveOnlyToLoopback proves that the name is resolved and
// every answer checked before an address is chosen to connect to.
func TestLocalhostMustResolveOnlyToLoopback(t *testing.T) {
	original := lookupHost
	t.Cleanup(func() { lookupHost = original })

	lookupHost = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("::1")}, {IP: net.ParseIP("127.0.0.1")}}, nil
	}
	target, err := resolveAPITarget("localhost:9000")
	if err != nil {
		t.Fatalf("resolveAPITarget(localhost): %v", err)
	}
	if target.dial != "127.0.0.1:9000" || target.base != "http://127.0.0.1:9000" {
		t.Errorf("target = %+v, want the verified IPv4 loopback address", target)
	}

	lookupHost = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}, {IP: net.ParseIP("192.0.2.5")}}, nil
	}
	if _, err := resolveAPITarget("localhost:9000"); err == nil || !strings.Contains(err.Error(), "not loopback") {
		t.Errorf("a mixed resolution was not refused: %v", err)
	}

	lookupHost = func(context.Context, string) ([]net.IPAddr, error) {
		return nil, nil
	}
	if _, err := resolveAPITarget("localhost:9000"); err == nil {
		t.Error("an empty resolution was accepted")
	}
}

// TestCredentialedRequestRefusesRedirects pins the two transport rules that keep
// the token local: a 3xx is not followed and the environment proxy is ignored.
func TestCredentialedRequestRefusesRedirectsAndProxy(t *testing.T) {
	var followed bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		followed = true
		if r.Header.Get("Authorization") != "" {
			t.Error("the redirect target received the bearer token")
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(other.Close)

	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/v1/status", http.StatusFound)
	}))
	t.Cleanup(core.Close)

	// A poisoned proxy would fail the request if the transport honoured it.
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("http_proxy", "http://127.0.0.1:1")

	c, err := newClient(&options{api: core.URL, token: testToken})
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	transport, ok := c.http.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || transport.DialContext == nil {
		t.Fatalf("transport is not pinned: %+v", c.http.Transport)
	}
	if c.http.CheckRedirect == nil || !errors.Is(c.http.CheckRedirect(nil, nil), http.ErrUseLastResponse) {
		t.Error("the client would follow a redirect")
	}
	var out api.StatusView
	if err := c.get(context.Background(), "/v1/status", &out); err == nil {
		t.Error("a redirect was accepted as an answer")
	}
	if followed {
		t.Error("the redirect was followed")
	}
}

// TestHistorySummaryPrintsTheStore drives "history" without a part: it describes
// the file, and it says so when the file is not being written.
func TestHistorySummaryPrintsTheStore(t *testing.T) {
	core := startCore(t, testToken, map[string]http.HandlerFunc{
		"/v1/history": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, api.HistoryView{
				Enabled:     true,
				Path:        "/var/lib/melonarc/history.sqlite3",
				Bytes:       4096,
				Connections: 3,
				Events:      2,
				Samples:     17,
				Capacity:    api.HistoryCapacityView{Connections: 2000, Events: 500, Samples: 1440},
				Flushes:     4,
				LastFlush:   "2026-01-02T15:04:05Z",
				LastError:   "no space left on device",
				Up:          1200,
				Down:        3400,
			})
		},
	})
	code, stdout, stderr := runCLI("-api", core.URL, "-token", testToken, "history")
	if code != exitOK {
		t.Fatalf("exit code = %d: %s", code, stderr)
	}
	for _, want := range []string{
		"/var/lib/melonarc/history.sqlite3",
		"4.0KB",
		"3 of 2000",
		"2 of 500",
		"17 of 1440",
		"1.2KB up",
		"3.3KB down",
		"no space left on device",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the summary does not mention %q:\n%s", want, stdout)
		}
	}
}

// TestHistorySummarySaysThereIsNone checks the answer of a core that keeps no
// history: it says so instead of printing zeroes that look like an empty file.
func TestHistorySummarySaysThereIsNone(t *testing.T) {
	core := startCore(t, testToken, map[string]http.HandlerFunc{
		"/v1/history": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, api.HistoryView{Enabled: false})
		},
	})
	code, stdout, stderr := runCLI("-api", core.URL, "-token", testToken, "history")
	if code != exitOK {
		t.Fatalf("exit code = %d: %s", code, stderr)
	}
	if !strings.Contains(stdout, "keeps no history") {
		t.Errorf("stdout = %q", stdout)
	}
}

// TestHistoryConnectionsPrintsTheWindow checks the table and the query it is read
// with: the limit and the period both reach the core.
func TestHistoryConnectionsPrintsTheWindow(t *testing.T) {
	var query string
	core := startCore(t, testToken, map[string]http.HandlerFunc{
		"/v1/history/connections": func(w http.ResponseWriter, r *http.Request) {
			query = r.URL.RawQuery
			writeJSON(w, api.ConnectionListView{Count: 1, Connections: []api.ConnectionView{{
				Time:       "2026-01-02T15:04:05Z",
				Protocol:   "http",
				Target:     "example.com:443",
				Network:    "tcp",
				Policy:     "manual",
				Outbound:   "alpha",
				Up:         512,
				Down:       2048,
				DurationMS: 1500,
			}}})
		},
	})
	code, stdout, stderr := runCLI("-api", core.URL, "-token", testToken, "-since", "2h", "history", "connections", "50")
	if code != exitOK {
		t.Fatalf("exit code = %d: %s", code, stderr)
	}
	if !strings.Contains(query, "limit=50") || !strings.Contains(query, "since=2h0m0s") {
		t.Errorf("the core was asked with %q, want the limit and the period", query)
	}
	for _, want := range []string{"TIME", "example.com:443", "manual", "alpha", "1.5s"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the table does not mention %q:\n%s", want, stdout)
		}
	}
}

// TestHistoryEventsAndTraffic checks the two remaining windows, including the
// line that sums the traffic of the period.
func TestHistoryEventsAndTraffic(t *testing.T) {
	core := startCore(t, testToken, map[string]http.HandlerFunc{
		"/v1/history/events": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, api.EventListView{Count: 2, Events: []api.EventView{
				{Time: "2026-01-02T15:04:05Z", Kind: "reload", Name: "/etc/melonarc.ini", Detail: "rules 1", OK: true},
				{Time: "2026-01-02T15:05:05Z", Kind: "reload", OK: false, Detail: "the file is broken"},
			}})
		},
		"/v1/history/traffic": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, api.TrafficListView{Count: 2, Up: 1024, Down: 3072, Samples: []api.TrafficView{
				{Time: "2026-01-02T15:04:00Z", Up: 1024, Down: 2048},
				{Time: "2026-01-02T15:05:00Z", Down: 1024},
			}})
		},
	})
	code, stdout, stderr := runCLI("-api", core.URL, "-token", testToken, "history", "events")
	if code != exitOK {
		t.Fatalf("events exited %d: %s", code, stderr)
	}
	for _, want := range []string{"KIND", "reload", "yes", "no", "the file is broken"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the event table does not mention %q:\n%s", want, stdout)
		}
	}

	code, stdout, stderr = runCLI("-api", core.URL, "-token", testToken, "history", "traffic")
	if code != exitOK {
		t.Fatalf("traffic exited %d: %s", code, stderr)
	}
	for _, want := range []string{"1.0KB", "2.0KB", "3.0KB", "2 intervals"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the traffic table does not mention %q:\n%s", want, stdout)
		}
	}
}

// TestHistoryRejectsAWindowItCannotApply keeps a flag from being accepted for a
// command that would ignore it.
func TestHistoryRejectsAWindowItCannotApply(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "since with the summary", args: []string{"-since", "1h", "history"}, want: "the summary describes the whole file"},
		{name: "a limit that is not a number", args: []string{"history", "connections", "many"}, want: "not a non-negative number"},
		{name: "two limits", args: []string{"history", "connections", "1", "2"}, want: "at most one limit"},
		{name: "a negative since", args: []string{"-since", "-1h", "history", "events"}, want: "-since must not be negative"},
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

func TestHumanBytes(t *testing.T) {
	tests := []struct {
		in   int64
		want string
	}{
		{in: 0, want: "0B"},
		{in: 999, want: "999B"},
		{in: 1024, want: "1.0KB"},
		{in: 1536, want: "1.5KB"},
		{in: 1 << 20, want: "1.0MB"},
		{in: 3 << 30, want: "3.0GB"},
	}
	for _, tc := range tests {
		if got := humanBytes(tc.in); got != tc.want {
			t.Errorf("humanBytes(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestUsageDocumentsEveryCommand keeps the arguments a command reads from being
// invisible in the help text.
func TestUsageDocumentsEveryCommand(t *testing.T) {
	code, stdout, _ := runCLI("help")
	if code != exitOK {
		t.Fatalf("exit code = %d", code)
	}
	for _, want := range []string{
		"history [what] [limit]", "-since <duration>", "-data-dir",
		"subscriptions [name] [offset] [limit]",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the usage text does not mention %q", want)
		}
	}
}

// The client reports the same string the core does. One package holds it, so a
// release build cannot have `version` and `status` disagree about which build
// is running.
func TestVersionCommandReportsTheSharedVersion(t *testing.T) {
	original := version.Version
	version.Version = "9.9.9-test"
	t.Cleanup(func() { version.Version = original })

	code, stdout, stderr := runCLI("version")
	if code != exitOK {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr)
	}
	if want := "melonarc-cli 9.9.9-test\n"; stdout != want {
		t.Fatalf("stdout = %q, want %q", stdout, want)
	}
}

// TestSubscriptionsListsWhatTheCoreKept checks the summary command: one row per
// subscription with the counts that make the detail worth asking for, and the
// last failure of a subscription that is down.
func TestSubscriptionsListsWhatTheCoreKept(t *testing.T) {
	core := startCore(t, testToken, map[string]http.HandlerFunc{
		"/v1/subscriptions": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, api.SubscriptionListView{Subscriptions: []api.SubscriptionView{
				{
					Name: "airport", Nodes: 12, Skipped: 3,
					FetchedAt: "2026-11-16T08:00:00Z", NextAt: "2026-11-16T14:00:00Z",
				},
				{Name: "spare", Attempts: 2, Error: "the server answered 502 Bad Gateway"},
			}})
		},
	})

	code, stdout, stderr := runCLI("-api", core.URL, "-token", testToken, "subscriptions")
	if code != exitOK {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr)
	}
	for _, want := range []string{
		"NAME", "NODES", "SKIPPED", "LAST REFRESH",
		"airport", "12", "3", "2026-11-16T08:00:00Z",
		"spare", "the server answered 502 Bad Gateway",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout does not mention %q:\n%s", want, stdout)
		}
	}

	// -json is the same answer the core gave, so a script can read the counts
	// without parsing a table.
	code, stdout, _ = runCLI("-api", core.URL, "-token", testToken, "-json", "subscriptions")
	if code != exitOK {
		t.Fatalf("-json exit code = %d", code)
	}
	if !strings.Contains(stdout, `"name": "airport"`) || !strings.Contains(stdout, `"skipped": 3`) {
		t.Errorf("-json stdout = %s", stdout)
	}
}

// TestSubscriptionsPagesThroughTheSkippedEntries drives the detail command: it
// prints the item numbers and reasons of one page, says how much of the list it
// covered, and hands the reader the command for the next page.
func TestSubscriptionsPagesThroughTheSkippedEntries(t *testing.T) {
	var offsets []string
	core := startCore(t, testToken, map[string]http.HandlerFunc{
		"/v1/subscriptions/airport/skipped": func(w http.ResponseWriter, r *http.Request) {
			offset := r.URL.Query().Get("offset")
			offsets = append(offsets, offset+"|"+r.URL.Query().Get("limit"))
			page := api.SkippedListView{
				Subscription: "airport",
				Refreshed:    true,
				FetchedAt:    "2026-11-16T08:00:00Z",
				Total:        12,
				Limit:        2,
			}
			switch offset {
			case "2":
				page.Offset = 2
				page.Skipped = []api.SkippedEntryView{
					{Item: 3, Reason: "unsupported link type"},
					{Item: 4, Reason: "the cipher is not implemented"},
				}
			default:
				page.Skipped = []api.SkippedEntryView{
					{Item: 1, Reason: "the cipher is not implemented"},
					{Item: 2, Reason: "unsupported link type"},
				}
			}
			writeJSON(w, page)
		},
	})

	code, stdout, stderr := runCLI("-api", core.URL, "-token", testToken, "subscriptions", "airport", "0", "2")
	if code != exitOK {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr)
	}
	for _, want := range []string{
		"ITEM", "REASON",
		"1", "the cipher is not implemented",
		"2", "unsupported link type",
		"1-2 of 12 skipped entries",
		"next: melonarc-cli subscriptions airport 2 2",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout does not mention %q:\n%s", want, stdout)
		}
	}

	code, stdout, _ = runCLI("-api", core.URL, "-token", testToken, "subscriptions", "airport", "2", "2")
	if code != exitOK {
		t.Fatalf("second page exit code = %d", code)
	}
	if !strings.Contains(stdout, "3-4 of 12 skipped entries") {
		t.Errorf("the second page does not report its window:\n%s", stdout)
	}
	if !strings.Contains(stdout, "next: melonarc-cli subscriptions airport 4 2") {
		t.Errorf("the second page does not point at the third:\n%s", stdout)
	}
	if strings.Contains(stdout, "the cipher is not implemented") && strings.Contains(stdout, "unsupported link type") {
		// Both reasons are on every page in this fixture; what must not appear
		// is the first page's item numbers.
		if strings.Contains(stdout, "\n1  ") {
			t.Errorf("the second page repeats the first:\n%s", stdout)
		}
	}
	if len(offsets) != 2 || offsets[0] != "|2" {
		t.Errorf("the first request carried offset %q, want none", offsets[0])
	}
	if offsets[1] != "2|2" {
		t.Errorf("the second request carried %q, want offset 2 and limit 2", offsets[1])
	}
}

// TestSubscriptionsKeepsTheEmptyAnswersApart covers the three ways a detail can
// be empty and the one refusal: a subscription that never refreshed, one whose
// refresh skipped nothing, an offset past the end, and a name the file does not
// declare.
func TestSubscriptionsKeepsTheEmptyAnswersApart(t *testing.T) {
	core := startCore(t, testToken, map[string]http.HandlerFunc{
		"/v1/subscriptions/fresh/skipped": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, api.SkippedListView{Subscription: "fresh"})
		},
		"/v1/subscriptions/clean/skipped": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, api.SkippedListView{Subscription: "clean", Refreshed: true, Total: 0})
		},
		"/v1/subscriptions/past/skipped": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, api.SkippedListView{
				Subscription: "past", Refreshed: true, Total: 3, Offset: 9, Limit: 5,
			})
		},
		"/v1/subscriptions/typo/skipped": func(w http.ResponseWriter, _ *http.Request) {
			writeErrorBody(w, http.StatusNotFound, "unknown_subscription", `no subscription is named "typo"`)
		},
	})

	code, stdout, _ := runCLI("-api", core.URL, "-token", testToken, "subscriptions", "fresh")
	if code != exitOK || !strings.Contains(stdout, "fresh has not completed a refresh yet") {
		t.Errorf("a never-refreshed subscription gave %d %q", code, stdout)
	}
	code, stdout, _ = runCLI("-api", core.URL, "-token", testToken, "subscriptions", "clean")
	if code != exitOK || !strings.Contains(stdout, "clean skipped no entry in its last refresh") {
		t.Errorf("a clean subscription gave %d %q", code, stdout)
	}
	code, stdout, _ = runCLI("-api", core.URL, "-token", testToken, "subscriptions", "past", "9")
	if code != exitOK || !strings.Contains(stdout, "no entry at offset 9: past skipped 3") {
		t.Errorf("an offset past the end gave %d %q", code, stdout)
	}
	code, _, stderr := runCLI("-api", core.URL, "-token", testToken, "subscriptions", "typo")
	if code != exitFailure || !strings.Contains(stderr, "unknown_subscription") {
		t.Errorf("an unknown name gave %d %q", code, stderr)
	}

	// The list itself has an empty answer of its own: a configuration without a
	// subscription is not an error.
	var emptyCore = startCore(t, testToken, map[string]http.HandlerFunc{
		"/v1/subscriptions": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, api.SubscriptionListView{})
		},
	})
	code, stdout, _ = runCLI("-api", emptyCore.URL, "-token", testToken, "subscriptions")
	if code != exitOK || !strings.Contains(stdout, "no subscription is configured") {
		t.Errorf("a configuration without subscriptions gave %d %q", code, stdout)
	}
}

// writeErrorBody writes the JSON error shape the core uses, so a test can drive
// a refused request through the client's decoder.
func writeErrorBody(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `{"error":{"code":%q,"message":%q}}`, code, message)
}
