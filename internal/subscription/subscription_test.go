package subscription

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/melon-tgj/melonarc/internal/config"
)

const testLink = "ss://" + "YWVzLTI1Ni1nY206c2VjcmV0" + "@example.com:8388#Node" // aes-256-gcm:secret

// testConfig is the smallest configuration that declares a subscription and
// points a rule at it.
func testConfig(t *testing.T, url string) *config.Config {
	t.Helper()
	text := fmt.Sprintf(`[General]
[Subscription]
airport = %s

[Rule]
FINAL,airport
`, url)
	cfg, err := config.Parse([]byte(text))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	return cfg
}

func TestImportMergesPlainTextBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s\n\n# a comment\n%s\n", testLink, testLink)
	}))
	defer server.Close()

	cfg := testConfig(t, server.URL)
	mgr := New(Options{})
	if err := mgr.Import(context.Background(), cfg); err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(cfg.Proxies) != 2 {
		t.Fatalf("proxies = %d, want 2", len(cfg.Proxies))
	}
	group, ok := cfg.GroupByName("airport")
	if !ok {
		t.Fatal("the subscription group is missing")
	}
	if len(group.Members) != 2 {
		t.Fatalf("group members = %v", group.Members)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("imported configuration does not validate: %v", err)
	}
}

func TestImportMergesBase64Body(t *testing.T) {
	body := base64.StdEncoding.EncodeToString([]byte(testLink + "\n" + testLink + "\n"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Providers wrap the base64 at 76 columns; the decoder has to cope.
		for i := 0; i < len(body); i += 76 {
			end := i + 76
			if end > len(body) {
				end = len(body)
			}
			fmt.Fprintln(w, body[i:end])
		}
	}))
	defer server.Close()

	cfg := testConfig(t, server.URL)
	if err := New(Options{}).Import(context.Background(), cfg); err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(cfg.Proxies) != 2 {
		t.Fatalf("proxies = %d, want 2", len(cfg.Proxies))
	}
}

// TestImportKeepsThePreviousNodesOnFailure is the retention rule: a refresh that
// fails must leave the nodes in force untouched, and schedule the next attempt
// further out.
func TestImportKeepsThePreviousNodesOnFailure(t *testing.T) {
	failing := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failing {
			http.Error(w, "nope", http.StatusBadGateway)
			return
		}
		fmt.Fprintln(w, testLink)
	}))
	defer server.Close()

	now := time.Unix(1700000000, 0)
	mgr := New(Options{Now: func() time.Time { return now }})
	cfg := testConfig(t, server.URL)
	if err := mgr.Import(context.Background(), cfg); err != nil {
		t.Fatalf("first import: %v", err)
	}

	failing = true
	now = now.Add(7 * time.Hour) // past the interval, so a refresh is due
	cfg = testConfig(t, server.URL)
	if err := mgr.Import(context.Background(), cfg); err != nil {
		t.Fatalf("import after a failure: %v", err)
	}
	if len(cfg.Proxies) != 1 {
		t.Fatalf("proxies = %d, want the previous node to be kept", len(cfg.Proxies))
	}
	status := mgr.Snapshot()[0]
	if status.Attempts != 1 || status.Error == "" {
		t.Fatalf("status = %+v, want one failed attempt", status)
	}
	if !status.NextAt.After(now) {
		t.Fatalf("next attempt at %s is not in the future", status.NextAt)
	}
	if got := status.NextAt.Sub(now); got != retryBaseDelay {
		t.Fatalf("retry delay = %s, want %s", got, retryBaseDelay)
	}
}

// TestImportFallsBackToTheCache covers a restart on a network that is down: the
// body from the last successful run is on disk, and it is what the rules and
// groups need.
func TestImportFallsBackToTheCache(t *testing.T) {
	dir := t.TempDir()
	up := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !up {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintln(w, testLink)
	}))
	defer server.Close()

	if err := New(Options{CacheDir: dir}).Import(context.Background(), testConfig(t, server.URL)); err != nil {
		t.Fatalf("first import: %v", err)
	}

	up = false
	// A new manager has no memory, which is what a restart looks like.
	cfg := testConfig(t, server.URL)
	if err := New(Options{CacheDir: dir}).Import(context.Background(), cfg); err != nil {
		t.Fatalf("import from the cache: %v", err)
	}
	if len(cfg.Proxies) != 1 {
		t.Fatalf("proxies = %d, want 1 from the cache", len(cfg.Proxies))
	}
}

func TestImportWithoutAnySourceFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	cfg := testConfig(t, server.URL)
	err := New(Options{}).Import(context.Background(), cfg)
	if err == nil {
		t.Fatal("import succeeded with no fetch and no cache")
	}
	if !strings.Contains(err.Error(), "airport") {
		t.Fatalf("error %q does not name the subscription", err)
	}
}

func TestImportRejectsABodyWithoutLinks(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "# only a comment")
	}))
	defer server.Close()

	err := New(Options{}).Import(context.Background(), testConfig(t, server.URL))
	if err == nil {
		t.Fatal("import accepted a body with no link")
	}
	if !errors.Is(err, ErrEmpty) {
		t.Fatalf("error = %v, want ErrEmpty", err)
	}
	if !strings.Contains(err.Error(), "airport") {
		t.Fatalf("error %q does not name the subscription", err)
	}
}

// TestResolveRespectsTheInterval checks that a reload inside the interval does
// not talk to the network again.
func TestResolveRespectsTheInterval(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		fmt.Fprintln(w, testLink)
	}))
	defer server.Close()

	now := time.Unix(1700000000, 0)
	mgr := New(Options{Now: func() time.Time { return now }})
	entry := config.Subscription{Name: "airport", URL: server.URL, Interval: 6 * time.Hour}

	if _, err := mgr.resolve(context.Background(), entry); err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	now = now.Add(time.Hour)
	if _, err := mgr.resolve(context.Background(), entry); err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want 1: a reload inside the interval must reuse the result", requests)
	}
	now = now.Add(6 * time.Hour)
	if _, err := mgr.resolve(context.Background(), entry); err != nil {
		t.Fatalf("third resolve: %v", err)
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want 2: the interval has passed", requests)
	}
}

// TestRefreshDueReportsAChange is what drives a rebuild: only a change in the
// node list may restart the runtime.
func TestRefreshDueReportsAChange(t *testing.T) {
	second := "ss://" + "YWVzLTEyOC1nY206b3RoZXI" + "@other.example.com:8388#Other"
	body := testLink
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, body)
	}))
	defer server.Close()

	now := time.Unix(1700000000, 0)
	mgr := New(Options{Now: func() time.Time { return now }})
	cfg := testConfig(t, server.URL)
	if err := mgr.Import(context.Background(), cfg); err != nil {
		t.Fatalf("import: %v", err)
	}

	now = now.Add(7 * time.Hour)
	if mgr.refreshDue(context.Background()) {
		t.Fatal("an unchanged list reported a change")
	}

	body = second
	now = now.Add(7 * time.Hour)
	if !mgr.refreshDue(context.Background()) {
		t.Fatal("a changed list did not report a change")
	}
}

func TestRetryDelayBacksOffAndStopsAtTheInterval(t *testing.T) {
	cases := []struct {
		attempts int
		interval time.Duration
		want     time.Duration
	}{
		{1, 6 * time.Hour, retryBaseDelay},
		{2, 6 * time.Hour, 2 * retryBaseDelay},
		{3, 6 * time.Hour, 4 * retryBaseDelay},
		{100, 6 * time.Hour, maxRetryDelay},
		{100, time.Minute, time.Minute}, // never longer than the interval
	}
	for _, tc := range cases {
		if got := retryDelay(tc.attempts, tc.interval); got != tc.want {
			t.Fatalf("retryDelay(%d, %s) = %s, want %s", tc.attempts, tc.interval, got, tc.want)
		}
	}
}

func TestParseBodySkipsNoise(t *testing.T) {
	body := "\ufeff" + testLink + "\r\n\r\n// provider notice\r\n  \r\n" + testLink + "\r\n"
	proxies, err := parseBody([]byte(body))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(proxies) != 2 {
		t.Fatalf("proxies = %d, want 2", len(proxies))
	}
}

func TestParseBodyReportsABadLink(t *testing.T) {
	_, err := parseBody([]byte(testLink + "\nwireguard://key@host:1\n"))
	if err == nil {
		t.Fatal("parse accepted an unsupported link")
	}
	if !strings.Contains(err.Error(), "wireguard") {
		t.Fatalf("error = %v", err)
	}
}
