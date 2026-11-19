package subscription

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/melon-tgj/melonarc/internal/config"
)

const testLink = "ss://" + "YWVzLTI1Ni1nY206c2VjcmV0" + "@example.com:8388#Node" // aes-256-gcm:secret

// badStaticLink has the shape of a good ss link but names a cipher the outbound
// registry does not implement. It is the kind of node that used to parse and
// then break startup; now the importer rejects it with a reason.
const badStaticLink = "ss://aes-999:pw@bad.example.com:8388#Bad"

const unsupportedLink = "wireguard://key@host:1"

// mixedBody is a provider's list with two good nodes, one bad static parameter
// and one link type the importer does not know.
func mixedBody() string {
	return strings.Join([]string{testLink, badStaticLink, unsupportedLink, testLink}, "\n") + "\n"
}

func allBadBody() string {
	return badStaticLink + "\n" + unsupportedLink + "\n"
}

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
	proxies, skips, err := parseBody([]byte(body))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(proxies) != 2 {
		t.Fatalf("proxies = %d, want 2", len(proxies))
	}
	if len(skips) != 0 {
		t.Fatalf("skips = %+v, want none", skips)
	}
}

// TestParseBodyKeepsTheValidEntriesAndReportsEachSkip is the mixed-body rule:
// the good nodes survive, every bad item is named by its position and reason,
// and the body as a whole is not a failure.
func TestParseBodyKeepsTheValidEntriesAndReportsEachSkip(t *testing.T) {
	proxies, skips, err := parseBody([]byte(mixedBody()))
	if err != nil {
		t.Fatalf("a mixed body is not a failed refresh: %v", err)
	}
	if len(proxies) != 2 {
		t.Fatalf("proxies = %d, want the 2 valid nodes", len(proxies))
	}
	if len(skips) != 2 {
		t.Fatalf("skips = %+v, want 2", skips)
	}
	if skips[0].Item != 2 || !strings.Contains(skips[0].Reason, "unsupported cipher") {
		t.Errorf("first skip = %+v, want item 2 with the registry's cipher reason", skips[0])
	}
	if skips[1].Item != 3 || !strings.Contains(skips[1].Reason, "wireguard") {
		t.Errorf("second skip = %+v, want item 3 with an unsupported type", skips[1])
	}
	for _, skip := range skips {
		if strings.Contains(skip.Reason, "bad.example.com") || strings.Contains(skip.Reason, "pw@") {
			t.Errorf("a skip reason quotes the link: %q", skip.Reason)
		}
	}
}

func TestParseBodyFailsWhenEveryLinkIsInvalid(t *testing.T) {
	proxies, skips, err := parseBody([]byte(allBadBody()))
	if !errors.Is(err, ErrEmpty) {
		t.Fatalf("error = %v, want an empty-subscription failure", err)
	}
	if len(proxies) != 0 {
		t.Fatalf("proxies = %d, want none", len(proxies))
	}
	if len(skips) != 2 {
		t.Fatalf("skips = %+v, want a reason per entry", skips)
	}
}

// TestImportUsesTheValidNodesOfAMixedBody drives the same rule through Import:
// a provider that mixes good and bad links still produces a usable
// configuration, and the skipped entries are visible in the manager's status.
func TestImportUsesTheValidNodesOfAMixedBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(mixedBody()))
	}))
	defer server.Close()

	mgr := New(Options{})
	cfg := testConfig(t, server.URL)
	if err := mgr.Import(context.Background(), cfg); err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(cfg.Proxies) != 2 {
		t.Fatalf("proxies = %d, want the 2 valid nodes", len(cfg.Proxies))
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the imported configuration does not validate: %v", err)
	}
	status := mgr.Snapshot()[0]
	if status.Nodes != 2 || status.Error != "" {
		t.Fatalf("status = %+v, want a successful refresh of 2 nodes", status)
	}
	if len(status.Skipped) != 2 || status.Skipped[0].Item != 2 || status.Skipped[1].Item != 3 {
		t.Fatalf("skipped = %+v, want items 2 and 3", status.Skipped)
	}
}

// TestRefreshReportsEachSkippedEntry checks the operator's view: one log line
// per skipped entry, carrying the item number and the reason, and no link.
func TestRefreshReportsEachSkippedEntry(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(mixedBody()))
	}))
	defer server.Close()

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	mgr := New(Options{Logger: logger})
	if err := mgr.Import(context.Background(), testConfig(t, server.URL)); err != nil {
		t.Fatalf("import: %v", err)
	}
	for _, want := range []string{
		"subscription entry skipped", "item=2", "item=3",
		"unsupported cipher", "unsupported link type",
	} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("the log does not mention %q:\n%s", want, logs.String())
		}
	}
	if strings.Contains(logs.String(), "bad.example.com") {
		t.Errorf("the log quotes a rejected link:\n%s", logs.String())
	}
}

// TestImportKeepsThePreviousNodesWhenEveryLinkIsInvalid is the retention rule
// for a refresh where nothing is usable: the nodes in force stay, the cache is
// left alone, and the attempt is counted and backed off.
func TestImportKeepsThePreviousNodesWhenEveryLinkIsInvalid(t *testing.T) {
	bad := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if bad {
			_, _ = w.Write([]byte(allBadBody()))
			return
		}
		fmt.Fprintln(w, testLink)
	}))
	defer server.Close()

	now := time.Unix(1700000000, 0)
	mgr := New(Options{Now: func() time.Time { return now }})
	if err := mgr.Import(context.Background(), testConfig(t, server.URL)); err != nil {
		t.Fatalf("first import: %v", err)
	}

	bad = true
	now = now.Add(7 * time.Hour) // past the interval, so a refresh is due
	cfg := testConfig(t, server.URL)
	if err := mgr.Import(context.Background(), cfg); err != nil {
		t.Fatalf("import after an all-invalid refresh: %v", err)
	}
	if len(cfg.Proxies) != 1 {
		t.Fatalf("proxies = %d, want the previous node to be kept", len(cfg.Proxies))
	}
	status := mgr.Snapshot()[0]
	if status.Attempts != 1 || !strings.Contains(status.Error, "rejected") {
		t.Fatalf("status = %+v, want one failed attempt with a reason", status)
	}
	if !status.NextAt.After(now) || status.NextAt.Sub(now) != retryBaseDelay {
		t.Fatalf("next attempt = %s, want a %s backoff", status.NextAt, retryBaseDelay)
	}
}

// TestImportFallsBackToTheCacheWhenEveryLinkIsInvalid covers a restart whose
// first refresh is entirely bad: the body from the last good run is still on
// disk, and the bad body must not overwrite it.
func TestImportFallsBackToTheCacheWhenEveryLinkIsInvalid(t *testing.T) {
	dir := t.TempDir()
	good := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !good {
			_, _ = w.Write([]byte(allBadBody()))
			return
		}
		fmt.Fprintln(w, testLink)
	}))
	defer server.Close()

	if err := New(Options{CacheDir: dir}).Import(context.Background(), testConfig(t, server.URL)); err != nil {
		t.Fatalf("first import: %v", err)
	}
	cachePath := New(Options{CacheDir: dir}).cachePath("airport")
	before, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatalf("read the cache: %v", err)
	}

	good = false
	cfg := testConfig(t, server.URL)
	if err := New(Options{CacheDir: dir}).Import(context.Background(), cfg); err != nil {
		t.Fatalf("import from the cache: %v", err)
	}
	if len(cfg.Proxies) != 1 {
		t.Fatalf("proxies = %d, want 1 from the cache", len(cfg.Proxies))
	}
	after, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatalf("read the cache again: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("the all-invalid body overwrote the cache:\nbefore %q\nafter  %q", before, after)
	}
}

// TestImportWithoutAnyUsableLinkOnFirstImportFails is the case with nothing to
// fall back to: no previous nodes and no cache, so the error names the
// subscription and no group is left pointing at an empty list.
func TestImportWithoutAnyUsableLinkOnFirstImportFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(allBadBody()))
	}))
	defer server.Close()

	cfg := testConfig(t, server.URL)
	err := New(Options{}).Import(context.Background(), cfg)
	if err == nil {
		t.Fatal("import succeeded with a body that has no usable node")
	}
	if !strings.Contains(err.Error(), "airport") || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("error %q does not name the subscription and the reason", err)
	}
	if len(cfg.Proxies) != 0 {
		t.Fatalf("proxies = %d, want none", len(cfg.Proxies))
	}
}

// ------------------------------------------------------- the retained detail

// skippedBody is a provider's list with bad entries followed by one good node:
// twelve positions are rejected, the thirteenth is imported. The two kinds of
// rejection alternate so a page can be checked position by position.
func skippedBody() string {
	var lines []string
	for i := 0; i < 6; i++ {
		lines = append(lines, badStaticLink, unsupportedLink)
	}
	lines = append(lines, testLink)
	return strings.Join(lines, "\n") + "\n"
}

// serveBody starts a provider that answers with body until the test changes it.
func serveBody(t *testing.T, body *string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(*body))
	}))
	t.Cleanup(server.Close)
	return server
}

// TestSkippedDetailIsCompleteAndReadsInPages is the endpoint's contract: the
// detail is the whole list of the last refresh, not the first eight lines the
// log carried, and a page is a window of it that reports the total separately.
func TestSkippedDetailIsCompleteAndReadsInPages(t *testing.T) {
	body := skippedBody()
	server := serveBody(t, &body)
	mgr := New(Options{})
	if err := mgr.Import(context.Background(), testConfig(t, server.URL)); err != nil {
		t.Fatalf("import: %v", err)
	}

	const total = 12
	first, ok := mgr.Skipped("airport", 0, 5)
	if !ok {
		t.Fatal("the manager does not know the subscription it just imported")
	}
	if !first.Refreshed || first.FetchedAt.IsZero() {
		t.Fatalf("page = %+v, want a completed refresh", first)
	}
	if first.Total != total || first.Offset != 0 || first.Limit != 5 || len(first.Items) != 5 {
		t.Fatalf("first page = total %d, offset %d, limit %d, %d items",
			first.Total, first.Offset, first.Limit, len(first.Items))
	}
	if first.Items[0].Item != 1 || !strings.Contains(first.Items[0].Reason, "unsupported cipher") {
		t.Errorf("first entry = %+v, want item 1 with the cipher reason", first.Items[0])
	}
	if first.Items[1].Item != 2 || !strings.Contains(first.Items[1].Reason, "unsupported link type") {
		t.Errorf("second entry = %+v, want item 2 with the link-type reason", first.Items[1])
	}

	// The middle page crosses no boundary of its own: it is offset 5, five
	// items, and the positions keep being the body's, not the page's.
	second, _ := mgr.Skipped("airport", 5, 5)
	if second.Total != total || second.Offset != 5 || len(second.Items) != 5 {
		t.Fatalf("second page = %+v", second)
	}
	if second.Items[0].Item != 6 || second.Items[4].Item != 10 {
		t.Errorf("second page covers items %d..%d, want 6..10", second.Items[0].Item, second.Items[4].Item)
	}

	// The last page is short, and says so by returning fewer items than the
	// page size it was asked for.
	last, _ := mgr.Skipped("airport", 10, 5)
	if last.Total != total || len(last.Items) != 2 || last.Items[1].Item != 12 {
		t.Fatalf("last page = %+v, want items 11 and 12", last)
	}

	// Past the end is an empty window, not a failure: the total still tells a
	// client that it walked off the list rather than that the list is empty.
	past, _ := mgr.Skipped("airport", 50, 5)
	if past.Total != total || past.Offset != 50 || len(past.Items) != 0 {
		t.Fatalf("past-the-end page = %+v", past)
	}
	if past.Items == nil {
		t.Error("an empty page carries an empty list, not a nil one")
	}
}

// TestSkippedDetailUsesADefaultPageAndCapsALargeOne pins the two page sizes a
// caller does not control: no limit means the default page, and a limit past
// the cap is clamped rather than turned into the whole list.
func TestSkippedDetailUsesADefaultPageAndCapsALargeOne(t *testing.T) {
	body := skippedBody()
	server := serveBody(t, &body)
	mgr := New(Options{})
	if err := mgr.Import(context.Background(), testConfig(t, server.URL)); err != nil {
		t.Fatalf("import: %v", err)
	}

	if page, _ := mgr.Skipped("airport", 0, 0); page.Limit != DefaultSkippedPage || len(page.Items) != 12 {
		t.Fatalf("no limit gave limit %d and %d items", page.Limit, len(page.Items))
	}
	if page, _ := mgr.Skipped("airport", 0, 10_000); page.Limit != MaxSkippedPage {
		t.Fatalf("a huge limit gave limit %d, want the cap %d", page.Limit, MaxSkippedPage)
	}
	if page, _ := mgr.Skipped("airport", -3, 5); page.Offset != 0 || len(page.Items) != 5 {
		t.Fatalf("a negative offset gave %+v", page)
	}
}

// TestClampSkippedPageIsTheOneWindowRule pins the exported clamp, because the
// daemon layer applies it to the empty page it serves for a subscription the
// manager has not seen: both answers have to name the same window.
func TestClampSkippedPageIsTheOneWindowRule(t *testing.T) {
	cases := []struct{ offset, limit, wantOffset, wantLimit int }{
		{0, 0, 0, DefaultSkippedPage},
		{0, -1, 0, DefaultSkippedPage},
		{-7, 25, 0, 25},
		{0, 10_000, 0, MaxSkippedPage},
		{0, MaxSkippedPage, 0, MaxSkippedPage},
		{40, 500, 40, 500},
	}
	for _, c := range cases {
		offset, limit := ClampSkippedPage(c.offset, c.limit)
		if offset != c.wantOffset || limit != c.wantLimit {
			t.Fatalf("ClampSkippedPage(%d, %d) = (%d, %d), want (%d, %d)",
				c.offset, c.limit, offset, limit, c.wantOffset, c.wantLimit)
		}
	}
}

// TestSkippedDetailIsReplacedByTheNextCompletedRefresh is the retention rule in
// the success direction: the detail always describes the body in force, so a
// fixed list stops looking broken and a partly broken one starts.
func TestSkippedDetailIsReplacedByTheNextCompletedRefresh(t *testing.T) {
	body := skippedBody()
	server := serveBody(t, &body)
	now := time.Unix(1700000000, 0)
	mgr := New(Options{Now: func() time.Time { return now }})
	if err := mgr.Import(context.Background(), testConfig(t, server.URL)); err != nil {
		t.Fatalf("first import: %v", err)
	}
	firstFetched := mgr.Snapshot()[0].FetchedAt

	body = testLink + "\n" + testLink + "\n"
	now = now.Add(7 * time.Hour)
	if err := mgr.Import(context.Background(), testConfig(t, server.URL)); err != nil {
		t.Fatalf("second import: %v", err)
	}
	page, _ := mgr.Skipped("airport", 0, 10)
	if page.Total != 0 || len(page.Items) != 0 {
		t.Fatalf("a clean body left %d entries behind: %+v", page.Total, page.Items)
	}
	if !page.FetchedAt.After(firstFetched) {
		t.Errorf("detail still claims to be from %s, the first refresh", page.FetchedAt)
	}

	body = unsupportedLink + "\n" + testLink + "\n"
	now = now.Add(7 * time.Hour)
	if err := mgr.Import(context.Background(), testConfig(t, server.URL)); err != nil {
		t.Fatalf("third import: %v", err)
	}
	page, _ = mgr.Skipped("airport", 0, 10)
	if page.Total != 1 || len(page.Items) != 1 || page.Items[0].Item != 1 {
		t.Fatalf("the third body's one bad entry is not the detail: %+v", page)
	}
}

// TestSkippedDetailIsKeptWhenARefreshFails is the other half of the rule: a
// refresh that failed kept the nodes, so it keeps the detail that describes
// them, and it does not claim to have refreshed anything.
func TestSkippedDetailIsKeptWhenARefreshFails(t *testing.T) {
	body := skippedBody()
	server := serveBody(t, &body)
	now := time.Unix(1700000000, 0)
	mgr := New(Options{Now: func() time.Time { return now }})
	if err := mgr.Import(context.Background(), testConfig(t, server.URL)); err != nil {
		t.Fatalf("first import: %v", err)
	}
	before, _ := mgr.Skipped("airport", 0, 50)

	body = allBadBody()
	now = now.Add(7 * time.Hour)
	cfg := testConfig(t, server.URL)
	if err := mgr.Import(context.Background(), cfg); err != nil {
		t.Fatalf("an all-invalid refresh keeps the previous nodes: %v", err)
	}
	after, ok := mgr.Skipped("airport", 0, 50)
	if !ok {
		t.Fatal("the subscription disappeared after a failed refresh")
	}
	if after.Total != before.Total || len(after.Items) != len(before.Items) {
		t.Fatalf("the failed body replaced the detail: %d entries, want %d", after.Total, before.Total)
	}
	if !after.FetchedAt.Equal(before.FetchedAt) {
		t.Errorf("detail moved to %s, want it to stay at %s", after.FetchedAt, before.FetchedAt)
	}
	for i, item := range after.Items {
		if item != before.Items[i] {
			t.Fatalf("entry %d changed to %+v, want %+v", i, item, before.Items[i])
		}
	}
	if status := mgr.Snapshot()[0]; status.Attempts != 1 || status.Error == "" {
		t.Fatalf("status = %+v, want the failed attempt recorded next to the kept detail", status)
	}
}

// TestSkippedDetailOutlivesTheLogCap separates the two bounds: the log stops at
// eight lines and counts the rest, while the detail keeps every entry so the
// endpoint can page through them.
func TestSkippedDetailOutlivesTheLogCap(t *testing.T) {
	body := skippedBody()
	server := serveBody(t, &body)
	var logs bytes.Buffer
	mgr := New(Options{Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	if err := mgr.Import(context.Background(), testConfig(t, server.URL)); err != nil {
		t.Fatalf("import: %v", err)
	}

	if got := strings.Count(logs.String(), "subscription entry skipped"); got != maxReportedSkips {
		t.Errorf("%d per-entry lines, want the log bound of %d:\n%s", got, maxReportedSkips, logs.String())
	}
	if !strings.Contains(logs.String(), "count=4") {
		t.Errorf("the log does not count the entries it did not name:\n%s", logs.String())
	}
	page, _ := mgr.Skipped("airport", 0, 50)
	if page.Total != 12 {
		t.Fatalf("detail holds %d entries, want all 12", page.Total)
	}
	if len(mgr.Snapshot()[0].Skipped) != 12 {
		t.Fatalf("status carries %d entries, want all 12", len(mgr.Snapshot()[0].Skipped))
	}
}

// TestSkippedDetailOfAnUnknownName keeps "no such subscription" apart from
// "nothing was skipped", which is what lets the API answer 404 rather than an
// empty page.
func TestSkippedDetailOfAnUnknownName(t *testing.T) {
	body := skippedBody()
	server := serveBody(t, &body)
	mgr := New(Options{})
	if err := mgr.Import(context.Background(), testConfig(t, server.URL)); err != nil {
		t.Fatalf("import: %v", err)
	}
	if page, ok := mgr.Skipped("typo", 0, 10); ok {
		t.Fatalf("an unknown name answered a page: %+v", page)
	}
	if _, ok := mgr.Status("typo"); ok {
		t.Fatal("an unknown name answered a status")
	}
	if _, ok := mgr.Status("airport"); !ok {
		t.Fatal("a known name answered no status")
	}
}

// TestSkippedDetailBeforeAnyRefreshCompleted covers the state a subscription is
// in when its very first fetch failed: it is known, it has no detail, and it
// says so instead of pretending the last refresh skipped nothing.
func TestSkippedDetailBeforeAnyRefreshCompleted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	mgr := New(Options{})
	if err := mgr.Import(context.Background(), testConfig(t, server.URL)); err == nil {
		t.Fatal("a first fetch that failed was reported as an import")
	}
	page, ok := mgr.Skipped("airport", 0, 10)
	if !ok {
		t.Fatal("the manager forgot a subscription it just failed to fetch")
	}
	if page.Refreshed || !page.FetchedAt.IsZero() || page.Total != 0 || len(page.Items) != 0 {
		t.Fatalf("page = %+v, want an explicit never-refreshed answer", page)
	}
}
