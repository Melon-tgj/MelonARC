package api

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

// TestHistorySummaryIsServed checks the summary endpoint carries what a client
// needs to tell a history that is empty from one that is not being written.
func TestHistorySummaryIsServed(t *testing.T) {
	want := HistoryView{
		Enabled:     true,
		Path:        "/var/lib/melonarc/history.sqlite3",
		Bytes:       4096,
		Connections: 3,
		Events:      2,
		Samples:     1440,
		Capacity:    HistoryCapacityView{Connections: 2000, Events: 500, Samples: 1440},
		Flushes:     7,
		LastFlush:   "2026-01-02T15:04:05Z",
		Up:          1200,
		Down:        3400,
	}
	s := newTestServer(t, &fakeProvider{history: want})

	got := decode[HistoryView](t, request(t, s, http.MethodGet, "/v1/history", "test-token"))
	if got != want {
		t.Errorf("history = %+v, want %+v", got, want)
	}
}

// TestHistoryWindowIsParsed checks that limit and since reach the provider: a
// count narrows the page, a duration says how far back, and a timestamp says
// from when.
func TestHistoryWindowIsParsed(t *testing.T) {
	provider := &fakeProvider{}
	s := newTestServer(t, provider)

	decode[ConnectionListView](t, request(t, s, http.MethodGet, "/v1/history/connections?limit=25", "test-token"))
	if provider.lastHistory.limit != 25 {
		t.Errorf("limit = %d, want 25", provider.lastHistory.limit)
	}
	if !provider.lastHistory.since.IsZero() {
		t.Errorf("since = %v, want none", provider.lastHistory.since)
	}

	before := time.Now().Add(-time.Hour)
	decode[ConnectionListView](t, request(t, s, http.MethodGet, "/v1/history/connections?since=1h", "test-token"))
	after := time.Now().Add(-time.Hour)
	if since := provider.lastHistory.since; since.Before(before) || since.After(after) {
		t.Errorf("since = %v, want the hour before the request (%v..%v)", since, before, after)
	}

	instant := time.Date(2026, 1, 2, 15, 4, 5, 0, time.UTC)
	decode[ConnectionListView](t, request(t, s, http.MethodGet,
		"/v1/history/connections?since="+instant.Format(time.RFC3339), "test-token"))
	if !provider.lastHistory.since.Equal(instant) {
		t.Errorf("since = %v, want %v", provider.lastHistory.since, instant)
	}

	// The same window applies to the other two record endpoints.
	decode[TrafficListView](t, request(t, s, http.MethodGet, "/v1/history/traffic?limit=5&since=30m", "test-token"))
	if provider.lastHistory.limit != 5 || provider.lastHistory.since.IsZero() {
		t.Errorf("traffic window = %+v, want five samples of the last half hour", provider.lastHistory)
	}
}

// TestHistoryEventsPassTheKind checks the kind filter, which is what turns the
// endpoint into "show me the reloads".
func TestHistoryEventsPassTheKind(t *testing.T) {
	provider := &fakeProvider{events: EventListView{Count: 1, Events: []EventView{{Kind: "reload"}}}}
	s := newTestServer(t, provider)

	got := decode[EventListView](t, request(t, s, http.MethodGet, "/v1/history/events?kind=reload", "test-token"))
	if provider.lastHistory.kind != "reload" {
		t.Errorf("kind = %q, want reload", provider.lastHistory.kind)
	}
	if got.Count != 1 || got.Events[0].Kind != "reload" {
		t.Errorf("events = %+v", got)
	}

	// Whitespace is not a kind: it is trimmed away, and an empty filter means
	// every kind.
	decode[EventListView](t, request(t, s, http.MethodGet, "/v1/history/events?kind=%20reload%20", "test-token"))
	if provider.lastHistory.kind != "reload" {
		t.Errorf("kind = %q, want the trimmed reload", provider.lastHistory.kind)
	}
}

// TestHistoryRejectsWhatItCannotRead keeps a mistyped query from being answered
// with a silently different window.
func TestHistoryRejectsWhatItCannotRead(t *testing.T) {
	s := newTestServer(t, &fakeProvider{})
	tests := []struct {
		name   string
		target string
	}{
		{name: "a since that is not a time", target: "/v1/history/connections?since=yesterday"},
		{name: "a since that is negative", target: "/v1/history/connections?since=-1h"},
		{name: "a since that is zero", target: "/v1/history/connections?since=0s"},
		{name: "a limit that is not a number", target: "/v1/history/traffic?limit=many"},
		{name: "a negative limit", target: "/v1/history/events?limit=-5"},
		{name: "a kind that cannot exist", target: "/v1/history/events?kind=" + longKind()},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := request(t, s, http.MethodGet, tc.target, "test-token")
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("%s answered %d, want 400", tc.target, rec.Code)
			}
			body := decode[errorView](t, rec)
			if body.Error.Code != "bad_request" || body.Error.Message == "" {
				t.Errorf("error = %+v, want a bad_request with a message", body.Error)
			}
		})
	}
}

// longKind is a kind filter longer than the endpoint accepts.
func longKind() string {
	out := make([]byte, maxEventKind+1)
	for i := range out {
		out[i] = 'x'
	}
	return string(out)
}

// TestHistoryListsAreNeverNull checks the JSON shape of an empty answer. A
// client that has to test for null before iterating is a client that will
// forget to.
func TestHistoryListsAreNeverNull(t *testing.T) {
	s := newTestServer(t, &fakeProvider{})
	for _, path := range []string{"/v1/history/connections", "/v1/history/events", "/v1/history/traffic"} {
		rec := request(t, s, http.MethodGet, path, "test-token")
		var body map[string]json.RawMessage
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
		for key, raw := range body {
			if len(raw) > 0 && raw[0] == 'n' {
				t.Errorf("%s answered %s: null, want an empty list", path, key)
			}
		}
	}
}

// TestHistoryEndpointsRejectOtherMethods keeps the transport contract of the
// endpoints added in this stage the same as the rest.
func TestHistoryEndpointsRejectOtherMethods(t *testing.T) {
	s := newTestServer(t, &fakeProvider{})
	for _, path := range []string{
		"/v1/history",
		"/v1/history/connections",
		"/v1/history/events",
		"/v1/history/traffic",
	} {
		rec := request(t, s, http.MethodPost, path, "test-token")
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("POST %s gave %d, want 405", path, rec.Code)
		}
		if got := rec.Header().Get("Allow"); got != http.MethodGet {
			t.Errorf("POST %s Allow = %q", path, got)
		}
	}
}

// TestHistoryNeedsTheToken checks that the endpoints are behind the same
// authentication as everything else: the history says where a machine connects.
func TestHistoryNeedsTheToken(t *testing.T) {
	s := newTestServer(t, &fakeProvider{})
	for _, path := range []string{
		"/v1/history",
		"/v1/history/connections",
		"/v1/history/events",
		"/v1/history/traffic",
	} {
		if rec := request(t, s, http.MethodGet, path, ""); rec.Code != http.StatusUnauthorized {
			t.Errorf("GET %s without a token gave %d, want 401", path, rec.Code)
		}
	}
}
