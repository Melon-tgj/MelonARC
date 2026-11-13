package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// TestInboundEndpoint checks the runtime picture of the listeners, including
// the case where the daemon has no counters at all.
func TestInboundEndpoint(t *testing.T) {
	p := &fakeProvider{inbound: InboundView{
		Inbounds: []InboundStatsView{
			{Protocol: "http", Open: 1, Accepted: 4},
			{Protocol: "socks5", Open: 2, Accepted: 9, Datagrams: 1, DatagramsTotal: 3},
		},
		Open:               3,
		Accepted:           13,
		Failures:           2,
		Rejected:           1,
		FailureLogCapacity: 64,
		FailureLogCount:    3,
	}}
	s := newTestServer(t, p)
	rec := request(t, s, http.MethodGet, "/v1/inbound", "test-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
	}
	body := decode[InboundView](t, rec)
	if len(body.Inbounds) != 2 {
		t.Fatalf("inbounds = %+v", body.Inbounds)
	}
	if body.Inbounds[1].Protocol != "socks5" || body.Inbounds[1].Datagrams != 1 {
		t.Fatalf("socks5 counters = %+v", body.Inbounds[1])
	}
	if body.Open != 3 || body.Accepted != 13 || body.Failures != 2 || body.Rejected != 1 {
		t.Fatalf("totals = %+v", body)
	}
	if body.FailureLogCapacity != 64 || body.FailureLogCount != 3 {
		t.Fatalf("failure log = %d/%d", body.FailureLogCount, body.FailureLogCapacity)
	}

	// The JSON names are the contract the UI codes against.
	raw := rec.Body.String()
	for _, want := range []string{
		`"inbounds"`, `"open"`, `"accepted"`, `"datagram_associations"`,
		`"datagram_associations_total"`, `"failures"`, `"rejected"`,
		`"failure_log_capacity"`, `"failure_log_count"`,
	} {
		if !strings.Contains(raw, want) {
			t.Errorf("response has no %s: %s", want, raw)
		}
	}
}

// TestInboundEmptyIsAnArray keeps the shape stable when no listener is bound.
func TestInboundEmptyIsAnArray(t *testing.T) {
	s := newTestServer(t, &fakeProvider{})
	rec := request(t, s, http.MethodGet, "/v1/inbound", "test-token")
	var body map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := string(body["inbounds"]); got != "[]" {
		t.Fatalf("inbounds = %s, want []", got)
	}
}

// TestFailuresEndpoint checks the record, its fields and the limit parameter.
func TestFailuresEndpoint(t *testing.T) {
	p := &fakeProvider{failures: FailureListView{
		Capacity: 64,
		Count:    2,
		Failures: []FailureView{
			{Time: "2026-11-13T12:00:00Z", Target: "a.example:443", Network: "tcp", Stage: "dial", Category: "refused", Policy: "auto"},
			{Time: "2026-11-13T12:00:01Z", Target: "b.example:80", Network: "tcp", Stage: "route", Category: "unroutable"},
		},
	}}
	s := newTestServer(t, p)

	rec := request(t, s, http.MethodGet, "/v1/failures?limit=2", "test-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
	}
	if p.lastFailLimit != 2 {
		t.Errorf("provider saw limit %d", p.lastFailLimit)
	}
	body := decode[FailureListView](t, rec)
	if body.Count != 2 || len(body.Failures) != 2 {
		t.Fatalf("body = %+v", body)
	}
	first := body.Failures[0]
	if first.Target != "a.example:443" || first.Category != "refused" || first.Stage != "dial" {
		t.Fatalf("first record = %+v", first)
	}
	if body.Failures[1].Policy != "" {
		t.Errorf("an empty policy must be omitted, got %q", body.Failures[1].Policy)
	}
	raw := rec.Body.String()
	for _, want := range []string{`"capacity"`, `"count"`, `"failures"`, `"category"`, `"stage"`, `"target"`, `"time"`} {
		if !strings.Contains(raw, want) {
			t.Errorf("response has no %s: %s", want, raw)
		}
	}

	for _, bad := range []string{"-1", "abc", "999999"} {
		rec := request(t, s, http.MethodGet, "/v1/failures?limit="+bad, "test-token")
		if rec.Code != http.StatusBadRequest {
			t.Errorf("limit=%s gave %d, want 400", bad, rec.Code)
		}
	}
}

// TestFailuresEmptyIsAnArray keeps the shape stable with no record.
func TestFailuresEmptyIsAnArray(t *testing.T) {
	s := newTestServer(t, &fakeProvider{})
	rec := request(t, s, http.MethodGet, "/v1/failures", "test-token")
	if got := strings.TrimSpace(rec.Body.String()); got != `{"capacity":0,"count":0,"failures":[]}` {
		t.Fatalf("body = %s", got)
	}
}

// TestDNSEndpoint checks the resolver statistics. Nothing in the payload may
// name a [Host] entry.
func TestDNSEndpoint(t *testing.T) {
	p := &fakeProvider{dns: DNSView{
		CacheHits:   7,
		CacheMisses: 3,
		Entries:     2,
		MaxEntries:  1024,
		Succeeded:   9,
		Failed:      1,
	}}
	s := newTestServer(t, p)
	rec := request(t, s, http.MethodGet, "/v1/dns", "test-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := decode[DNSView](t, rec)
	if body != p.dns {
		t.Fatalf("dns = %+v, want %+v", body, p.dns)
	}
	raw := rec.Body.String()
	for _, want := range []string{
		`"cache_hits"`, `"cache_misses"`, `"entries"`, `"max_entries"`,
		`"resolutions_succeeded"`, `"resolutions_failed"`,
	} {
		if !strings.Contains(raw, want) {
			t.Errorf("response has no %s: %s", want, raw)
		}
	}
}

// TestPolicyHealthFields pins the fields that make an all-unhealthy group
// visible: the flag itself, the per-member failure count, the time of the last
// check and the reason.
func TestPolicyHealthFields(t *testing.T) {
	p := &fakeProvider{policies: []PolicyView{{
		Name:           "Auto",
		Type:           "url-test",
		Active:         "a",
		Checked:        "2026-11-13T12:00:00Z",
		HealthyMembers: 0,
		AllUnhealthy:   true,
		Members: []MemberView{
			{Name: "a", Healthy: false, Checked: true, CheckedAt: "2026-11-13T12:00:00Z", Failures: 3, Error: "probe a: 404 Not Found"},
			{Name: "b", Healthy: false, Checked: true, CheckedAt: "2026-11-13T12:00:00Z", Failures: 1, Error: "probe b: connection refused"},
		},
	}}}
	s := newTestServer(t, p)
	rec := request(t, s, http.MethodGet, "/v1/policies", "test-token")
	raw := rec.Body.String()
	for _, want := range []string{`"all_unhealthy":true`, `"healthy_members":0`, `"failures":3`, `"checked_at"`, `"error"`} {
		if !strings.Contains(raw, want) {
			t.Errorf("response has no %s: %s", want, raw)
		}
	}
	var body struct {
		Policies []PolicyView `json:"policies"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Policies) != 1 || !body.Policies[0].AllUnhealthy {
		t.Fatalf("policies = %+v", body.Policies)
	}
	if body.Policies[0].Members[0].Failures != 3 {
		t.Fatalf("member = %+v", body.Policies[0].Members[0])
	}
}

// TestNewEndpointsRejectOtherMethods keeps the transport contract consistent
// across the endpoints added in this stage.
func TestNewEndpointsRejectOtherMethods(t *testing.T) {
	s := newTestServer(t, &fakeProvider{})
	for _, path := range []string{"/v1/inbound", "/v1/failures", "/v1/dns"} {
		rec := request(t, s, http.MethodPost, path, "test-token")
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("POST %s gave %d, want 405", path, rec.Code)
		}
		if got := rec.Header().Get("Allow"); got != http.MethodGet {
			t.Errorf("POST %s Allow = %q", path, got)
		}
	}
}
