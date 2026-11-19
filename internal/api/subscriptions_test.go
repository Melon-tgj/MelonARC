package api

import (
	"net/http"
	"strings"
	"testing"
)

// TestSubscriptionsEndpoint checks the summary: the counts a client needs to
// decide whether to ask for the detail, and no detail in the answer itself.
func TestSubscriptionsEndpoint(t *testing.T) {
	p := &fakeProvider{subscriptions: SubscriptionListView{Subscriptions: []SubscriptionView{
		{
			Name: "airport", Nodes: 12, Skipped: 3,
			FetchedAt: "2026-11-16T08:00:00Z", NextAt: "2026-11-16T14:00:00Z",
		},
		{Name: "stale", Attempts: 2, Error: "the server answered 502 Bad Gateway"},
	}}}
	s := newTestServer(t, p)
	rec := request(t, s, http.MethodGet, "/v1/subscriptions", "test-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
	}
	body := decode[SubscriptionListView](t, rec)
	if len(body.Subscriptions) != 2 {
		t.Fatalf("subscriptions = %+v", body.Subscriptions)
	}
	first := body.Subscriptions[0]
	if first.Name != "airport" || first.Nodes != 12 || first.Skipped != 3 {
		t.Fatalf("first subscription = %+v", first)
	}
	if first.FetchedAt != "2026-11-16T08:00:00Z" || first.NextAt != "2026-11-16T14:00:00Z" {
		t.Fatalf("times = %q / %q", first.FetchedAt, first.NextAt)
	}
	if failed := body.Subscriptions[1]; failed.Attempts != 2 || failed.Error == "" {
		t.Fatalf("failed subscription = %+v", failed)
	}

	raw := rec.Body.String()
	for _, want := range []string{
		`"subscriptions"`, `"name":"airport"`, `"nodes":12`, `"skipped":3`,
		`"fetched_at"`, `"next_at"`, `"attempts":2`, `"error"`,
	} {
		if !strings.Contains(raw, want) {
			t.Errorf("response has no %s: %s", want, raw)
		}
	}
	// The decision this endpoint exists for: the ordinary answer carries a
	// count, never a reason. A provider with a thousand bad links must not make
	// this answer large.
	if strings.Contains(raw, `"reason"`) {
		t.Errorf("the summary carries skip details: %s", raw)
	}
}

// TestSubscriptionSkippedEndpoint checks one page: the path segment arrives
// decoded, the two parameters reach the provider as parsed, and the answer
// reports the total separately from the window it carries.
func TestSubscriptionSkippedEndpoint(t *testing.T) {
	p := &fakeProvider{skipped: SkippedListView{
		Subscription: "airport",
		Refreshed:    true,
		FetchedAt:    "2026-11-16T08:00:00Z",
		Total:        12,
		Offset:       5,
		Limit:        5,
		Skipped: []SkippedEntryView{
			{Item: 6, Reason: "unsupported link type"},
			{Item: 7, Reason: "the cipher is not implemented"},
		},
	}}
	s := newTestServer(t, p)

	rec := request(t, s, http.MethodGet, "/v1/subscriptions/airport/skipped?offset=5&limit=5", "test-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
	}
	if p.lastSkipped != (skippedQuery{name: "airport", offset: 5, limit: 5}) {
		t.Fatalf("provider saw %+v", p.lastSkipped)
	}
	body := decode[SkippedListView](t, rec)
	if body.Total != 12 || body.Offset != 5 || body.Limit != 5 || len(body.Skipped) != 2 {
		t.Fatalf("body = %+v", body)
	}
	if body.Skipped[0].Item != 6 || body.Skipped[1].Reason == "" {
		t.Fatalf("entries = %+v", body.Skipped)
	}
	raw := rec.Body.String()
	for _, want := range []string{
		`"subscription":"airport"`, `"refreshed":true`, `"total":12`,
		`"offset":5`, `"limit":5`, `"skipped":[`, `"item":6`, `"reason"`,
	} {
		if !strings.Contains(raw, want) {
			t.Errorf("response has no %s: %s", want, raw)
		}
	}

	// A configuration name may contain a slash; the client escapes it, and the
	// mux hands the provider the decoded name rather than two segments.
	if rec := request(t, s, http.MethodGet, "/v1/subscriptions/airport%2Fus/skipped", "test-token"); rec.Code != http.StatusOK {
		t.Fatalf("an escaped slash gave %d (%s)", rec.Code, rec.Body.String())
	}
	if p.lastSkipped.name != "airport/us" {
		t.Fatalf("provider saw the name %q, want the decoded one", p.lastSkipped.name)
	}
	if p.lastSkipped.offset != 0 || p.lastSkipped.limit != 0 {
		t.Errorf("no parameters became offset %d, limit %d: the endpoint picks the page", p.lastSkipped.offset, p.lastSkipped.limit)
	}
}

// TestSubscriptionSkippedEmptyAndUnknown covers the two empty answers the
// endpoint has to keep apart: a subscription that never completed a refresh is
// an empty list with Refreshed false, and a name the configuration does not
// declare is a 404.
func TestSubscriptionSkippedEmptyAndUnknown(t *testing.T) {
	p := &fakeProvider{skipped: SkippedListView{Subscription: "fresh"}}
	s := newTestServer(t, p)
	rec := request(t, s, http.MethodGet, "/v1/subscriptions/fresh/skipped", "test-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"refreshed":false`) {
		t.Errorf("a never-refreshed subscription does not say so: %s", rec.Body.String())
	}
	if got := strings.TrimSpace(strings.Split(rec.Body.String(), `"skipped":`)[1]); got != "[]}" {
		t.Errorf("the skipped list is %q, want an empty array", got)
	}

	p.skippedErr = NotFound("unknown_subscription", `no subscription is named "typo"`)
	rec = request(t, s, http.MethodGet, "/v1/subscriptions/typo/skipped", "test-token")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("an unknown name gave %d (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"code":"unknown_subscription"`) {
		t.Errorf("the refusal does not name the reason: %s", rec.Body.String())
	}
}

// TestSubscriptionSkippedRejectsBadPages keeps a malformed window a client
// error: an offset or a limit that cannot be served is refused with the number
// it would have been shortened to, rather than silently answered with a
// different page.
func TestSubscriptionSkippedRejectsBadPages(t *testing.T) {
	s := newTestServer(t, &fakeProvider{})
	for _, query := range []string{
		"offset=-1", "offset=abc", "limit=-1", "limit=abc", "limit=501",
	} {
		rec := request(t, s, http.MethodGet, "/v1/subscriptions/airport/skipped?"+query, "test-token")
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s gave %d, want 400", query, rec.Code)
		}
	}
	for _, query := range []string{"", "offset=0", "limit=500", "offset=12&limit=1"} {
		rec := request(t, s, http.MethodGet, "/v1/subscriptions/airport/skipped?"+query, "test-token")
		if rec.Code != http.StatusOK {
			t.Errorf("%q gave %d, want 200 (%s)", query, rec.Code, rec.Body.String())
		}
	}
}

// TestSubscriptionEndpointsRejectOtherMethods keeps the transport contract the
// other read endpoints follow: JSON 405 with the method that is allowed.
func TestSubscriptionEndpointsRejectOtherMethods(t *testing.T) {
	s := newTestServer(t, &fakeProvider{})
	for _, path := range []string{"/v1/subscriptions", "/v1/subscriptions/airport/skipped"} {
		rec := request(t, s, http.MethodPost, path, "test-token")
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("POST %s gave %d, want 405", path, rec.Code)
		}
		if got := rec.Header().Get("Allow"); got != http.MethodGet {
			t.Errorf("POST %s Allow = %q", path, got)
		}
	}
	// An authenticated read still needs the token: the endpoints are not a
	// second, unauthenticated door to the configuration.
	if rec := request(t, s, http.MethodGet, "/v1/subscriptions", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("a request without a token gave %d, want 401", rec.Code)
	}
}
