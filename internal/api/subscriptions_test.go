package api

import (
	"net/http"
	"net/http/httptest"
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
	rec := request(t, s, http.MethodPost, "/v1/subscriptions/airport/skipped", "test-token")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST skipped gave %d, want 405", rec.Code)
	}
	if got := rec.Header().Get("Allow"); got != http.MethodGet {
		t.Errorf("POST skipped Allow = %q", got)
	}
	// The list path is both a read and the create endpoint: its 405 must say so.
	rec = request(t, s, http.MethodDelete, "/v1/subscriptions", "test-token")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("DELETE subscriptions gave %d, want 405", rec.Code)
	}
	if got := rec.Header().Get("Allow"); got != "GET, POST" {
		t.Errorf("DELETE subscriptions Allow = %q", got)
	}
	// An authenticated read still needs the token: the endpoints are not a
	// second, unauthenticated door to the configuration.
	if rec := request(t, s, http.MethodGet, "/v1/subscriptions", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("a request without a token gave %d, want 401", rec.Code)
	}
}

// TestSubscriptionCreateEndpoint checks the two success statuses, the error
// mapping and that the URL never leaks into the audit ring.
func TestSubscriptionCreateEndpoint(t *testing.T) {
	const body = `{"name":"daily","url":"https://example.com/sub?token=private","interval_seconds":43200}`
	p := &fakeProvider{createCreated: true, createView: SubscriptionView{Name: "daily", Nodes: 7}}
	s := newTestServer(t, p)
	rec := post(t, s, "/v1/subscriptions", "test-token", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("first create gave %d, want 201: %s", rec.Code, rec.Body.String())
	}
	view := decode[SubscriptionView](t, rec)
	if view.Name != "daily" || view.Nodes != 7 {
		t.Fatalf("view = %+v", view)
	}
	if p.lastCreate.IntervalSeconds != 43200 {
		t.Fatalf("interval = %d", p.lastCreate.IntervalSeconds)
	}
	p.createCreated = false
	if rec := post(t, s, "/v1/subscriptions", "test-token", body); rec.Code != http.StatusOK {
		t.Fatalf("retry gave %d, want 200", rec.Code)
	}
	audit := decode[AuditListView](t, request(t, s, http.MethodGet, "/v1/audit", "test-token"))
	for _, entry := range audit.Entries {
		if strings.Contains(entry.Detail, "private") {
			t.Fatalf("the audit record leaked a subscription token: %+v", entry)
		}
	}
}

// TestSubscriptionCreateErrors maps the provider's RequestError to the status
// the shell uses to choose between a form error and a conflict dialog.
func TestSubscriptionCreateErrors(t *testing.T) {
	for name, tc := range map[string]struct {
		err    error
		status int
		code   string
	}{
		"invalid":  {BadRequest("invalid_subscription", "bad url"), http.StatusBadRequest, "invalid_subscription"},
		"conflict": {Conflict("subscription_conflict", "name taken"), http.StatusConflict, "subscription_conflict"},
		"stale":    {Conflict("config_changed", "retry"), http.StatusConflict, "config_changed"},
		"fetch":    {Unprocessable("subscription_import_failed", "fetch failed"), http.StatusUnprocessableEntity, "subscription_import_failed"},
	} {
		t.Run(name, func(t *testing.T) {
			s := newTestServer(t, &fakeProvider{createErr: tc.err})
			rec := post(t, s, "/v1/subscriptions", "test-token", `{"name":"a","url":"https://example.com/a"}`)
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d", rec.Code, tc.status)
			}
			if body := decode[errorView](t, rec); body.Error.Code != tc.code {
				t.Fatalf("code = %q, want %q", body.Error.Code, tc.code)
			}
		})
	}
}

// TestSubscriptionRefreshEndpoint checks that a POST forces one named refresh,
// returns the facts a client draws, and is recorded as a write.
func TestSubscriptionRefreshEndpoint(t *testing.T) {
	p := &fakeProvider{refresh: SubscriptionRefreshView{
		Refreshed: true, Reloaded: true, Nodes: 12, Skipped: 3,
		FetchedAt: "2026-11-18T08:00:00Z", Attempts: 0,
	}}
	s := newTestServer(t, p)
	rec := post(t, s, "/v1/subscriptions/airport/refresh", "test-token", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
	}
	body := decode[SubscriptionRefreshView](t, rec)
	if body.Subscription != "airport" || !body.Refreshed || !body.Reloaded {
		t.Fatalf("view = %+v", body)
	}
	if body.Nodes != 12 || body.Skipped != 3 || body.FetchedAt != "2026-11-18T08:00:00Z" {
		t.Fatalf("facts = %+v", body)
	}
	if p.lastSkipped.name != "airport" {
		t.Errorf("the provider was asked about %q, want airport", p.lastSkipped.name)
	}
	entries := auditOf(t, s)
	if len(entries) != 1 || entries[0].Action != ActionSubscriptionRefresh || entries[0].Result != ResultOK {
		t.Fatalf("audit = %+v", entries)
	}
	raw := rec.Body.String()
	for _, want := range []string{
		`"subscription":"airport"`, `"refreshed":true`, `"reloaded":true`, `"nodes":12`,
	} {
		if !strings.Contains(raw, want) {
			t.Errorf("response has no %s: %s", want, raw)
		}
	}
}

// TestSubscriptionRefreshFailureStaysInTheView keeps a failed fetch out of the
// error channel: the previous nodes were kept, so the request succeeded and the
// reason is carried in the answer the interface can show.
func TestSubscriptionRefreshFailureStaysInTheView(t *testing.T) {
	p := &fakeProvider{refresh: SubscriptionRefreshView{
		Nodes: 12, Attempts: 2, Error: "the server answered 502 Bad Gateway",
	}}
	s := newTestServer(t, p)
	rec := post(t, s, "/v1/subscriptions/airport/refresh", "test-token", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
	}
	body := decode[SubscriptionRefreshView](t, rec)
	if body.Refreshed || body.Reloaded || body.Error == "" || body.Nodes != 12 {
		t.Fatalf("view = %+v", body)
	}
	entries := auditOf(t, s)
	if len(entries) != 1 || entries[0].Result != ResultOK {
		t.Fatalf("a kept-nodes failure must still be a recorded OK: %+v", entries)
	}
}

// TestSubscriptionRefreshReportsProviderErrors keeps the error shape of the
// other write endpoints: a name the daemon does not know is a JSON 404.
func TestSubscriptionRefreshReportsProviderErrors(t *testing.T) {
	p := &fakeProvider{refreshErr: NotFound("unknown_subscription", "no subscription is named here")}
	s := newTestServer(t, p)
	rec := post(t, s, "/v1/subscriptions/ghost/refresh", "test-token", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
	}
	body := decode[struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}](t, rec)
	if body.Error.Code != "unknown_subscription" {
		t.Fatalf("code = %q", body.Error.Code)
	}
	entries := auditOf(t, s)
	if len(entries) != 1 || entries[0].Result != ResultFailed {
		t.Fatalf("audit = %+v", entries)
	}
}

// TestSubscriptionRefreshRejectsAnEmptyName keeps a blank name out of the
// provider. The mux folds a double slash into a redirect before the handler,
// so the handler's own guard is exercised directly here.
func TestSubscriptionRefreshRejectsAnEmptyName(t *testing.T) {
	p := &fakeProvider{}
	s := newTestServer(t, p)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/subscriptions/x/refresh", nil)
	req.SetPathValue("name", "  ")
	s.handleSubscriptionRefresh(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (%s)", rec.Code, rec.Body.String())
	}
	if p.lastSkipped.name != "" {
		t.Errorf("an empty name reached the provider: %q", p.lastSkipped.name)
	}
	// The redirect for a literal empty segment must not reach the provider
	// either.
	rec = post(t, s, "/v1/subscriptions//refresh", "test-token", "")
	if p.lastSkipped.name != "" {
		t.Errorf("a folded empty segment reached the provider: %q", p.lastSkipped.name)
	}
}
