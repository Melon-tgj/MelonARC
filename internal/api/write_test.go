package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// post runs one write request through the router without opening a socket.
func post(t *testing.T, s *Server, target, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	s.http.Handler.ServeHTTP(rec, req)
	return rec
}

// TestWriteEndpointsRequireTheToken keeps the write endpoints behind the same
// authentication as the read ones: a local process without the token must not be
// able to change what the daemon routes.
func TestWriteEndpointsRequireTheToken(t *testing.T) {
	for _, target := range []string{"/v1/policies/select", "/v1/config/reload", "/v1/config/update", "/v1/subscriptions/airport/refresh"} {
		t.Run(target, func(t *testing.T) {
			p := &fakeProvider{}
			s := newTestServer(t, p)
			rec := post(t, s, target, "", `{"group":"manual","member":"a"}`)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", rec.Code)
			}
			if p.lastSelect[0] != "" || p.reloadCalls != 0 {
				t.Errorf("an unauthorised request reached the provider: %+v", p)
			}
			if entries := auditOf(t, s); len(entries) != 0 {
				t.Errorf("an unauthorised request was recorded: %+v", entries)
			}
		})
	}
}

func TestWriteEndpointsRejectOtherMethods(t *testing.T) {
	s := newTestServer(t, &fakeProvider{})
	for _, target := range []string{"/v1/policies/select", "/v1/config/reload", "/v1/config/update", "/v1/subscriptions/airport/refresh"} {
		rec := request(t, s, http.MethodGet, target, "test-token")
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("GET %s = %d, want 405", target, rec.Code)
		}
		if got := rec.Header().Get("Allow"); got != http.MethodPost {
			t.Errorf("Allow = %q, want POST", got)
		}
	}
}

func TestSelectValidatesTheBody(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{name: "empty body", body: "", want: "JSON object"},
		{name: "not json", body: "group=manual", want: "JSON object"},
		{name: "array", body: `["manual"]`, want: "JSON object"},
		{name: "unknown field", body: `{"group":"manual","members":"a"}`, want: "unknown field"},
		{name: "two objects", body: `{"group":"manual","member":"a"}{"group":"manual"}`, want: "exactly one"},
		{name: "no group", body: `{"member":"a"}`, want: "group is required"},
		{name: "no member", body: `{"group":"manual"}`, want: "member is required"},
		{name: "blank group", body: `{"group":"  ","member":"a"}`, want: "group is required"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := &fakeProvider{}
			s := newTestServer(t, p)
			rec := post(t, s, "/v1/policies/select", "test-token", tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body %q)", rec.Code, rec.Body.String())
			}
			body := decode[errorView](t, rec)
			if body.Error.Code != "bad_request" {
				t.Errorf("code = %q, want bad_request", body.Error.Code)
			}
			if !strings.Contains(body.Error.Message, tc.want) {
				t.Errorf("message %q does not mention %q", body.Error.Message, tc.want)
			}
			if p.lastSelect[0] != "" {
				t.Errorf("a malformed request reached the provider: %+v", p.lastSelect)
			}
		})
	}
}

// TestSelectRejectsAnOversizedBody bounds the request body: the two write
// endpoints take a small object, and nothing larger should be read into memory.
func TestSelectRejectsAnOversizedBody(t *testing.T) {
	p := &fakeProvider{}
	s := newTestServer(t, p)
	body := `{"group":"` + strings.Repeat("g", 100<<10) + `","member":"b"}`
	rec := post(t, s, "/v1/policies/select", "test-token", body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %s)", rec.Code, rec.Body.String())
	}
	if p.lastSelect[0] != "" {
		t.Errorf("an oversized request reached the provider: %+v", p.lastSelect)
	}
}

func TestSelectPinsTheGroup(t *testing.T) {
	p := &fakeProvider{selectView: SelectView{Group: "manual", Previous: "a", Active: "b"}}
	s := newTestServer(t, p)
	rec := post(t, s, "/v1/policies/select", "test-token", `{"group":"manual","member":"b"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (body %s)", rec.Code, rec.Body.String())
	}
	view := decode[SelectView](t, rec)
	if view.Active != "b" || view.Previous != "a" {
		t.Errorf("view = %+v", view)
	}
	if p.lastSelect != [2]string{"manual", "b"} {
		t.Errorf("provider got %v", p.lastSelect)
	}
}

// TestSelectMapsProviderErrors checks that a refusal reaches the client with the
// status and the code the provider chose, so a CLI can explain it instead of
// printing a generic failure.
func TestSelectMapsProviderErrors(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{name: "unknown group", err: NotFound("unknown_group", "no group named x"), wantStatus: 404, wantCode: "unknown_group"},
		{name: "not a manual group", err: Conflict("not_selectable", "auto is a url-test group"), wantStatus: 409, wantCode: "not_selectable"},
		{name: "unknown member", err: BadRequest("unknown_member", "z is not a member"), wantStatus: 400, wantCode: "unknown_member"},
		{name: "unclassified", err: errors.New("the registry is gone"), wantStatus: 500, wantCode: "internal_error"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer(t, &fakeProvider{selectErr: tc.err})
			rec := post(t, s, "/v1/policies/select", "test-token", `{"group":"manual","member":"b"}`)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			body := decode[errorView](t, rec)
			if body.Error.Code != tc.wantCode {
				t.Errorf("code = %q, want %q", body.Error.Code, tc.wantCode)
			}
			if !strings.Contains(body.Error.Message, tc.err.Error()) {
				t.Errorf("message %q does not carry the provider's reason", body.Error.Message)
			}
		})
	}
}

func TestReloadReportsWhatIsInForce(t *testing.T) {
	p := &fakeProvider{reloadView: ReloadView{
		OK:              true,
		Path:            "/etc/melonarc.ini",
		RuleCount:       12,
		ProxyCount:      3,
		GroupCount:      2,
		HostCount:       1,
		RestartRequired: []string{"http-listen"},
		ElapsedMS:       12.5,
	}}
	s := newTestServer(t, p)
	rec := post(t, s, "/v1/config/reload", "test-token", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (body %s)", rec.Code, rec.Body.String())
	}
	view := decode[ReloadView](t, rec)
	if !view.OK || view.RuleCount != 12 || len(view.RestartRequired) != 1 {
		t.Errorf("view = %+v", view)
	}
	if p.reloadCalls != 1 {
		t.Errorf("provider saw %d reloads, want 1", p.reloadCalls)
	}
}

// TestReloadRejectionCarriesTheProblems is the contract a rejected reload has to
// keep: a clear status, a reason naming every problem, and no change.
func TestReloadRejectionCarriesTheProblems(t *testing.T) {
	reason := "2 configuration problem(s):\n  - [Rule] line 4: rule targets unknown policy \"gone\"\n" +
		"  - [Rule]: the rule list must end with FINAL\n" +
		"the previous configuration is still in force"
	s := newTestServer(t, &fakeProvider{reloadErr: Unprocessable("reload_rejected", reason)})
	rec := post(t, s, "/v1/config/reload", "test-token", "")
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", rec.Code)
	}
	body := decode[errorView](t, rec)
	if body.Error.Code != "reload_rejected" {
		t.Errorf("code = %q", body.Error.Code)
	}
	if body.Error.Message != reason {
		t.Errorf("message = %q, want it verbatim", body.Error.Message)
	}
}

func TestAuditRecordsBothOutcomes(t *testing.T) {
	p := &fakeProvider{selectView: SelectView{Group: "manual", Previous: "a", Active: "b"}}
	s := newTestServer(t, p)

	if rec := post(t, s, "/v1/policies/select", "test-token", `{"group":"manual","member":"b"}`); rec.Code != http.StatusOK {
		t.Fatalf("select answered %d", rec.Code)
	}
	p.selectErr = Conflict("not_selectable", "auto is a url-test group")
	if rec := post(t, s, "/v1/policies/select", "test-token", `{"group":"auto","member":"b"}`); rec.Code != http.StatusConflict {
		t.Fatalf("select answered %d", rec.Code)
	}
	p.reloadErr = Unprocessable("reload_rejected", "the rule list must end with FINAL")
	if rec := post(t, s, "/v1/config/reload", "test-token", ""); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("reload answered %d", rec.Code)
	}

	entries := auditOf(t, s)
	if len(entries) != 3 {
		t.Fatalf("audit holds %d entries, want 3: %+v", len(entries), entries)
	}
	wantActions := []string{ActionPolicySelect, ActionPolicySelect, ActionConfigReload}
	wantResults := []string{ResultOK, ResultFailed, ResultFailed}
	for i, entry := range entries {
		if entry.Action != wantActions[i] || entry.Result != wantResults[i] {
			t.Errorf("entry %d = %+v, want %s/%s", i, entry, wantActions[i], wantResults[i])
		}
		if entry.Time == "" {
			t.Errorf("entry %d has no timestamp", i)
		}
	}
	if !strings.Contains(entries[0].Detail, "manual: a -> b") {
		t.Errorf("successful switch recorded as %q", entries[0].Detail)
	}
	if !strings.Contains(entries[1].Detail, "not_selectable") &&
		!strings.Contains(entries[1].Detail, "url-test") {
		t.Errorf("refused switch recorded as %q, want the reason", entries[1].Detail)
	}

	// A limit narrows the answer but not the record.
	limited := decode[AuditListView](t, request(t, s, http.MethodGet, "/v1/audit?limit=1", "test-token"))
	if limited.Count != 3 || len(limited.Entries) != 1 {
		t.Errorf("limited view = %+v, want the newest of three", limited)
	}
	if limited.Entries[0].Action != ActionConfigReload {
		t.Errorf("limited view ends with %q", limited.Entries[0].Action)
	}
	if limited.Capacity != DefaultAuditCapacity {
		t.Errorf("capacity = %d, want %d", limited.Capacity, DefaultAuditCapacity)
	}
}

func TestAuditRejectsABadLimit(t *testing.T) {
	s := newTestServer(t, &fakeProvider{})
	for _, limit := range []string{"-1", "many", "99999"} {
		rec := request(t, s, http.MethodGet, "/v1/audit?limit="+limit, "test-token")
		if rec.Code != http.StatusBadRequest {
			t.Errorf("limit %q answered %d, want 400", limit, rec.Code)
		}
	}
}

func TestAuditRingEvictsTheOldest(t *testing.T) {
	ring := newAuditLog(3)
	for i := 0; i < 5; i++ {
		ring.add(AuditEntry{Action: ActionConfigReload, Result: ResultOK, Detail: string(rune('a' + i))})
	}
	entries := ring.snapshot(0)
	if len(entries) != 3 {
		t.Fatalf("ring holds %d entries, want 3", len(entries))
	}
	for i, entry := range entries {
		if want := string(rune('c' + i)); entry.Detail != want {
			t.Errorf("entry %d = %q, want %q", i, entry.Detail, want)
		}
	}
	if ring.len() != 3 || ring.capacity() != 3 {
		t.Errorf("len = %d, capacity = %d", ring.len(), ring.capacity())
	}
}

// TestAuditDetailIsBounded keeps one long refusal from crowding the record.
func TestAuditDetailIsBounded(t *testing.T) {
	long := strings.Repeat("problem ", 100)
	s := newTestServer(t, &fakeProvider{reloadErr: Unprocessable("reload_rejected", long)})
	post(t, s, "/v1/config/reload", "test-token", "")
	entries := auditOf(t, s)
	if len(entries) != 1 {
		t.Fatalf("audit holds %d entries", len(entries))
	}
	if len(entries[0].Detail) > maxAuditDetailLen+len("...") {
		t.Errorf("detail is %d bytes, want it cut to about %d", len(entries[0].Detail), maxAuditDetailLen)
	}
	if !strings.HasSuffix(entries[0].Detail, "...") {
		t.Errorf("a cut detail does not look cut: %q", entries[0].Detail)
	}
}

// auditOf decodes the audit endpoint of a server.
func auditOf(t *testing.T, s *Server) []AuditView {
	t.Helper()
	view := decode[AuditListView](t, request(t, s, http.MethodGet, "/v1/audit", "test-token"))
	return view.Entries
}
