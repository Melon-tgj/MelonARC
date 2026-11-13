package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// reloadTimeout bounds a configuration reload. It is separate from
// handlerTimeout because a reload re-reads rule sets from disk and recompiles
// the rule program: a hundred thousand rules take a fraction of a second, but a
// cold disk or a large set of external files can take longer than a read.
const reloadTimeout = 30 * time.Second

// maxRequestBody bounds the body of a write request. The two write endpoints
// take a small object; anything larger is a client that is not this CLI.
const maxRequestBody = 64 << 10

// RequestError is what a Provider returns when a write request is well formed
// but cannot be carried out as asked: an unknown group, a group that decides on
// its own, a configuration that does not validate.
//
// The API maps it to a status and a code instead of answering 500, so a client
// can tell "your request was wrong" from "the daemon broke". Anything that is
// not a RequestError is an internal error and is reported as one.
type RequestError struct {
	Status  int
	Code    string
	Message string
}

// Error implements error.
func (e *RequestError) Error() string { return e.Message }

// BadRequest reports a request whose arguments do not make sense.
func BadRequest(code, message string) *RequestError {
	return &RequestError{Status: http.StatusBadRequest, Code: code, Message: message}
}

// NotFound reports a name the daemon does not know.
func NotFound(code, message string) *RequestError {
	return &RequestError{Status: http.StatusNotFound, Code: code, Message: message}
}

// Conflict reports a request that is valid but that this daemon cannot carry
// out in its current state.
func Conflict(code, message string) *RequestError {
	return &RequestError{Status: http.StatusConflict, Code: code, Message: message}
}

// Unprocessable reports input that was understood and rejected, such as a
// configuration that does not validate.
func Unprocessable(code, message string) *RequestError {
	return &RequestError{Status: http.StatusUnprocessableEntity, Code: code, Message: message}
}

// writeProviderError answers with the status a provider error asks for, or with
// an internal error when the provider did not classify it.
func writeProviderError(w http.ResponseWriter, err error) {
	var re *RequestError
	if errors.As(err, &re) && re.Status != 0 && re.Code != "" {
		writeError(w, re.Status, re.Code, re.Message)
		return
	}
	writeError(w, http.StatusInternalServerError, "internal_error", err.Error())
}

// selectRequest is the body of POST /v1/policies/select.
type selectRequest struct {
	Group  string `json:"group"`
	Member string `json:"member"`
}

// handleSelect pins a manual policy group to a member.
func (s *Server) handleSelect(w http.ResponseWriter, r *http.Request) {
	var body selectRequest
	if err := decodeBody(r, &body); err != nil {
		s.record(r, ActionPolicySelect, ResultFailed, "malformed request: "+err.Error())
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	group, member := strings.TrimSpace(body.Group), strings.TrimSpace(body.Member)
	switch {
	case group == "":
		s.record(r, ActionPolicySelect, ResultFailed, "no group named")
		writeError(w, http.StatusBadRequest, "bad_request", "group is required")
		return
	case member == "":
		s.record(r, ActionPolicySelect, ResultFailed, group+": no member named")
		writeError(w, http.StatusBadRequest, "bad_request", "member is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), handlerTimeout)
	defer cancel()
	view, err := s.provider.SelectPolicy(ctx, group, member)
	if err != nil {
		s.record(r, ActionPolicySelect, ResultFailed, group+" -> "+member+": "+err.Error())
		writeProviderError(w, err)
		return
	}
	s.record(r, ActionPolicySelect, ResultOK, selectDetail(view))
	writeJSON(w, http.StatusOK, view)
}

// selectDetail describes a completed switch for the audit record.
func selectDetail(view SelectView) string {
	if view.Previous == "" {
		return view.Group + " -> " + view.Active
	}
	return fmt.Sprintf("%s: %s -> %s", view.Group, view.Previous, view.Active)
}

// handleReload re-reads the configuration file and installs it.
func (s *Server) handleReload(w http.ResponseWriter, r *http.Request) {
	// A reload takes no body, but a client that sends one should not have it
	// read as part of the next request on a reused connection.
	defer drainBody(r)

	ctx, cancel := context.WithTimeout(r.Context(), reloadTimeout)
	defer cancel()
	view, err := s.provider.ReloadConfig(ctx)
	if err != nil {
		s.record(r, ActionConfigReload, ResultFailed, err.Error())
		writeProviderError(w, err)
		return
	}
	s.record(r, ActionConfigReload, ResultOK, reloadDetail(view))
	writeJSON(w, http.StatusOK, view)
}

// reloadDetail describes a completed reload for the audit record.
func reloadDetail(view ReloadView) string {
	detail := fmt.Sprintf("%s: %d rules, %d groups", view.Path, view.RuleCount, view.GroupCount)
	if len(view.RestartRequired) > 0 {
		detail += "; restart required for " + strings.Join(view.RestartRequired, ", ")
	}
	return detail
}

// handleAudit serves the write operations the API carried out.
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	limit, err := parseLimit(r.URL.Query().Get("limit"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	entries := s.audit.snapshot(limit)
	view := AuditListView{
		Capacity: s.audit.capacity(),
		Count:    s.audit.len(),
		Entries:  make([]AuditView, 0, len(entries)),
	}
	for _, e := range entries {
		view.Entries = append(view.Entries, AuditView{
			Time:   e.Time.UTC().Format(time.RFC3339),
			Action: e.Action,
			Result: e.Result,
			Detail: e.Detail,
			Remote: e.Remote,
		})
	}
	writeJSON(w, http.StatusOK, view)
}

// decodeBody reads one JSON object from the request body. Unknown fields are
// rejected: a client that spells "member" as "members" should be told, not
// silently get a request that switches nothing.
func decodeBody(r *http.Request, dst any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, maxRequestBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("the body must be a JSON object with the documented fields: %w", err)
	}
	if dec.More() {
		return errors.New("the body must hold exactly one JSON object")
	}
	return nil
}

// drainBody reads whatever is left of a request body so the connection can be
// reused. It is bounded by maxRequestBody.
func drainBody(r *http.Request) {
	if r.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, maxRequestBody))
}
