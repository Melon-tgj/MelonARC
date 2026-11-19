package api

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// maxSkippedPage bounds one page of a subscription's skip detail. A body of four
// megabytes can carry hundreds of thousands of rejected links, and a client that
// asks for all of them at once is asking the daemon to serialise the whole list.
// The same bound is applied by the subscription manager; it lives here as well
// because a request above it is refused with a reason rather than silently
// shortened.
const maxSkippedPage = 500

// handleSubscriptions serves the summary of every declared subscription.
func (s *Server) handleSubscriptions(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), handlerTimeout)
	defer cancel()
	view := s.provider.Subscriptions(ctx)
	if view.Subscriptions == nil {
		view.Subscriptions = []SubscriptionView{}
	}
	writeJSON(w, http.StatusOK, view)
}

// handleSubscriptionSkipped serves one page of a subscription's skip detail.
//
// The name is a path segment, so a subscription whose name contains a slash —
// configuration names may — arrives percent-encoded and is decoded by the mux
// before it reaches here.
func (s *Server) handleSubscriptionSkipped(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PathValue("name"))
	offset, limit, err := parseSkippedPage(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if name == "" {
		writeError(w, http.StatusNotFound, "unknown_subscription", "no subscription is named here")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), handlerTimeout)
	defer cancel()
	view, err := s.provider.SubscriptionSkipped(ctx, name, offset, limit)
	if err != nil {
		writeProviderError(w, err)
		return
	}
	if view.Skipped == nil {
		view.Skipped = []SkippedEntryView{}
	}
	writeJSON(w, http.StatusOK, view)
}

// handleSubscriptionRefresh forces one declared subscription to fetch now.
// The name is a path segment like the skipped-detail endpoint, so a name with
// a slash arrives percent-encoded and is decoded by the mux before it gets
// here. The response always describes what is in force after the attempt: a
// failed fetch keeps the previous nodes and reports them with an Error.
func (s *Server) handleSubscriptionRefresh(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PathValue("name"))
	if name == "" {
		writeError(w, http.StatusNotFound, "unknown_subscription", "no subscription is named here")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), reloadTimeout)
	defer cancel()
	view, err := s.provider.RefreshSubscription(ctx, name)
	if err != nil {
		s.record(r, ActionSubscriptionRefresh, ResultFailed, name+": "+err.Error())
		writeProviderError(w, err)
		return
	}
	detail := fmt.Sprintf("%s: refreshed=%t reloaded=%t nodes=%d", name, view.Refreshed, view.Reloaded, view.Nodes)
	if view.Error != "" {
		detail += ": " + view.Error
	}
	s.record(r, ActionSubscriptionRefresh, ResultOK, detail)
	writeJSON(w, http.StatusOK, view)
}

// parseSkippedPage reads the two parameters of a skip-detail page.
//
// They are separate from the single limit of the other read endpoints because a
// detail is walked rather than truncated: a client asks for the window it has
// not shown yet, and the total tells it when to stop.
func parseSkippedPage(r *http.Request) (int, int, error) {
	q := r.URL.Query()
	offset, err := parseOffset(q.Get("offset"))
	if err != nil {
		return 0, 0, err
	}
	limit, err := parseLimitWithin(q.Get("limit"), maxSkippedPage)
	if err != nil {
		return 0, 0, err
	}
	return offset, limit, nil
}

// parseOffset reads the optional offset parameter.
func parseOffset(raw string) (int, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("offset %q is not a non-negative number", raw)
	}
	return n, nil
}
