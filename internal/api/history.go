package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// maxEventKind bounds the kind filter. The store spells its kinds out and none
// of them is long, so anything past this is a mistyped request rather than a
// filter that could match.
const maxEventKind = 32

// handleHistory reports the state of the observation history.
func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), handlerTimeout)
	defer cancel()
	writeJSON(w, http.StatusOK, s.provider.History(ctx))
}

// handleHistoryConnections serves the carried connections.
func (s *Server) handleHistoryConnections(w http.ResponseWriter, r *http.Request) {
	limit, since, err := parseHistoryWindow(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), handlerTimeout)
	defer cancel()
	view := s.provider.HistoryConnections(ctx, limit, since)
	if view.Connections == nil {
		view.Connections = []ConnectionView{}
	}
	writeJSON(w, http.StatusOK, view)
}

// handleHistoryEvents serves the events, optionally narrowed to one kind.
func (s *Server) handleHistoryEvents(w http.ResponseWriter, r *http.Request) {
	limit, since, err := parseHistoryWindow(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	kind := strings.TrimSpace(r.URL.Query().Get("kind"))
	if len(kind) > maxEventKind {
		writeError(w, http.StatusBadRequest, "bad_request",
			fmt.Sprintf("kind is longer than the %d bytes a kind can have", maxEventKind))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), handlerTimeout)
	defer cancel()
	view := s.provider.HistoryEvents(ctx, limit, kind, since)
	if view.Events == nil {
		view.Events = []EventView{}
	}
	writeJSON(w, http.StatusOK, view)
}

// handleHistoryTraffic serves the traffic samples.
func (s *Server) handleHistoryTraffic(w http.ResponseWriter, r *http.Request) {
	limit, since, err := parseHistoryWindow(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), handlerTimeout)
	defer cancel()
	view := s.provider.HistoryTraffic(ctx, limit, since)
	if view.Samples == nil {
		view.Samples = []TrafficView{}
	}
	writeJSON(w, http.StatusOK, view)
}

// parseHistoryWindow reads the limit and since parameters the history endpoints
// share.
func parseHistoryWindow(r *http.Request) (int, time.Time, error) {
	q := r.URL.Query()
	limit, err := parseLimit(q.Get("limit"))
	if err != nil {
		return 0, time.Time{}, err
	}
	since, err := parseSince(q.Get("since"), time.Now())
	if err != nil {
		return 0, time.Time{}, err
	}
	return limit, since, nil
}

// parseSince reads the lower bound of a history query.
//
// A window is given either as an instant — "2026-01-02T15:04:05Z" — or as how
// far back to look, "1h". The second form is what a person types, and turning it
// into an instant here keeps the provider from needing a clock.
func parseSince(raw string, now time.Time) (time.Time, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return time.Time{}, nil
	}
	if d, err := time.ParseDuration(value); err == nil {
		if d <= 0 {
			return time.Time{}, errors.New("since must be a positive duration, for example 1h")
		}
		return now.Add(-d), nil
	}
	if t, err := time.Parse(time.RFC3339, value); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf(
		"since %q is neither a timestamp (2026-01-02T15:04:05Z) nor a duration (1h, 30m)", raw)
}
