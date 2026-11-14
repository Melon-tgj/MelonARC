package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/melon-tgj/melonarc/internal/inbound"
	"github.com/melon-tgj/melonarc/internal/store"
	"github.com/melon-tgj/melonarc/internal/subscription"
)

// historyObserver is the seam between the inbound layer and the persistent
// history: the layer keeps its own bounded records for the live endpoints and
// tells this adapter about them, which appends to the store.
//
// Both methods are called from the goroutine that served the request, so they
// only append to a bounded in-memory table. Nothing here returns an error and
// nothing blocks on the file: a history that cannot be written is a warning in
// the log, never a request that failed.
type historyObserver struct {
	store *store.Store
}

// Connection keeps one connection that was carried. The destination stays as
// the client asked for it — a name stays a name — because that is what a rule
// matched and what an operator recognizes.
func (o historyObserver) Connection(rec inbound.ConnectionRecord) {
	o.store.RecordConnection(store.Connection{
		At:       rec.Started,
		Protocol: rec.Protocol,
		Host:     rec.Target.Host,
		Port:     int(rec.Target.Port),
		Network:  rec.Network,
		Rule:     rec.Rule,
		Policy:   rec.Policy,
		Outbound: rec.Outbound,
		Up:       rec.Up,
		Down:     rec.Down,
		Duration: rec.Duration,
	})
}

// Failure keeps one request that was not carried.
//
// It is recorded as an event rather than as a connection, and with OK false:
// the request did not reach the destination. The category stays in the detail,
// because a rule that blocked a destination on purpose and a proxy that refused
// a connection are the same shape here and the opposite meaning to a reader.
func (o historyObserver) Failure(f inbound.Failure) {
	detail := f.Stage + " " + f.Category
	if f.Network != "" {
		detail += " " + f.Network
	}
	if f.Policy != "" {
		detail += " via " + f.Policy
	}
	o.store.RecordEvent(store.Event{
		At:     f.Time,
		Kind:   store.KindFailure,
		Name:   f.Target,
		Detail: detail,
		OK:     false,
	})
}

// sampleTraffic records what the connections carried during each interval.
//
// The counters only grow, so the difference between two reads is exactly what
// happened in between and a sample cannot miss a connection that spans the
// boundary. An idle interval is recorded as a zero rather than skipped: a zero
// is a fact about the interval, and a series with holes cannot be drawn.
//
// The last interval is not written on shutdown. It would cover a fraction of the
// usual span, and a short interval drawn as a full one is a dip that never
// happened; the connections still draining after the context ends are therefore
// counted in the totals but not in the series.
//
// The interval is a parameter rather than the constant so a test can drive the
// loop instead of waiting a minute for it.
func sampleTraffic(ctx context.Context, metrics *inbound.Metrics, st *store.Store, interval time.Duration, logger *slog.Logger) {
	if interval <= 0 {
		interval = store.SampleInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	lastUp, lastDown := metrics.Traffic()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			up, down := metrics.Traffic()
			sample := store.Sample{Up: up - lastUp, Down: down - lastDown}
			lastUp, lastDown = up, down
			st.RecordSample(sample)
			logger.Debug("traffic sampled", "up", sample.Up, "down", sample.Down)
		}
	}
}

// recordReload keeps the outcome of a reload.
//
// A refused reload is recorded too, with the reason: "the file did not take
// effect" is the one thing a later reader of the history has to be able to see,
// and the reason is already written to be read by a person.
func (s *daemonState) recordReload(path string, ok bool, detail string) {
	if s == nil {
		return
	}
	s.history.RecordEvent(store.Event{Kind: store.KindReload, Name: path, Detail: detail, OK: ok})
}

// recordSelection keeps a manual policy selection.
func (s *daemonState) recordSelection(group, previous, active string) {
	if s == nil {
		return
	}
	detail := "pinned " + active
	if previous != "" && previous != active {
		detail = previous + " -> " + active
	}
	s.history.RecordEvent(store.Event{Kind: store.KindPolicy, Name: group, Detail: detail, OK: true})
}

// subscriptionNodes counts the nodes the subscriptions currently provide, over
// all of them. It is what a refresh event reports: the number is the one a
// person compares with the one they saw before.
func subscriptionNodes(m *subscription.Manager) int {
	if m == nil {
		return 0
	}
	total := 0
	for _, st := range m.Snapshot() {
		total += st.Nodes
	}
	return total
}

// recordRefresh keeps a subscription refresh, which lands through the reload
// path and is the reason a pinned member or a rule can change without anyone
// editing the file.
func (s *daemonState) recordRefresh(nodes int, err error) {
	if s == nil {
		return
	}
	if err != nil {
		s.history.RecordEvent(store.Event{
			Kind:   store.KindSubscription,
			Name:   "refresh",
			Detail: err.Error(),
			OK:     false,
		})
		return
	}
	s.history.RecordEvent(store.Event{
		Kind:   store.KindSubscription,
		Name:   "refresh",
		Detail: fmt.Sprintf("%d nodes in force", nodes),
		OK:     true,
	})
}
