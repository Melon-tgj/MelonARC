// Package subscription fetches subscription URLs and keeps the nodes they
// describe.
//
// A subscription is a URL that returns a list of share links, usually base64
// encoded. Three properties shape this package:
//
//   - A refresh that fails must not take nodes away. The previous result stays
//     in force, and the next attempt backs off instead of hammering a server
//     that is already unhappy.
//   - The result outlives the process. The last successful body is cached on
//     disk, so a restart on a network that is down still produces the nodes the
//     routes and groups refer to.
//   - A body keeps its good links and reports every bad one by position and
//     reason. Only a body with nothing usable is a failed refresh; a mixed body
//     is a successful refresh of its valid nodes. A first import that has
//     neither a previous result nor a cache is an error naming the
//     subscription, never an empty group.
package subscription

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/melon-tgj/melonarc/internal/config"
	"github.com/melon-tgj/melonarc/internal/share"
)

// Defaults for the refresh loop. The tick is how often the manager looks for a
// subscription that is due; it is much shorter than any interval so a refresh
// starts close to its schedule without waking up more than twice a minute.
const (
	defaultTick       = 30 * time.Second
	retryBaseDelay    = 15 * time.Second
	maxRetryDelay     = 15 * time.Minute
	defaultHTTPTimout = 20 * time.Second
)

// Options configures a Manager. The zero value is usable: it fetches over the
// default client and keeps no cache.
type Options struct {
	// Client is the HTTP client used for fetches. Nil gets a client with a
	// timeout; a client of the caller's own keeps its own settings.
	Client *http.Client
	// CacheDir holds the last good body of every subscription. Empty disables
	// the cache, which is what tests want.
	CacheDir string
	// Logger receives one line per refresh. Nil discards them.
	Logger *slog.Logger
	// Now is the clock. Tests replace it to step through intervals.
	Now func() time.Time
}

// state is one subscription's history.
type state struct {
	entry     config.Subscription
	nodes     []config.Proxy
	skipped   []Skip
	signature string
	fetchedAt time.Time
	lastErr   error
	attempts  int
	next      time.Time
}

// Manager fetches subscriptions, remembers their last good result and refreshes
// them on their own schedule.
type Manager struct {
	opts Options

	mu    sync.Mutex
	state map[string]*state
}

// New builds a manager.
func New(opts Options) *Manager {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Client == nil {
		opts.Client = newHTTPClient(defaultHTTPTimout)
	}
	return &Manager{opts: opts, state: make(map[string]*state)}
}

// Import resolves every subscription declared by cfg and merges the result into
// it, so the configuration that goes on to build dialers has the nodes its
// rules and groups refer to.
//
// Subscriptions that are not due for a refresh reuse what the manager already
// has, which is what keeps a reload cheap: only the first load and the
// scheduled refreshes talk to the network.
func (m *Manager) Import(ctx context.Context, cfg *config.Config) error {
	if len(cfg.Subscriptions) == 0 {
		return nil
	}
	// The fetches are independent and each one is bounded by the client's
	// timeout, so they run together: a configuration with four subscriptions
	// takes as long as the slowest one, not as long as all four.
	type result struct {
		index   int
		proxies []config.Proxy
		err     error
	}
	results := make(chan result, len(cfg.Subscriptions))
	var wg sync.WaitGroup
	for i, sub := range cfg.Subscriptions {
		wg.Add(1)
		go func(index int, sub config.Subscription) {
			defer wg.Done()
			proxies, err := m.resolve(ctx, sub)
			results <- result{index: index, proxies: proxies, err: err}
		}(i, sub)
	}
	wg.Wait()
	close(results)

	nodes := make(map[string][]config.Proxy, len(cfg.Subscriptions))
	var issues []error
	for res := range results {
		sub := cfg.Subscriptions[res.index]
		if res.err != nil {
			issues = append(issues, fmt.Errorf("subscription %q: %w", sub.Name, res.err))
			continue
		}
		nodes[sub.Name] = res.proxies
	}
	if len(issues) > 0 {
		return errors.Join(issues...)
	}
	return cfg.MergeSubscriptions(nodes)
}

// resolve returns a subscription's nodes, fetching it only when it is due.
func (m *Manager) resolve(ctx context.Context, sub config.Subscription) ([]config.Proxy, error) {
	m.mu.Lock()
	st := m.state[sub.Name]
	now := m.opts.Now()
	due := st == nil || st.fetchedAt.IsZero() || !now.Before(st.next) || st.entry.URL != sub.URL
	var ready []config.Proxy
	if st != nil && !due {
		ready = copyProxies(st.nodes)
	}
	m.mu.Unlock()
	if !due && ready != nil {
		return ready, nil
	}
	proxies, _, err := m.refresh(ctx, sub)
	return proxies, err
}

// refresh fetches one subscription and updates its state. The boolean reports
// whether the node list changed.
func (m *Manager) refresh(ctx context.Context, sub config.Subscription) ([]config.Proxy, bool, error) {
	now := m.opts.Now()
	body, fetchErr := m.fetch(ctx, sub.URL)
	var proxies []config.Proxy
	var skips []Skip
	var err error
	if fetchErr == nil {
		proxies, skips, err = parseBody(body)
	} else {
		err = fetchErr
	}
	// The reasons are reported per entry whether the body was adopted or not:
	// on a total failure they are the only explanation of what the provider
	// served.
	m.reportSkips(sub.Name, skips)
	if err == nil {
		if len(body) > 0 {
			m.writeCache(sub.Name, body)
		}
		signature := signatureOf(proxies)
		m.mu.Lock()
		previous := m.state[sub.Name]
		changed := previous == nil || previous.signature != signature
		m.state[sub.Name] = &state{
			entry: sub, nodes: proxies, skipped: copySkips(skips), signature: signature,
			fetchedAt: now, next: now.Add(sub.Interval),
		}
		m.mu.Unlock()
		m.log().Info("subscription refreshed", "subscription", sub.Name,
			"nodes", len(proxies), "skipped", len(skips))
		return proxies, changed, nil
	}

	// The fetch or the parse failed. The previous result, or the cached body
	// from an earlier successful run, is still the best answer available.
	m.mu.Lock()
	st := m.state[sub.Name]
	if st == nil {
		st = &state{entry: sub}
		m.state[sub.Name] = st
	}
	st.entry = sub
	st.lastErr = err
	st.attempts++
	delay := retryDelay(st.attempts, sub.Interval)
	st.next = now.Add(delay)
	cached := copyProxies(st.nodes)
	m.mu.Unlock()

	if cached == nil {
		if body, cacheErr := m.readCache(sub.Name); cacheErr == nil {
			if parsed, _, parseErr := parseBody(body); parseErr == nil && len(parsed) > 0 {
				cached = parsed
				m.mu.Lock()
				m.state[sub.Name].nodes = parsed
				m.state[sub.Name].signature = signatureOf(parsed)
				m.mu.Unlock()
				m.log().Warn("subscription refresh failed, using the cached body",
					"subscription", sub.Name, "error", err)
			}
		}
	}
	if cached == nil {
		return nil, false, err
	}
	m.log().Warn("subscription refresh failed, keeping the previous nodes",
		"subscription", sub.Name, "nodes", len(cached), "error", err, "retry_in", delay.Round(time.Second))
	return cached, false, nil
}

// maxReportedSkips bounds the log lines of one refresh. A provider can serve a
// thousand bad links; the first few reasons are enough to diagnose it, and the
// rest are counted. Every reason, including those past the bound, is still
// available in Status.Skipped.
const maxReportedSkips = 8

// reportSkips is the per-entry answer to a link that could not be imported.
// The reasons come from the share importer and never quote the link.
func (m *Manager) reportSkips(subscription string, skips []Skip) {
	if len(skips) == 0 {
		return
	}
	for i, skip := range skips {
		if i == maxReportedSkips {
			m.log().Warn("more subscription entries were skipped",
				"subscription", subscription, "count", len(skips)-i)
			break
		}
		m.log().Warn("subscription entry skipped",
			"subscription", subscription, "item", skip.Item, "reason", skip.Reason)
	}
}

// Run refreshes subscriptions as their intervals come due and calls onChange
// after a refresh that changed the node list, so the caller can rebuild its
// routing artefacts against the new nodes.
//
// A failed refresh is retried with a backoff and never calls onChange: the nodes
// in force have not changed, so nothing has to be rebuilt.
func (m *Manager) Run(ctx context.Context, onChange func()) {
	ticker := time.NewTicker(defaultTick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if m.refreshDue(ctx) && onChange != nil {
				onChange()
			}
		}
	}
}

// refreshDue refreshes every subscription whose next attempt is now.
func (m *Manager) refreshDue(ctx context.Context) bool {
	m.mu.Lock()
	due := make([]config.Subscription, 0, len(m.state))
	now := m.opts.Now()
	for _, st := range m.state {
		if !now.Before(st.next) {
			due = append(due, st.entry)
		}
	}
	m.mu.Unlock()

	changed := false
	for _, sub := range due {
		if _, didChange, err := m.refresh(ctx, sub); err == nil && didChange {
			changed = true
		}
	}
	return changed
}

// Snapshot reports what the manager currently holds, for the local API and for
// tests. The nodes are copies.
func (m *Manager) Snapshot() []Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Status, 0, len(m.state))
	for _, st := range m.state {
		out = append(out, Status{
			Name:      st.entry.Name,
			URL:       st.entry.URL,
			Nodes:     len(st.nodes),
			Skipped:   copySkips(st.skipped),
			FetchedAt: st.fetchedAt,
			NextAt:    st.next,
			Attempts:  st.attempts,
			Error:     errorText(st.lastErr),
		})
	}
	return out
}

// Skip is one entry of a subscription body that was not imported.
//
// Item is the 1-based position among the links the body carried, and Reason
// says why without quoting the link. Skips describe the body that is currently
// in force; a refresh that failed and kept older nodes keeps their skips too.
type Skip struct {
	Item   int
	Reason string
}

// Status is one subscription's state, without the nodes themselves.
type Status struct {
	Name      string
	URL       string
	Nodes     int
	Skipped   []Skip
	FetchedAt time.Time
	NextAt    time.Time
	Attempts  int
	Error     string
}

// retryDelay grows the wait between attempts up to the subscription's own
// interval: a provider that is down for an hour should not be asked every
// fifteen seconds, and one that is down for a day should not be forgotten
// either.
func retryDelay(attempts int, interval time.Duration) time.Duration {
	delay := retryBaseDelay
	for i := 1; i < attempts && delay < maxRetryDelay; i++ {
		delay *= 2
	}
	if delay > maxRetryDelay {
		delay = maxRetryDelay
	}
	if interval > 0 && delay > interval {
		delay = interval
	}
	return delay
}

// signatureOf renders the node list to a comparable string. Server, port, type
// and arguments are what a dialer is built from, so a change in any of them
// means the runtime has to be rebuilt.
func signatureOf(proxies []config.Proxy) string {
	var b []byte
	for _, p := range proxies {
		b = append(b, p.Name...)
		b = append(b, 0)
		b = append(b, p.Type...)
		b = append(b, 0)
		b = append(b, p.Server...)
		b = append(b, 0)
		b = append(b, fmt.Sprint(p.Port)...)
		b = append(b, 0)
		for _, arg := range p.Args {
			b = append(b, arg...)
			b = append(b, 0)
		}
		b = append(b, '\n')
	}
	return string(b)
}

func copyProxies(proxies []config.Proxy) []config.Proxy {
	if proxies == nil {
		return nil
	}
	out := make([]config.Proxy, len(proxies))
	for i, p := range proxies {
		out[i] = p
		out[i].Args = append([]string(nil), p.Args...)
	}
	return out
}

func copySkips(skips []Skip) []Skip {
	if skips == nil {
		return nil
	}
	return append([]Skip(nil), skips...)
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func (m *Manager) log() *slog.Logger {
	if m.opts.Logger != nil {
		return m.opts.Logger
	}
	return slog.New(slog.DiscardHandler)
}

// ErrEmpty marks a body that parsed but described no node.
var ErrEmpty = errors.New("empty subscription")

// parseBody reads a subscription body: either base64 of a list of links or the
// list itself, one link per line. Blank lines and comments are skipped.
//
// It returns the entries that were understood completely and one Skip per
// rejected link. Only a body with nothing usable is an error: a mixed body is a
// successful refresh of its valid nodes, and the caller reports each skipped
// entry by position. That is what keeps one bad node from taking a whole
// subscription away, while still refusing to replace a working list with an
// empty one.
func parseBody(body []byte) ([]config.Proxy, []Skip, error) {
	text := decodeSubscription(body)
	lines := make([]string, 0, 16)
	for _, line := range splitLines(text) {
		line = trimLine(line)
		if line == "" || isComment(line) {
			continue
		}
		lines = append(lines, line)
	}
	if len(lines) == 0 {
		return nil, nil, fmt.Errorf("%w: the subscription body holds no link", ErrEmpty)
	}
	proxies, rejections := share.ParseAll(lines)
	skips := make([]Skip, 0, len(rejections))
	for _, rejection := range rejections {
		skips = append(skips, Skip{Item: rejection.Item, Reason: rejection.Reason.Error()})
	}
	if len(proxies) == 0 {
		return nil, skips, fmt.Errorf("%w: all %d links in the subscription body were rejected", ErrEmpty, len(lines))
	}
	return proxies, skips, nil
}
