package policy

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
	"unicode/utf8"
)

// Default timings for groups that probe their members.
const (
	DefaultInterval  = 300 * time.Second
	DefaultTimeout   = 5 * time.Second
	DefaultTolerance = 50 * time.Millisecond
)

// background runs a periodic check and serialises manual checks against it.
type background struct {
	checkMu sync.Mutex

	mu      sync.Mutex
	cancel  context.CancelFunc
	done    chan struct{}
	running bool
}

// start launches the periodic check. It is a no-op when already running.
func (b *background) start(ctx context.Context, interval time.Duration, check func(context.Context)) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.running {
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	b.cancel, b.done, b.running = cancel, done, true
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		check(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				check(ctx)
			}
		}
	}()
}

// stop cancels the periodic check and waits for it to return.
func (b *background) stop() {
	b.mu.Lock()
	cancel, done, running := b.cancel, b.done, b.running
	b.cancel, b.done, b.running = nil, nil, false
	b.mu.Unlock()
	if !running {
		return
	}
	cancel()
	<-done
}

// probeRound measures every member concurrently and returns one result each.
// Members whose probe overruns the timeout are recorded as unhealthy.
func probeRound(ctx context.Context, prober Prober, members []string, timeout time.Duration) map[string]probeResult {
	type outcome struct {
		name   string
		result probeResult
	}
	ch := make(chan outcome, len(members))
	for _, m := range members {
		go func(member string) {
			cctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			latency, err := prober.Probe(cctx, member)
			ch <- outcome{name: member, result: probeResult{
				latency: latency,
				healthy: err == nil,
				checked: true,
				at:      time.Now(),
				err:     err,
			}}
		}(m)
	}
	out := make(map[string]probeResult, len(members))
	for range members {
		o := <-ch
		out[o.name] = o.result
	}
	return out
}

// carryFailures keeps the consecutive failure count across probe rounds: a
// healthy answer clears it, a failed one adds to what the member already had.
// previous may be nil on the first round.
func carryFailures(fresh, previous map[string]probeResult) {
	for name, r := range fresh {
		if r.healthy {
			r.failures = 0
			r.err = nil
		} else {
			r.failures = previous[name].failures + 1
		}
		fresh[name] = r
	}
}

// allUnhealthy reports whether every member was probed and failed. A member
// that has never been probed counts as up, which is what keeps a fresh group
// from reporting itself dead before its first round.
func allUnhealthy(members []string, results map[string]probeResult) bool {
	if len(members) == 0 {
		return false
	}
	for _, m := range members {
		r := results[m]
		if !r.checked || r.healthy {
			return false
		}
	}
	return true
}

// Select is a group that routes to the member the user picked. A selection
// takes effect on the next lookup, with no probing involved.
type Select struct {
	name    string
	members []string

	mu      sync.RWMutex
	active  string
	results map[string]probeResult
}

// NewSelect builds a select group. initial may be empty, in which case the
// first member is used.
func NewSelect(name string, members []string, initial string) (*Select, error) {
	if name == "" {
		return nil, errors.New("policy: select group needs a name")
	}
	if err := validateMembers(name, members); err != nil {
		return nil, err
	}
	active := members[0]
	if initial != "" {
		if !contains(members, initial) {
			return nil, fmt.Errorf("%w: %s is not a member of %s", ErrUnknownMember, initial, name)
		}
		active = initial
	}
	return &Select{
		name:    name,
		members: append([]string(nil), members...),
		active:  active,
		results: make(map[string]probeResult, len(members)),
	}, nil
}

// Name implements Group.
func (g *Select) Name() string { return g.name }

// Kind implements Group.
func (g *Select) Kind() Kind { return KindSelect }

// Members implements Group.
func (g *Select) Members() []string { return append([]string(nil), g.members...) }

// Active implements Group.
func (g *Select) Active() string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.active
}

// Select implements Group. The change is visible to the next Active call.
func (g *Select) Select(name string) error {
	if !contains(g.members, name) {
		return fmt.Errorf("%w: %s is not a member of %s", ErrUnknownMember, name, g.name)
	}
	g.mu.Lock()
	g.active = name
	g.mu.Unlock()
	return nil
}

// NotifyFailure implements Group. The selection never changes: the user owns
// the choice and a failing member stays selected until they pick another one.
//
// The failure is still counted. A manual group has no probe, so this is the
// only way "the member I picked keeps failing" can reach an operator, and the
// member is left marked as never probed rather than down, because nothing here
// can bring it back up.
func (g *Select) NotifyFailure(name string) {
	if !contains(g.members, name) {
		return
	}
	g.mu.Lock()
	r := g.results[name]
	r.failures++
	r.at = time.Now()
	g.results[name] = r
	g.mu.Unlock()
}

// Start implements Group. A manual group has no background work.
func (g *Select) Start(context.Context) {}

// Status implements Group.
func (g *Select) Status() Status {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return Status{
		Name:    g.name,
		Kind:    KindSelect,
		Active:  g.active,
		Members: memberStatuses(g.members, g.results),
	}
}

// Close implements Group.
func (g *Select) Close() {}

// URLTest is a group that probes its members on an interval and routes to the
// fastest healthy one. A switch only happens when the new member is faster by
// more than the tolerance, which keeps the choice from flapping.
type URLTest struct {
	name      string
	members   []string
	prober    Prober
	interval  time.Duration
	timeout   time.Duration
	tolerance time.Duration

	bg background

	mu        sync.RWMutex
	results   map[string]probeResult
	active    string
	lastCheck time.Time
}

// NewURLTest builds a URL-Test group. Zero or negative timings fall back to the
// package defaults.
func NewURLTest(name string, members []string, prober Prober, interval, timeout, tolerance time.Duration) (*URLTest, error) {
	if name == "" {
		return nil, errors.New("policy: url-test group needs a name")
	}
	if prober == nil {
		return nil, fmt.Errorf("policy: url-test group %q needs a prober", name)
	}
	if err := validateMembers(name, members); err != nil {
		return nil, err
	}
	if interval <= 0 {
		interval = DefaultInterval
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if tolerance < 0 {
		tolerance = DefaultTolerance
	}
	return &URLTest{
		name:      name,
		members:   append([]string(nil), members...),
		prober:    prober,
		interval:  interval,
		timeout:   timeout,
		tolerance: tolerance,
		results:   make(map[string]probeResult, len(members)),
		active:    members[0],
	}, nil
}

// Name implements Group.
func (g *URLTest) Name() string { return g.name }

// Kind implements Group.
func (g *URLTest) Kind() Kind { return KindURLTest }

// Members implements Group.
func (g *URLTest) Members() []string { return append([]string(nil), g.members...) }

// Active implements Group.
func (g *URLTest) Active() string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.active
}

// Select implements Group. URL-Test decides on its own.
func (g *URLTest) Select(string) error { return ErrNotManual }

// NotifyFailure implements Group: the failed member is marked unhealthy and the
// fastest remaining member takes over immediately, without a new probe round.
func (g *URLTest) NotifyFailure(name string) {
	g.mu.Lock()
	if _, ok := g.results[name]; !ok {
		g.results[name] = probeResult{checked: true, at: time.Now()}
	}
	r := g.results[name]
	r.healthy = false
	r.checked = true
	r.at = time.Now()
	r.failures++
	g.results[name] = r
	g.reselectLocked()
	g.mu.Unlock()
}

// Start begins periodic probing, with an immediate first round.
func (g *URLTest) Start(ctx context.Context) {
	g.bg.start(ctx, g.interval, g.Check)
}

// Check runs one probe round and updates the selection.
func (g *URLTest) Check(ctx context.Context) {
	g.bg.checkMu.Lock()
	defer g.bg.checkMu.Unlock()
	results := probeRound(ctx, g.prober, g.members, g.timeout)
	g.mu.Lock()
	carryFailures(results, g.results)
	g.results = results
	g.lastCheck = time.Now()
	g.reselectLocked()
	g.mu.Unlock()
}

// reselectLocked picks the fastest healthy member. The caller holds g.mu.
func (g *URLTest) reselectLocked() {
	best := ""
	var bestLatency time.Duration
	for _, m := range g.members {
		r := g.results[m]
		if !r.checked || !r.healthy {
			continue
		}
		if best == "" || r.latency < bestLatency {
			best, bestLatency = m, r.latency
		}
	}
	if best == "" {
		// Nothing is known to be healthy; keep the current member rather than
		// leaving the group without a target.
		return
	}
	if g.active == "" {
		g.active = best
		return
	}
	current, ok := g.results[g.active]
	if !ok || !current.checked || !current.healthy {
		g.active = best
		return
	}
	if best != g.active && bestLatency+g.tolerance < current.latency {
		g.active = best
	}
}

// Status implements Group.
func (g *URLTest) Status() Status {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return Status{
		Name:         g.name,
		Kind:         KindURLTest,
		Active:       g.active,
		Members:      memberStatuses(g.members, g.results),
		Checked:      g.lastCheck,
		AllUnhealthy: allUnhealthy(g.members, g.results),
	}
}

// Close implements Group.
func (g *URLTest) Close() { g.bg.stop() }

// Fallback is a group that routes to the first healthy member in declaration
// order and moves to the next one when a member fails.
type Fallback struct {
	name     string
	members  []string
	prober   Prober
	interval time.Duration
	timeout  time.Duration

	bg background

	mu        sync.RWMutex
	results   map[string]probeResult
	active    string
	lastCheck time.Time
}

// NewFallback builds a fallback group.
func NewFallback(name string, members []string, prober Prober, interval, timeout time.Duration) (*Fallback, error) {
	if name == "" {
		return nil, errors.New("policy: fallback group needs a name")
	}
	if prober == nil {
		return nil, fmt.Errorf("policy: fallback group %q needs a prober", name)
	}
	if err := validateMembers(name, members); err != nil {
		return nil, err
	}
	if interval <= 0 {
		interval = DefaultInterval
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &Fallback{
		name:     name,
		members:  append([]string(nil), members...),
		prober:   prober,
		interval: interval,
		timeout:  timeout,
		results:  make(map[string]probeResult, len(members)),
		active:   members[0],
	}, nil
}

// Name implements Group.
func (g *Fallback) Name() string { return g.name }

// Kind implements Group.
func (g *Fallback) Kind() Kind { return KindFallback }

// Members implements Group.
func (g *Fallback) Members() []string { return append([]string(nil), g.members...) }

// Active implements Group.
func (g *Fallback) Active() string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.active
}

// Select implements Group. Fallback decides on its own.
func (g *Fallback) Select(string) error { return ErrNotManual }

// NotifyFailure implements Group: the failed member is skipped and the next
// healthy one takes over immediately.
func (g *Fallback) NotifyFailure(name string) {
	g.mu.Lock()
	r := g.results[name]
	r.healthy = false
	r.checked = true
	r.at = time.Now()
	r.failures++
	g.results[name] = r
	g.reselectLocked()
	g.mu.Unlock()
}

// Start begins periodic probing, with an immediate first round.
func (g *Fallback) Start(ctx context.Context) {
	g.bg.start(ctx, g.interval, g.Check)
}

// Check runs one probe round and restores priority order.
func (g *Fallback) Check(ctx context.Context) {
	g.bg.checkMu.Lock()
	defer g.bg.checkMu.Unlock()
	results := probeRound(ctx, g.prober, g.members, g.timeout)
	g.mu.Lock()
	carryFailures(results, g.results)
	g.results = results
	g.lastCheck = time.Now()
	g.reselectLocked()
	g.mu.Unlock()
}

// reselectLocked takes the first member that is not known to be down. Members
// that were never probed count as up, so a fresh group starts at the top of the
// list. The caller holds g.mu.
func (g *Fallback) reselectLocked() {
	for _, m := range g.members {
		r := g.results[m]
		if !r.checked || r.healthy {
			g.active = m
			return
		}
	}
	// Every member failed its last probe. Stay on the first one and let the
	// dialer report the failure instead of leaving the group without a target.
	g.active = g.members[0]
}

// Status implements Group.
func (g *Fallback) Status() Status {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return Status{
		Name:         g.name,
		Kind:         KindFallback,
		Active:       g.active,
		Members:      memberStatuses(g.members, g.results),
		Checked:      g.lastCheck,
		AllUnhealthy: allUnhealthy(g.members, g.results),
	}
}

// Close implements Group.
func (g *Fallback) Close() { g.bg.stop() }

// memberStatuses renders the probe results in member order.
func memberStatuses(members []string, results map[string]probeResult) []MemberStatus {
	out := make([]MemberStatus, 0, len(members))
	for _, m := range members {
		r := results[m]
		out = append(out, MemberStatus{
			Name:      m,
			Latency:   r.latency,
			Healthy:   !r.checked || r.healthy,
			Checked:   r.checked,
			CheckedAt: r.at,
			Failures:  r.failures,
			Error:     shortError(r.err),
		})
	}
	return out
}

// maxErrorLen bounds the failure text a member snapshot carries. A probe error
// repeats the URL that failed, which is configuration, but a snapshot is read
// by a UI and must not grow with whatever a remote peer put in a message.
const maxErrorLen = 160

// shortError renders an error for a snapshot, cutting it at a rune boundary so
// the result stays valid text.
func shortError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if len(msg) <= maxErrorLen {
		return msg
	}
	cut := maxErrorLen
	for cut > 0 && !utf8.RuneStart(msg[cut]) {
		cut--
	}
	return msg[:cut] + "..."
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
