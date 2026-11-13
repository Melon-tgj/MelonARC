package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

// fakeClock is a clock the test advances by hand, so TTL behaviour is checked
// without sleeping.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

// Now reads the clock.
func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// advance moves the clock forward.
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// newClock returns a clock starting at a fixed instant.
func newClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)}
}

// scriptedLookup is a LookupFunc whose answers a test decides, and which records
// every name it was asked for.
type scriptedLookup struct {
	answer func(host string) ([]net.IP, error)

	mu    sync.Mutex
	calls []string

	// entered is closed when the first call starts; release holds every call
	// open until it is closed. Both are nil in tests that do not need to keep a
	// lookup in flight.
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

// lookup implements LookupFunc.
func (l *scriptedLookup) lookup(ctx context.Context, host string) ([]net.IP, error) {
	l.mu.Lock()
	l.calls = append(l.calls, host)
	l.mu.Unlock()
	if l.entered != nil {
		l.once.Do(func() { close(l.entered) })
	}
	if l.release != nil {
		select {
		case <-l.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return l.answer(host)
}

// count returns how many lookups were made.
func (l *scriptedLookup) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.calls)
}

// names returns the names looked up, in order.
func (l *scriptedLookup) names() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.calls...)
}

// fixedIPs answers every name with the same addresses.
func fixedIPs(ips ...string) func(string) ([]net.IP, error) {
	return func(string) ([]net.IP, error) {
		out := make([]net.IP, 0, len(ips))
		for _, ip := range ips {
			out = append(out, net.ParseIP(ip))
		}
		return out, nil
	}
}

// newResolver builds a resolver over a scripted lookup and a fake clock.
func newResolver(t *testing.T, opts Options, lookup *scriptedLookup, clock *fakeClock) *Resolver {
	t.Helper()
	opts.Lookup = lookup.lookup
	if opts.Now == nil {
		opts.Now = clock.Now
	}
	r, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r
}

// TestStaticMappingWins checks that [Host] answers before anything else and that
// a mapped name never reaches the lookup at all.
func TestStaticMappingWins(t *testing.T) {
	lookup := &scriptedLookup{answer: fixedIPs("198.51.100.7")}
	r := newResolver(t, Options{
		Hosts: map[string][]net.IP{"cdn.example.com": {net.ParseIP("203.0.113.9")}},
	}, lookup, newClock())

	res, err := r.Resolve(context.Background(), "cdn.example.com")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Source != SourceHosts {
		t.Fatalf("source = %q, want %q", res.Source, SourceHosts)
	}
	if len(res.IPs) != 1 || !res.IPs[0].Equal(net.ParseIP("203.0.113.9")) {
		t.Fatalf("addresses = %v, want the mapped address", res.IPs)
	}
	if got := lookup.count(); got != 0 {
		t.Fatalf("the lookup ran %d times for a mapped name, want 0", got)
	}
}

// TestStaticMappingIgnoresSpelling checks that case and a trailing dot do not
// sidestep the mapping.
func TestStaticMappingIgnoresSpelling(t *testing.T) {
	lookup := &scriptedLookup{answer: fixedIPs("198.51.100.7")}
	r := newResolver(t, Options{
		Hosts: map[string][]net.IP{"cdn.example.com": {net.ParseIP("203.0.113.9")}},
	}, lookup, newClock())

	res, err := r.Resolve(context.Background(), "  CDN.Example.COM.  ")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Source != SourceHosts {
		t.Fatalf("source = %q, want %q", res.Source, SourceHosts)
	}
}

// TestPositiveCache checks that the second lookup of a name is answered from the
// cache, that the answer survives until the TTL ends, and that an expired answer
// is looked up again.
func TestPositiveCache(t *testing.T) {
	clock := newClock()
	lookup := &scriptedLookup{answer: fixedIPs("198.51.100.7")}
	r := newResolver(t, Options{PositiveTTL: time.Minute}, lookup, clock)
	ctx := context.Background()

	first, err := r.Resolve(ctx, "a.example.com")
	if err != nil {
		t.Fatalf("first Resolve: %v", err)
	}
	if first.Source != SourceSystem {
		t.Fatalf("first source = %q, want %q", first.Source, SourceSystem)
	}
	if got := lookup.count(); got != 1 {
		t.Fatalf("lookups after the first resolve = %d, want 1", got)
	}

	clock.advance(30 * time.Second)
	second, err := r.Resolve(ctx, "a.example.com")
	if err != nil {
		t.Fatalf("cached Resolve: %v", err)
	}
	if second.Source != SourceCache {
		t.Fatalf("second source = %q, want %q", second.Source, SourceCache)
	}
	if got := lookup.count(); got != 1 {
		t.Fatalf("lookups after a cache hit = %d, want 1", got)
	}

	clock.advance(31 * time.Second)
	if _, err := r.Resolve(ctx, "a.example.com"); err != nil {
		t.Fatalf("Resolve after expiry: %v", err)
	}
	if got := lookup.count(); got != 2 {
		t.Fatalf("lookups after the TTL ran out = %d, want 2", got)
	}
}

// TestAnswerIsACopy checks that a caller cannot edit the cache through an answer
// it was given.
func TestAnswerIsACopy(t *testing.T) {
	lookup := &scriptedLookup{answer: fixedIPs("198.51.100.7")}
	r := newResolver(t, Options{}, lookup, newClock())
	ctx := context.Background()

	first, err := r.Resolve(ctx, "a.example.com")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	first.IPs[0][15] = 99
	second, err := r.Resolve(ctx, "a.example.com")
	if err != nil {
		t.Fatalf("second Resolve: %v", err)
	}
	if !second.IPs[0].Equal(net.ParseIP("198.51.100.7")) {
		t.Fatalf("the cache was changed through a returned answer: %v", second.IPs)
	}
}

// TestNegativeCache checks that "no such name" is remembered for the negative
// TTL and stops being reused when it ends.
func TestNegativeCache(t *testing.T) {
	clock := newClock()
	notFound := &net.DNSError{Err: "no such host", Name: "gone.example.com", IsNotFound: true}
	lookup := &scriptedLookup{answer: func(string) ([]net.IP, error) { return nil, notFound }}
	r := newResolver(t, Options{NegativeTTL: 10 * time.Second}, lookup, clock)
	ctx := context.Background()

	if _, err := r.Resolve(ctx, "gone.example.com"); err == nil {
		t.Fatal("Resolve of a missing name succeeded, want the lookup error")
	}
	if got := lookup.count(); got != 1 {
		t.Fatalf("lookups after the first failure = %d, want 1", got)
	}

	_, err := r.Resolve(ctx, "gone.example.com")
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
		t.Fatalf("cached failure = %v, want the original not-found error", err)
	}
	if got := lookup.count(); got != 1 {
		t.Fatalf("lookups after a negative cache hit = %d, want 1", got)
	}

	clock.advance(11 * time.Second)
	if _, err := r.Resolve(ctx, "gone.example.com"); err == nil {
		t.Fatal("Resolve after the negative TTL succeeded, want a failure")
	}
	if got := lookup.count(); got != 2 {
		t.Fatalf("lookups after the negative TTL ran out = %d, want 2", got)
	}
}

// TestTransientFailureIsNotCached checks that a failure which says nothing about
// the name is retried instead of being remembered.
func TestTransientFailureIsNotCached(t *testing.T) {
	lookup := &scriptedLookup{answer: func(string) ([]net.IP, error) {
		return nil, errors.New("lookup timed out")
	}}
	r := newResolver(t, Options{}, lookup, newClock())
	ctx := context.Background()

	for i := 2; i > 0; i-- {
		if _, err := r.Resolve(ctx, "a.example.com"); err == nil {
			t.Fatal("Resolve succeeded, want the lookup error")
		}
	}
	if got := lookup.count(); got != 2 {
		t.Fatalf("lookups = %d, want 2: a timeout must not be cached", got)
	}
}

// TestEmptyAnswerIsNegative checks that a resolver answering with no address is
// treated as "the name does not resolve" rather than as an empty success.
func TestEmptyAnswerIsNegative(t *testing.T) {
	lookup := &scriptedLookup{answer: func(string) ([]net.IP, error) { return nil, nil }}
	r := newResolver(t, Options{}, lookup, newClock())

	_, err := r.Resolve(context.Background(), "empty.example.com")
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
		t.Fatalf("Resolve = %v, want a not-found error", err)
	}
	if got := lookup.count(); got != 1 {
		t.Fatalf("lookups = %d, want 1", got)
	}
	if _, err := r.Resolve(context.Background(), "empty.example.com"); err == nil {
		t.Fatal("the empty answer was not cached as a negative one")
	}
	if got := lookup.count(); got != 1 {
		t.Fatalf("lookups after the negative cache hit = %d, want 1", got)
	}
}

// TestConcurrentLookupsShareOneQuery is the coalescing proof: many callers, one
// upstream lookup, and every caller gets the same answer.
func TestConcurrentLookupsShareOneQuery(t *testing.T) {
	const callers = 32
	lookup := &scriptedLookup{
		answer:  fixedIPs("198.51.100.7", "198.51.100.8"),
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	r := newResolver(t, Options{}, lookup, newClock())

	results := make([]Result, callers)
	errs := make([]error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = r.Resolve(context.Background(), "burst.example.com")
		}(i)
	}

	// Let every caller reach Resolve before the first lookup is allowed to
	// finish, so they all have a chance to join the same call.
	<-lookup.entered
	time.Sleep(20 * time.Millisecond)
	close(lookup.release)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("caller %d: %v", i, err)
		}
		if len(results[i].IPs) != 2 || !results[i].IPs[0].Equal(net.ParseIP("198.51.100.7")) {
			t.Fatalf("caller %d got %v, want the shared answer", i, results[i].IPs)
		}
	}
	if got := lookup.count(); got != 1 {
		t.Fatalf("the lookup ran %d times for %d concurrent callers, want 1", got, callers)
	}
	if got := lookup.names(); len(got) != 1 || got[0] != "burst.example.com" {
		t.Fatalf("looked up %v, want one lookup of burst.example.com", got)
	}
}

// TestCanceledWaiterLeavesTheLookupAlone checks that a caller that gives up does
// not cancel the query another caller is waiting for.
func TestCanceledWaiterLeavesTheLookupAlone(t *testing.T) {
	lookup := &scriptedLookup{
		answer:  fixedIPs("198.51.100.7"),
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	r := newResolver(t, Options{}, lookup, newClock())

	leader := make(chan error, 1)
	go func() {
		_, err := r.Resolve(context.Background(), "slow.example.com")
		leader <- err
	}()
	<-lookup.entered

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.Resolve(ctx, "slow.example.com"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Resolve = %v, want context.Canceled", err)
	}

	close(lookup.release)
	if err := <-leader; err != nil {
		t.Fatalf("the waiting caller was failed by the canceled one: %v", err)
	}
	if got := lookup.count(); got != 1 {
		t.Fatalf("lookups = %d, want 1", got)
	}
}

// TestLiteralAddressNeedsNoLookup checks that an address is answered as is.
func TestLiteralAddressNeedsNoLookup(t *testing.T) {
	lookup := &scriptedLookup{answer: fixedIPs("198.51.100.7")}
	r := newResolver(t, Options{}, lookup, newClock())

	res, err := r.Resolve(context.Background(), "203.0.113.4")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Source != SourceLiteral {
		t.Fatalf("source = %q, want %q", res.Source, SourceLiteral)
	}
	if !res.IPs[0].Equal(net.ParseIP("203.0.113.4")) {
		t.Fatalf("addresses = %v", res.IPs)
	}
	if got := lookup.count(); got != 0 {
		t.Fatalf("lookups = %d, want 0", got)
	}
}

// TestRejectsMalformedNames checks that a name the resolver cannot mean is
// refused instead of being handed to the lookup.
func TestRejectsMalformedNames(t *testing.T) {
	lookup := &scriptedLookup{answer: fixedIPs("198.51.100.7")}
	r := newResolver(t, Options{}, lookup, newClock())

	for _, name := range []string{"", "   ", ".example.com", "a..b", "bad name", "a/b"} {
		if _, err := r.Resolve(context.Background(), name); !errors.Is(err, ErrInvalidName) {
			t.Fatalf("Resolve(%q) = %v, want ErrInvalidName", name, err)
		}
	}
	if got := lookup.count(); got != 0 {
		t.Fatalf("lookups = %d, want 0", got)
	}
}

// TestCacheIsBounded checks that a long run of distinct names cannot grow the
// cache past its limit.
func TestCacheIsBounded(t *testing.T) {
	lookup := &scriptedLookup{answer: fixedIPs("198.51.100.7")}
	r := newResolver(t, Options{MaxEntries: 4}, lookup, newClock())
	ctx := context.Background()

	for i := 0; i < 20; i++ {
		if _, err := r.Resolve(ctx, fmt.Sprintf("n%d.example.com", i)); err != nil {
			t.Fatalf("Resolve: %v", err)
		}
	}
	if got := r.Len(); got > 4 {
		t.Fatalf("cache holds %d answers, want at most 4", got)
	}
}

// TestNewRejectsBadHostTable checks that a static table which cannot be used is
// refused at construction instead of silently answering nothing.
func TestNewRejectsBadHostTable(t *testing.T) {
	tests := []struct {
		name  string
		hosts map[string][]net.IP
	}{
		{name: "no address", hosts: map[string][]net.IP{"a.example.com": nil}},
		{name: "nil address", hosts: map[string][]net.IP{"a.example.com": {nil}}},
		{name: "invalid name", hosts: map[string][]net.IP{"": {net.ParseIP("203.0.113.1")}}},
		{name: "duplicate name", hosts: map[string][]net.IP{
			"a.example.com":  {net.ParseIP("203.0.113.1")},
			"A.EXAMPLE.COM.": {net.ParseIP("203.0.113.2")},
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(Options{Hosts: tc.hosts}); err == nil {
				t.Fatalf("New accepted %v", tc.hosts)
			}
		})
	}
}

// TestLookupMatchesResolve checks the convenience method the outbound uses.
func TestLookupMatchesResolve(t *testing.T) {
	lookup := &scriptedLookup{answer: fixedIPs("198.51.100.7")}
	r := newResolver(t, Options{}, lookup, newClock())

	ips, err := r.Lookup(context.Background(), "a.example.com")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(ips) != 1 || !ips[0].Equal(net.ParseIP("198.51.100.7")) {
		t.Fatalf("Lookup = %v", ips)
	}
}
