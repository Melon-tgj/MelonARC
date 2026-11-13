package dns

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// scriptedExchange is an upstream a test controls. It records every name it was
// asked for and answers from a function.
type scriptedExchange struct {
	mu     sync.Mutex
	answer func(host string) (Answer, error)
	calls  []string
}

// exchange implements ExchangeFunc.
func (e *scriptedExchange) exchange(_ context.Context, host string) (Answer, error) {
	e.mu.Lock()
	e.calls = append(e.calls, host)
	e.mu.Unlock()
	return e.answer(host)
}

// count returns how many questions reached the upstream.
func (e *scriptedExchange) count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.calls)
}

// newUpstreamResolver builds a resolver that asks the given exchange first.
func newUpstreamResolver(t *testing.T, opts Options, exchange *scriptedExchange, clock *fakeClock) *Resolver {
	t.Helper()
	if exchange != nil {
		opts.Exchange = exchange.exchange
	}
	if opts.Now == nil {
		opts.Now = clock.Now
	}
	r, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r
}

// TestAnswerTTLDrivesTheCacheEntry checks the core of this stage: the lifetime
// of a cached answer comes from the answer, not from a fixed setting.
func TestAnswerTTLDrivesTheCacheEntry(t *testing.T) {
	clock := newClock()
	exchange := &scriptedExchange{answer: func(string) (Answer, error) {
		return Answer{IPs: []net.IP{net.ParseIP("203.0.113.5")}, TTL: time.Minute}, nil
	}}
	r := newUpstreamResolver(t, Options{PositiveTTL: 10 * time.Minute}, exchange, clock)

	first, err := r.Resolve(context.Background(), "ttl.test")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if first.Source != SourceUpstream {
		t.Fatalf("source = %q, want %q", first.Source, SourceUpstream)
	}
	if got, want := first.Expires.Sub(clock.Now()), time.Minute; got != want {
		t.Fatalf("lifetime = %v, want %v", got, want)
	}

	clock.advance(59 * time.Second)
	second, err := r.Resolve(context.Background(), "ttl.test")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if second.Source != SourceCache {
		t.Fatalf("second source = %q, want %q", second.Source, SourceCache)
	}
	if exchange.count() != 1 {
		t.Fatalf("upstream questions = %d, want 1", exchange.count())
	}

	clock.advance(2 * time.Second)
	if _, err := r.Resolve(context.Background(), "ttl.test"); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if exchange.count() != 2 {
		t.Fatalf("upstream questions = %d, want 2 once the answer expired", exchange.count())
	}
}

// TestAnswerTTLIsClamped keeps a server from deciding how the cache behaves: a
// very short and a very long lifetime both land inside the fixed bounds.
func TestAnswerTTLIsClamped(t *testing.T) {
	tests := []struct {
		name string
		ttl  time.Duration
		want time.Duration
	}{
		{name: "too short", ttl: time.Second, want: MinAnswerTTL},
		{name: "inside", ttl: 5 * time.Minute, want: 5 * time.Minute},
		{name: "too long", ttl: 48 * time.Hour, want: MaxAnswerTTL},
		{name: "not reported", ttl: 0, want: DefaultPositiveTTL},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clock := newClock()
			exchange := &scriptedExchange{answer: func(string) (Answer, error) {
				return Answer{IPs: []net.IP{net.ParseIP("198.51.100.1")}, TTL: tc.ttl}, nil
			}}
			r := newUpstreamResolver(t, Options{}, exchange, clock)
			res, err := r.Resolve(context.Background(), "clamp.test")
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if got := res.Expires.Sub(clock.Now()); got != tc.want {
				t.Fatalf("lifetime = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestNegativeAnswerUsesTheUpstreamLifetime checks that an upstream negative
// answer is remembered for as long as the authority allowed.
func TestNegativeAnswerUsesTheUpstreamLifetime(t *testing.T) {
	clock := newClock()
	exchange := &scriptedExchange{answer: func(host string) (Answer, error) {
		return Answer{}, &NegativeError{Name: host, Kind: NegativeNXDomain, Reason: "the name does not exist", Lifetime: 2 * time.Minute}
	}}
	r := newUpstreamResolver(t, Options{NegativeTTL: time.Minute}, exchange, clock)

	if _, err := r.Resolve(context.Background(), "gone.test"); err == nil {
		t.Fatal("resolve succeeded, want a negative answer")
	}
	clock.advance(90 * time.Second)
	_, err := r.Resolve(context.Background(), "gone.test")
	if err == nil {
		t.Fatal("resolve succeeded, want the cached negative answer")
	}
	if !isNotFound(err) {
		t.Fatalf("error = %v, want a not-found error", err)
	}
	if exchange.count() != 1 {
		t.Fatalf("upstream questions = %d, want 1 while the negative answer is cached", exchange.count())
	}

	clock.advance(31 * time.Second)
	if _, err := r.Resolve(context.Background(), "gone.test"); err == nil {
		t.Fatal("resolve succeeded, want a negative answer")
	}
	if exchange.count() != 2 {
		t.Fatalf("upstream questions = %d, want 2 once the negative answer expired", exchange.count())
	}
}

// TestNegativeAnswerLifetimeIsClamped keeps a generous SOA from hiding a freshly
// created name for an hour.
func TestNegativeAnswerLifetimeIsClamped(t *testing.T) {
	clock := newClock()
	exchange := &scriptedExchange{answer: func(host string) (Answer, error) {
		return Answer{}, &NegativeError{Name: host, Kind: NegativeNXDomain, Reason: "gone", Lifetime: 2 * time.Hour}
	}}
	r := newUpstreamResolver(t, Options{}, exchange, clock)
	_, err := r.Resolve(context.Background(), "gone.test")
	var negative *NegativeError
	if !errors.As(err, &negative) {
		t.Fatalf("error = %v, want a *NegativeError", err)
	}
	clock.advance(MaxNegativeTTL + time.Second)
	if _, err := r.Resolve(context.Background(), "gone.test"); err == nil {
		t.Fatal("resolve succeeded, want a negative answer")
	}
	if exchange.count() != 2 {
		t.Fatalf("upstream questions = %d, want 2 once the clamped lifetime passed", exchange.count())
	}
}

// TestNegativeAnswerWithoutALifetimeUsesTheDefault covers a source that says the
// name does not exist but not for how long.
func TestNegativeAnswerWithoutALifetimeUsesTheDefault(t *testing.T) {
	clock := newClock()
	exchange := &scriptedExchange{answer: func(host string) (Answer, error) {
		return Answer{}, &NegativeError{Name: host, Kind: NegativeNoData, Reason: "the answer carries no address"}
	}}
	r := newUpstreamResolver(t, Options{NegativeTTL: 20 * time.Second}, exchange, clock)
	if _, err := r.Resolve(context.Background(), "empty.test"); err == nil {
		t.Fatal("resolve succeeded, want a negative answer")
	}
	clock.advance(19 * time.Second)
	if _, err := r.Resolve(context.Background(), "empty.test"); err == nil {
		t.Fatal("resolve succeeded, want the cached negative answer")
	}
	if exchange.count() != 1 {
		t.Fatalf("upstream questions = %d, want 1", exchange.count())
	}
	clock.advance(2 * time.Second)
	if _, err := r.Resolve(context.Background(), "empty.test"); err == nil {
		t.Fatal("resolve succeeded, want a negative answer")
	}
	if exchange.count() != 2 {
		t.Fatalf("upstream questions = %d, want 2", exchange.count())
	}
}

// TestUpstreamFailureFallsBackToTheSystemResolver covers the configured switch:
// an unreachable upstream is not a reason to fail the lookup.
func TestUpstreamFailureFallsBackToTheSystemResolver(t *testing.T) {
	clock := newClock()
	exchange := &scriptedExchange{answer: func(string) (Answer, error) {
		return Answer{}, errors.New("network is unreachable")
	}}
	lookup := &scriptedLookup{answer: fixedIPs("192.0.2.10")}
	opts := Options{Lookup: lookup.lookup, FallbackToSystem: true}
	r := newUpstreamResolver(t, opts, exchange, clock)

	res, err := r.Resolve(context.Background(), "fallback.test")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res.Source != SourceSystem {
		t.Fatalf("source = %q, want %q", res.Source, SourceSystem)
	}
	if lookup.count() != 1 {
		t.Fatalf("system lookups = %d, want 1", lookup.count())
	}
	// The answer carries no lifetime, so the configured default applies.
	if got, want := res.Expires.Sub(clock.Now()), DefaultPositiveTTL; got != want {
		t.Fatalf("lifetime = %v, want %v", got, want)
	}
}

// TestUpstreamFailureWithoutFallbackIsFatal covers the switch turned off.
func TestUpstreamFailureWithoutFallbackIsFatal(t *testing.T) {
	clock := newClock()
	exchange := &scriptedExchange{answer: func(string) (Answer, error) {
		return Answer{}, errors.New("network is unreachable")
	}}
	lookup := &scriptedLookup{answer: fixedIPs("192.0.2.10")}
	opts := Options{Lookup: lookup.lookup}
	r := newUpstreamResolver(t, opts, exchange, clock)

	if _, err := r.Resolve(context.Background(), "strict.test"); err == nil {
		t.Fatal("resolve succeeded, want the upstream failure")
	}
	if lookup.count() != 0 {
		t.Fatalf("system lookups = %d, want 0", lookup.count())
	}
}

// TestNegativeAnswerDoesNotFallBack checks the distinction the whole fallback
// rule rests on: "the name has no address" is an answer, not a failure.
func TestNegativeAnswerDoesNotFallBack(t *testing.T) {
	clock := newClock()
	exchange := &scriptedExchange{answer: func(host string) (Answer, error) {
		return Answer{}, &NegativeError{Name: host, Kind: NegativeNXDomain, Reason: "gone", Lifetime: time.Minute}
	}}
	lookup := &scriptedLookup{answer: fixedIPs("192.0.2.10")}
	opts := Options{Lookup: lookup.lookup, FallbackToSystem: true}
	r := newUpstreamResolver(t, opts, exchange, clock)

	if _, err := r.Resolve(context.Background(), "gone.test"); err == nil {
		t.Fatal("resolve succeeded, want a negative answer")
	}
	if lookup.count() != 0 {
		t.Fatalf("system lookups = %d, want 0 for a negative answer", lookup.count())
	}
}

// TestSilentUpstreamsFallBackToTheSystemResolver walks the sequence with real
// sockets: both configured servers take the question and answer nothing, so the
// lookup has to move past both of them and be carried by the system resolver
// while still inside the budget.
func TestSilentUpstreamsFallBackToTheSystemResolver(t *testing.T) {
	zone := map[string]zoneEntry{"quiet.test": {silent: true}}
	first := newFakeDNS(t, zone)
	second := newFakeDNS(t, zone)
	up, err := NewUpstream([]string{first.addr(), second.addr()}, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("new upstream: %v", err)
	}
	lookup := &scriptedLookup{answer: fixedIPs("192.0.2.5")}
	clock := newClock()
	r, err := New(Options{
		Lookup:           lookup.lookup,
		Exchange:         up.Exchange,
		FallbackToSystem: true,
		Timeout:          2 * time.Second,
		Now:              clock.Now,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	start := time.Now()
	res, err := r.Resolve(context.Background(), "quiet.test")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res.Source != SourceSystem {
		t.Fatalf("source = %q, want %q", res.Source, SourceSystem)
	}
	if lookup.count() != 1 {
		t.Fatalf("system lookups = %d, want 1", lookup.count())
	}
	if len(first.questions()) == 0 || len(second.questions()) == 0 {
		t.Fatalf("servers asked = %v, %v; want both tried before the fallback",
			first.questions(), second.questions())
	}
	if elapsed >= 2*time.Second {
		t.Fatalf("lookup took %v, want it inside the budget so the fallback fits", elapsed)
	}
	// The system resolver reports no lifetime, so the configured default
	// applies here just as it did before the plaintext upstream existed.
	if got, want := res.Expires.Sub(clock.Now()), DefaultPositiveTTL; got != want {
		t.Fatalf("lifetime = %v, want %v", got, want)
	}
}

// TestStaticMappingStillWinsOverTheUpstream keeps [Host] first in the order.
func TestStaticMappingStillWinsOverTheUpstream(t *testing.T) {
	clock := newClock()
	exchange := &scriptedExchange{answer: func(string) (Answer, error) {
		return Answer{IPs: []net.IP{net.ParseIP("192.0.2.99")}, TTL: time.Minute}, nil
	}}
	r := newUpstreamResolver(t, Options{
		Hosts: map[string][]net.IP{"pinned.test": {net.ParseIP("203.0.113.1")}},
	}, exchange, clock)

	res, err := r.Resolve(context.Background(), "pinned.test")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res.Source != SourceHosts {
		t.Fatalf("source = %q, want %q", res.Source, SourceHosts)
	}
	if res.Expires != (time.Time{}) {
		t.Fatalf("expires = %v, want the zero time for a static mapping", res.Expires)
	}
	if exchange.count() != 0 {
		t.Fatalf("upstream questions = %d, want 0", exchange.count())
	}
}

// TestConcurrentLookupsShareOneUpstreamQuery keeps the request coalescing the
// resolver already had, now around the upstream path.
func TestConcurrentLookupsShareOneUpstreamQuery(t *testing.T) {
	clock := newClock()
	release := make(chan struct{})
	var once sync.Once
	exchange := &scriptedExchange{answer: func(string) (Answer, error) {
		<-release
		return Answer{IPs: []net.IP{net.ParseIP("203.0.113.8")}, TTL: time.Minute}, nil
	}}
	r := newUpstreamResolver(t, Options{}, exchange, clock)

	const callers = 8
	var wg sync.WaitGroup
	errs := make(chan error, callers)
	wg.Add(callers)
	for i := 0; i < callers; i++ {
		go func() {
			defer wg.Done()
			if _, err := r.Resolve(context.Background(), "shared.test"); err != nil {
				errs <- err
			}
		}()
	}
	// Let every caller queue on the in-flight lookup before it is answered.
	deadline := time.Now().Add(2 * time.Second)
	for exchange.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(10 * time.Millisecond)
	once.Do(func() { close(release) })
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("resolve: %v", err)
	}
	if exchange.count() != 1 {
		t.Fatalf("upstream questions = %d, want 1", exchange.count())
	}
}
