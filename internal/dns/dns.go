package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Defaults for Options. A source that reports no lifetime — the system
// resolver, or a static table — has to be bounded by a fixed lifetime: five
// minutes keeps a moved name from being wrong for long without turning every
// connection into a lookup. A negative answer is kept much shorter, so a typo or
// a momentary failure does not stick.
const (
	DefaultPositiveTTL = 5 * time.Minute
	DefaultNegativeTTL = 30 * time.Second
	DefaultTimeout     = 5 * time.Second
	DefaultMaxEntries  = 1024
)

// Bounds on a lifetime taken from an upstream answer. They are fixed rather than
// configurable on purpose: they protect the cache from the two ways a server can
// get it wrong, and a user has no information to tune them with.
//
//   - A very small TTL turns the cache off and multiplies upstream queries, so
//     anything below MinAnswerTTL is raised to it. Ten seconds is short enough
//     to follow a failover and long enough that a page load reuses one answer.
//   - A very large TTL keeps a moved address in place long after the operator
//     changed it, so anything above MaxAnswerTTL is lowered to it. An hour is
//     longer than any TTL a CDN publishes for an A record and short enough that
//     a mistake heals within a coffee break.
//
// The negative bounds are tighter because a negative answer costs more when it
// is wrong: a name that was just created stays invisible to the client.
const (
	MinAnswerTTL   = 10 * time.Second
	MaxAnswerTTL   = time.Hour
	MinNegativeTTL = time.Second
	MaxNegativeTTL = 5 * time.Minute
)

// maxNameLen is the longest name accepted, in bytes.
const maxNameLen = 253

// Errors reported by the resolver.
var (
	// ErrNotFound marks a name the lookup found no address for. The system
	// resolver reports it as a *net.DNSError with IsNotFound set; a custom
	// Lookup may return this sentinel instead, and either is cached as a
	// negative answer.
	ErrNotFound = errors.New("dns: name does not resolve")
	// ErrInvalidName is returned for a name that cannot be looked up.
	ErrInvalidName = errors.New("dns: invalid name")
)

// Source says where an answer came from.
type Source string

// The places an answer can come from.
const (
	// SourceHosts is a static [Host] mapping.
	SourceHosts Source = "hosts"
	// SourceCache is a cached answer, positive or negative.
	SourceCache Source = "cache"
	// SourceUpstream is a fresh answer from a configured plaintext server.
	SourceUpstream Source = "upstream"
	// SourceSystem is a fresh lookup through the system resolver.
	SourceSystem Source = "system"
	// SourceLiteral is an address that needed no lookup at all.
	SourceLiteral Source = "literal"
)

// String implements fmt.Stringer.
func (s Source) String() string { return string(s) }

// Result is one answer: the addresses, where they came from and when they stop
// being reused.
type Result struct {
	// IPs are the addresses the name resolved to, in the order the answer
	// listed them. Matching uses the first one; a dialer may try the rest.
	IPs []net.IP
	// Source is where the answer came from.
	Source Source
	// Expires is when a cached answer stops being used. It is the zero time
	// for a static or literal answer, which never expires.
	Expires time.Time
}

// LookupFunc performs one upstream lookup. It must return addresses in
// preference order and must honour ctx.
type LookupFunc func(ctx context.Context, host string) ([]net.IP, error)

// Options configures a Resolver.
type Options struct {
	// Hosts is the static name table, normally the [Host] section. It is
	// consulted before anything else and never expires.
	Hosts map[string][]net.IP
	// Lookup performs the upstream lookup. Nil means the system resolver.
	Lookup LookupFunc
	// Exchange asks a configured plaintext server. When set, every name goes
	// there first and the answer's own lifetime is used for the cache entry.
	// Nil means names go straight to Lookup.
	Exchange ExchangeFunc
	// FallbackToSystem lets a failure of Exchange fall through to Lookup. It is
	// the "fall back to the system resolver" switch of the configuration; a
	// negative answer never falls through, because the name really has no
	// address and the system resolver would either agree or be wrong.
	FallbackToSystem bool
	// PositiveTTL bounds how long a resolved answer is reused when the source
	// did not report a lifetime. Zero means DefaultPositiveTTL.
	PositiveTTL time.Duration
	// NegativeTTL bounds how long a failed answer is reused when the source did
	// not report a lifetime. Zero means DefaultNegativeTTL.
	NegativeTTL time.Duration
	// Timeout bounds one upstream lookup whose context carries no deadline.
	// Zero means DefaultTimeout.
	Timeout time.Duration
	// MaxEntries caps the cache. Zero means DefaultMaxEntries.
	MaxEntries int
	// Now supplies the clock; nil means time.Now. Tests set it to advance time
	// without sleeping.
	Now func() time.Time
}

// Resolver answers name lookups. It is safe for concurrent use.
type Resolver struct {
	hosts  map[string][]net.IP
	lookup LookupFunc
	// exchange is the plaintext upstream, nil when names go to the system
	// resolver directly.
	exchange ExchangeFunc
	fallback bool

	positiveTTL time.Duration
	negativeTTL time.Duration
	timeout     time.Duration
	maxEntries  int
	now         func() time.Time

	mu     sync.Mutex
	cache  map[string]entry
	flight map[string]*call

	// The counters are read by the local API and written on the lookup path,
	// so they are atomic rather than guarded by mu: a snapshot must not wait
	// behind an upstream lookup.
	hits      atomic.Uint64
	misses    atomic.Uint64
	succeeded atomic.Uint64
	failed    atomic.Uint64
}

// Stats is a snapshot of what a resolver has done. It reports counts only: the
// [Host] table names internal services, so its content is never part of a
// statistic.
type Stats struct {
	// CacheHits counts answers served from a live cache entry, positive or
	// negative.
	CacheHits uint64
	// CacheMisses counts lookups that found nothing usable in the cache and
	// went upstream.
	//
	// A resolution answered by joining an identical lookup already in flight
	// is neither a hit nor a miss: it started no query of its own, so
	// CacheHits+CacheMisses can be smaller than Succeeded.
	CacheMisses uint64
	// Entries is how many answers the cache holds, expired ones included until
	// they are next touched or evicted.
	Entries int
	// MaxEntries is the cache capacity.
	MaxEntries int
	// Succeeded and Failed count Resolve calls by outcome.
	Succeeded uint64
	Failed    uint64
}

// entry is one cached answer. A negative entry carries the error that failed
// the lookup and no addresses.
type entry struct {
	ips     []net.IP
	err     error
	expires time.Time
}

// call is one lookup in flight, shared by every caller waiting for it.
type call struct {
	done   chan struct{}
	result Result
	err    error
}

// snapshot returns a copy of the answer for one waiter, so no caller can reach
// the addresses another caller holds.
func (c *call) snapshot() Result {
	return Result{IPs: cloneIPs(c.result.IPs), Source: c.result.Source, Expires: c.result.Expires}
}

// New builds a resolver.
func New(opts Options) (*Resolver, error) {
	r := &Resolver{
		hosts:       make(map[string][]net.IP, len(opts.Hosts)),
		lookup:      opts.Lookup,
		exchange:    opts.Exchange,
		fallback:    opts.FallbackToSystem,
		positiveTTL: opts.PositiveTTL,
		negativeTTL: opts.NegativeTTL,
		timeout:     opts.Timeout,
		maxEntries:  opts.MaxEntries,
		now:         opts.Now,
		cache:       make(map[string]entry),
		flight:      make(map[string]*call),
	}
	if r.lookup == nil {
		r.lookup = systemLookup
	}
	if r.positiveTTL <= 0 {
		r.positiveTTL = DefaultPositiveTTL
	}
	if r.negativeTTL <= 0 {
		r.negativeTTL = DefaultNegativeTTL
	}
	if r.timeout <= 0 {
		r.timeout = DefaultTimeout
	}
	if r.maxEntries <= 0 {
		r.maxEntries = DefaultMaxEntries
	}
	if r.now == nil {
		r.now = time.Now
	}
	for name, ips := range opts.Hosts {
		key, err := normalise(name)
		if err != nil {
			return nil, fmt.Errorf("host %q: %w", name, err)
		}
		if _, dup := r.hosts[key]; dup {
			return nil, fmt.Errorf("host %q is mapped twice", name)
		}
		clean := make([]net.IP, 0, len(ips))
		for _, ip := range ips {
			if ip == nil {
				return nil, fmt.Errorf("host %q has an invalid address", name)
			}
			clean = append(clean, append(net.IP(nil), ip...))
		}
		if len(clean) == 0 {
			return nil, fmt.Errorf("host %q has no address", name)
		}
		r.hosts[key] = clean
	}
	return r, nil
}

// Resolve answers the addresses of a name.
//
// A static mapping wins over everything; a cached answer (positive or
// negative) wins over a fresh lookup; identical concurrent lookups share one
// upstream query. The returned addresses are a copy.
func (r *Resolver) Resolve(ctx context.Context, host string) (Result, error) {
	res, err := r.resolve(ctx, host)
	if err != nil {
		r.failed.Add(1)
	} else {
		r.succeeded.Add(1)
	}
	return res, err
}

// resolve carries the lookup sequence and returns whatever it found. The
// counters are kept in Resolve so every exit, including the literal and static
// answers, is counted exactly once.
func (r *Resolver) resolve(ctx context.Context, host string) (Result, error) {
	name, err := normalise(host)
	if err != nil {
		return Result{}, err
	}
	if ip := net.ParseIP(name); ip != nil {
		return Result{IPs: []net.IP{ip}, Source: SourceLiteral}, nil
	}
	if ips, ok := r.hosts[name]; ok {
		return Result{IPs: cloneIPs(ips), Source: SourceHosts}, nil
	}
	if res, cachedErr, ok := r.fromCache(name); ok {
		return res, cachedErr
	}

	c, leader := r.join(name)
	if !leader {
		select {
		case <-c.done:
			return c.snapshot(), c.err
		case <-ctx.Done():
			// The caller gave up. The lookup itself keeps going for the
			// others waiting on it; the answer lands in the cache either way.
			return Result{}, ctx.Err()
		}
	}
	res, err := r.fetch(ctx, name)
	r.leave(name, c, res, err)
	return res, err
}

// Lookup is Resolve without the bookkeeping, in the shape outbound.Direct
// takes. It is how the outbound reuses an answer the pipeline already paid for
// instead of asking the system resolver a second time.
func (r *Resolver) Lookup(ctx context.Context, host string) ([]net.IP, error) {
	res, err := r.Resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	return res.IPs, nil
}

// Len returns the number of cached answers, expired ones included until they
// are next touched. It exists for tests and for the startup summary.
func (r *Resolver) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.cache)
}

// Stats returns the counters the local API serves. Entries and MaxEntries come
// from the cache itself, so a caller never has to hold two locks to describe it.
func (r *Resolver) Stats() Stats {
	r.mu.Lock()
	entries := len(r.cache)
	r.mu.Unlock()
	return Stats{
		CacheHits:   r.hits.Load(),
		CacheMisses: r.misses.Load(),
		Entries:     entries,
		MaxEntries:  r.maxEntries,
		Succeeded:   r.succeeded.Load(),
		Failed:      r.failed.Load(),
	}
}

// fromCache returns a live cached answer, dropping the entry when it has
// expired. A cached failure is returned with its error, which is what makes a
// negative answer cheap: the caller sees the same error without a lookup.
func (r *Resolver) fromCache(name string) (Result, error, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.cache[name]
	if !ok {
		return Result{}, nil, false
	}
	if !r.now().Before(e.expires) {
		delete(r.cache, name)
		return Result{}, nil, false
	}
	r.hits.Add(1)
	if e.err != nil {
		return Result{Source: SourceCache, Expires: e.expires}, e.err, true
	}
	return Result{IPs: cloneIPs(e.ips), Source: SourceCache, Expires: e.expires}, nil, true
}

// join registers this caller as the leader of a lookup for name, or attaches
// it to the one already in flight.
func (r *Resolver) join(name string) (c *call, leader bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if inFlight, ok := r.flight[name]; ok {
		return inFlight, false
	}
	c = &call{done: make(chan struct{})}
	r.flight[name] = c
	return c, true
}

// leave publishes the answer to every waiter. The entry is removed from the
// in-flight table before done is closed, so a caller that arrives afterwards
// starts a new lookup instead of joining a finished one.
func (r *Resolver) leave(name string, c *call, res Result, err error) {
	r.mu.Lock()
	if r.flight[name] == c {
		delete(r.flight, name)
	}
	r.mu.Unlock()
	c.result, c.err = res, err
	close(c.done)
}

// fetch performs one upstream lookup and caches the answer. A failure is
// cached only when it says the name does not exist: a timeout or a refused
// connection is a property of the moment, not of the name.
//
// The configured plaintext upstream is asked first; the system resolver is the
// fallback for a failure, never for a negative answer, because a negative answer
// is the upstream saying it knows the name and the name has no address.
func (r *Resolver) fetch(ctx context.Context, name string) (Result, error) {
	r.misses.Add(1)
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	var (
		ips    []net.IP
		ttl    time.Duration
		source = SourceSystem
	)
	if r.exchange != nil {
		answer, err := r.exchange(ctx, name)
		switch {
		case err == nil:
			ips, ttl, source = answer.IPs, answer.TTL, SourceUpstream
		case isNotFound(err):
			r.storeNegative(name, err)
			return Result{}, err
		case !r.fallback:
			return Result{}, err
		}
		// A failure that is not a negative answer falls through when the
		// configuration allows it: an unreachable upstream is a property of
		// this moment, and the system resolver may still know the name.
	}
	if source != SourceUpstream {
		var err error
		ips, err = r.lookup(ctx, name)
		if err != nil {
			if isNotFound(err) {
				r.storeNegative(name, err)
			}
			return Result{}, err
		}
	}
	ips = dedupeIPs(ips)
	if len(ips) == 0 {
		err := &net.DNSError{Err: "the answer carries no address", Name: name, IsNotFound: true}
		r.storeNegative(name, err)
		return Result{}, err
	}
	expires := r.now().Add(r.positiveLifetime(source, ttl))
	r.store(name, entry{ips: cloneIPs(ips), expires: expires})
	return Result{IPs: cloneIPs(ips), Source: source, Expires: expires}, nil
}

// storeNegative keeps a definitive "no address" answer for as long as the
// source allowed it to be remembered.
func (r *Resolver) storeNegative(name string, err error) {
	r.store(name, entry{err: err, expires: r.now().Add(r.negativeLifetime(err))})
}

// positiveLifetime turns the lifetime an answer carried into the one the cache
// uses. A source that reports none keeps the configured default; an answer from
// an upstream is clamped, so neither a one second nor a one week TTL from a
// server can decide how the cache behaves.
func (r *Resolver) positiveLifetime(source Source, ttl time.Duration) time.Duration {
	if source == SourceUpstream && ttl > 0 {
		return clampLifetime(ttl, MinAnswerTTL, MaxAnswerTTL)
	}
	return r.positiveTTL
}

// negativeLifetime is positiveLifetime for an answer that carries no address.
func (r *Resolver) negativeLifetime(err error) time.Duration {
	var negative *NegativeError
	if errors.As(err, &negative) && negative.Lifetime > 0 {
		return clampLifetime(negative.Lifetime, MinNegativeTTL, MaxNegativeTTL)
	}
	return r.negativeTTL
}

// clampLifetime keeps a lifetime inside the bounds the cache accepts.
func clampLifetime(d, min, max time.Duration) time.Duration {
	switch {
	case d < min:
		return min
	case d > max:
		return max
	default:
		return d
	}
}

// store keeps an answer, making room first when the cache is full.
func (r *Resolver) store(name string, e entry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.cache[name]; !exists && len(r.cache) >= r.maxEntries {
		r.evictLocked()
	}
	r.cache[name] = e
}

// evictLocked drops expired entries and, when that was not enough, the one that
// expires soonest. This is a size cap, not a recency policy: lookups are cheap
// and the cache is small, so the extra bookkeeping of an LRU would buy nothing
// but a second map to keep consistent.
func (r *Resolver) evictLocked() {
	now := r.now()
	var (
		oldest   string
		oldestAt time.Time
	)
	for key, e := range r.cache {
		if !now.Before(e.expires) {
			delete(r.cache, key)
			continue
		}
		if oldest == "" || e.expires.Before(oldestAt) {
			oldest, oldestAt = key, e.expires
		}
	}
	if len(r.cache) >= r.maxEntries && oldest != "" {
		delete(r.cache, oldest)
	}
}

// systemLookup is the default LookupFunc. IPv6 zones cannot be carried in a
// net.IP, so a scoped answer loses its zone; a name that only resolves to a
// link-local address is not reachable anyway.
func systemLookup(ctx context.Context, host string) ([]net.IP, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		ips = append(ips, addr.IP)
	}
	return ips, nil
}

// isNotFound reports whether a lookup failure means "this name has no
// address", which is the only failure worth remembering.
func isNotFound(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.IsNotFound
	}
	return errors.Is(err, ErrNotFound)
}

// normalise brings a name to the form the table and the cache are keyed by:
// lower case, no trailing dot, no surrounding space.
func normalise(host string) (string, error) {
	name := strings.ToLower(strings.TrimSpace(host))
	name = strings.TrimSuffix(name, ".")
	switch {
	case name == "":
		return "", fmt.Errorf("%w: %q is empty", ErrInvalidName, host)
	case len(name) > maxNameLen:
		return "", fmt.Errorf("%w: %q is longer than %d bytes", ErrInvalidName, host, maxNameLen)
	case strings.ContainsAny(name, " \t\r\n/\\"):
		return "", fmt.Errorf("%w: %q contains a separator", ErrInvalidName, host)
	case strings.HasPrefix(name, "."), strings.Contains(name, ".."), strings.HasSuffix(name, "."):
		return "", fmt.Errorf("%w: %q has an empty label", ErrInvalidName, host)
	}
	return name, nil
}

// dedupeIPs removes repeated addresses while keeping the order of the answer,
// so a name with both A and AAAA records keeps the preference the resolver
// reported.
func dedupeIPs(ips []net.IP) []net.IP {
	out := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		seen := false
		for _, kept := range out {
			if kept.Equal(ip) {
				seen = true
				break
			}
		}
		if !seen {
			out = append(out, ip)
		}
	}
	return out
}

// cloneIPs copies a list of addresses so a caller cannot mutate cached state.
func cloneIPs(ips []net.IP) []net.IP {
	if len(ips) == 0 {
		return nil
	}
	out := make([]net.IP, len(ips))
	for i, ip := range ips {
		out[i] = append(net.IP(nil), ip...)
	}
	return out
}
