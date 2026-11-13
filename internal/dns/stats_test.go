package dns

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
)

// TestStatsCountCacheHitsAndMisses walks one name through the three outcomes a
// lookup can have and checks the counters an operator reads.
func TestStatsCountCacheHitsAndMisses(t *testing.T) {
	lookup := &scriptedLookup{answer: fixedIPs("198.51.100.7")}
	r := newResolver(t, Options{}, lookup, newClock())
	ctx := context.Background()

	if _, err := r.Resolve(ctx, "a.example.com"); err != nil {
		t.Fatalf("first Resolve: %v", err)
	}
	if _, err := r.Resolve(ctx, "a.example.com"); err != nil {
		t.Fatalf("second Resolve: %v", err)
	}

	st := r.Stats()
	if st.CacheMisses != 1 || st.CacheHits != 1 {
		t.Fatalf("cache = %d hits / %d misses, want 1 and 1", st.CacheHits, st.CacheMisses)
	}
	if st.Succeeded != 2 || st.Failed != 0 {
		t.Fatalf("outcomes = %d succeeded / %d failed, want 2 and 0", st.Succeeded, st.Failed)
	}
	if st.Entries != 1 {
		t.Fatalf("entries = %d, want 1", st.Entries)
	}
	if st.MaxEntries != DefaultMaxEntries {
		t.Fatalf("max entries = %d, want %d", st.MaxEntries, DefaultMaxEntries)
	}
	if got := lookup.count(); got != 1 {
		t.Fatalf("upstream lookups = %d, want 1", got)
	}
}

// TestStatsCountFailuresAndNegativeHits checks the failure side: a negative
// answer counts as a failure once and as a cache hit afterwards.
func TestStatsCountFailuresAndNegativeHits(t *testing.T) {
	lookup := &scriptedLookup{answer: func(string) ([]net.IP, error) {
		return nil, &net.DNSError{Err: "no such host", Name: "missing.example", IsNotFound: true}
	}}
	r := newResolver(t, Options{}, lookup, newClock())
	ctx := context.Background()

	if _, err := r.Resolve(ctx, "missing.example"); err == nil {
		t.Fatal("a nonexistent name resolved")
	}
	if _, err := r.Resolve(ctx, "missing.example"); err == nil {
		t.Fatal("the cached negative answer turned into a success")
	}

	st := r.Stats()
	if st.Failed != 2 || st.Succeeded != 0 {
		t.Fatalf("outcomes = %d succeeded / %d failed, want 0 and 2", st.Succeeded, st.Failed)
	}
	if st.CacheMisses != 1 || st.CacheHits != 1 {
		t.Fatalf("cache = %d hits / %d misses, want 1 and 1", st.CacheHits, st.CacheMisses)
	}
}

// TestStatsIgnoreStaticAndLiteralAnswers makes sure the cache counters describe
// the cache: a [Host] answer and an address literal never touch it.
func TestStatsIgnoreStaticAndLiteralAnswers(t *testing.T) {
	lookup := &scriptedLookup{answer: fixedIPs("198.51.100.7")}
	r := newResolver(t, Options{
		Hosts: map[string][]net.IP{"cdn.example.com": {net.ParseIP("203.0.113.9")}},
	}, lookup, newClock())
	ctx := context.Background()

	if _, err := r.Resolve(ctx, "cdn.example.com"); err != nil {
		t.Fatalf("mapped Resolve: %v", err)
	}
	if _, err := r.Resolve(ctx, "203.0.113.9"); err != nil {
		t.Fatalf("literal Resolve: %v", err)
	}

	st := r.Stats()
	if st.CacheHits != 0 || st.CacheMisses != 0 {
		t.Fatalf("cache = %d hits / %d misses, want none", st.CacheHits, st.CacheMisses)
	}
	if st.Succeeded != 2 || st.Entries != 0 {
		t.Fatalf("stats = %+v, want two successes and an empty cache", st)
	}
	if got := lookup.count(); got != 0 {
		t.Fatalf("upstream lookups = %d, want 0", got)
	}
}

// TestStatsAreConcurrencySafe reads the counters while lookups run.
func TestStatsAreConcurrencySafe(t *testing.T) {
	lookup := &scriptedLookup{answer: fixedIPs("198.51.100.7")}
	r := newResolver(t, Options{}, lookup, newClock())
	ctx := context.Background()

	const workers, rounds = 8, 25
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < rounds; j++ {
				_, _ = r.Resolve(ctx, "a.example.com")
				_ = r.Stats()
			}
		}()
	}
	wg.Wait()

	st := r.Stats()
	if want := uint64(workers * rounds); st.Succeeded != want {
		t.Fatalf("succeeded = %d, want %d", st.Succeeded, want)
	}
	// A resolution either hits the cache, runs the upstream query, or joins one
	// already in flight. The third case is why the two cache counters may add
	// up to less than the number of resolutions, but only one caller can ever
	// be the leader.
	if st.CacheMisses != 1 {
		t.Fatalf("misses = %d, want a single upstream query", st.CacheMisses)
	}
	if st.CacheHits+st.CacheMisses > st.Succeeded {
		t.Fatalf("cache counters %d+%d exceed %d resolutions",
			st.CacheHits, st.CacheMisses, st.Succeeded)
	}
	if st.CacheHits == 0 {
		t.Fatal("no resolution was answered from the cache")
	}
}

// TestStatsNeverLeakHostContent is the confidentiality check: the statistics are
// numbers, and the [Host] table stays inside the resolver.
func TestStatsNeverLeakHostContent(t *testing.T) {
	lookup := &scriptedLookup{answer: func(string) ([]net.IP, error) {
		return nil, errors.New("unused")
	}}
	r := newResolver(t, Options{
		Hosts: map[string][]net.IP{"secret.internal": {net.ParseIP("10.0.0.5")}},
	}, lookup, newClock())

	st := r.Stats()
	if st != (Stats{MaxEntries: DefaultMaxEntries}) {
		t.Fatalf("stats = %+v, want zero counters and the cache capacity", st)
	}
}
