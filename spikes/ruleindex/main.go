// Command ruleindex reports how fast a 100k rule matcher answers queries.
//
//	go run ./spikes/ruleindex
package main

import (
	"fmt"
	"log"
	"runtime"
	"time"
)

const (
	domainRules = 50000
	cidrRules   = 50000
	queries     = 200000
	seed        = 42
)

// sink keeps results observable so the calls below cannot be optimised away.
var sink int

func main() {
	log.SetFlags(0)
	log.SetPrefix("ruleindex: ")

	ds := generate(domainRules, cidrRules, seed)
	ix := NewIndex()

	start := time.Now()
	ds.build(ix)
	buildTook := time.Since(start)

	domains, cidrs, ranges := ix.Stats()
	fmt.Printf("rules: %d domain suffix + %d ip-cidr = %d total\n", domains, cidrs, domains+cidrs)
	fmt.Printf("index: %d disjoint ip ranges, built in %s\n", ranges, buildTook.Round(time.Microsecond))

	var m runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m)
	fmt.Printf("heap after build: %.1f MiB (allocated in total %.1f MiB)\n",
		float64(m.HeapAlloc)/(1<<20), float64(m.TotalAlloc)/(1<<20))

	report("domain", queries, func(i int) bool {
		_, ok := ix.MatchDomain(ds.hosts[i%len(ds.hosts)])
		return ok
	})
	report("ip", queries, func(i int) bool {
		_, ok := ix.MatchUint32(ds.addrs[i%len(ds.addrs)])
		return ok
	})
	report("mixed", queries, func(i int) bool {
		if i%2 == 0 {
			_, ok := ix.Match(ds.hosts[i%len(ds.hosts)])
			return ok
		}
		_, ok := ix.MatchUint32(ds.addrs[i%len(ds.addrs)])
		return ok
	})

	hits := countHits(ix, ds, queries)
	fmt.Printf("hit rate over %d probes: %.1f%%\n", queries, 100*float64(hits)/float64(queries))
}

// countHits walks the same probe mix and reports how many lookups matched.
func countHits(ix *Index, ds *dataset, n int) int {
	hits := 0
	for i := 0; i < n; i++ {
		var ok bool
		if i%2 == 0 {
			_, ok = ix.Match(ds.hosts[i%len(ds.hosts)])
		} else {
			_, ok = ix.MatchUint32(ds.addrs[i%len(ds.addrs)])
		}
		if ok {
			hits++
		}
	}
	return hits
}

// report times fn over n calls and prints the average.
func report(label string, n int, fn func(int) bool) {
	start := time.Now()
	for i := 0; i < n; i++ {
		if fn(i) {
			sink++
		}
	}
	elapsed := time.Since(start)
	fmt.Printf("%-7s %6d lookups in %8s  avg %s\n",
		label, n, elapsed.Round(time.Millisecond), (elapsed / time.Duration(n)).Round(time.Nanosecond))
}
