// Package dns resolves destination names for the routing pipeline.
//
// A lookup answers in this order: the [Host] table, the cache, the configured
// plaintext upstream, then the system resolver. Positive and negative answers
// are both cached, and concurrent lookups of the same name share one query, so a
// burst of connections to one host cannot turn into a burst of lookups.
//
// An upstream answer decides its own lifetime: the cache entry expires when the
// shortest lived record of the answer does, and a negative answer is kept for
// the lifetime its SOA record asked for. Both are clamped to fixed bounds, so a
// server cannot switch the cache off with a one second TTL or pin a stale
// address with a one week one. A source that reports no lifetime at all — the
// [Host] table, or the system resolver — keeps the configured default instead,
// and the static table never expires at all.
//
// The package writes to the network only through the Upstream type, whose
// datagram and stream clients are bounded by a per attempt timeout and by the
// caller's context. Everything else works on injected functions, which is what
// keeps the cache, the lifetimes and the coalescing testable without sockets.
package dns
