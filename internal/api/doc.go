// Package api serves the loopback-only HTTP/JSON API that the CLI and the
// desktop UI both consume, guarded by a random token.
//
// The listener refuses any address that is not loopback, and every request has
// to carry the token generated at startup. The read endpoints report health,
// status, configuration, rules, policies, rule match explanation, inbound
// counters, recent failures, resolver statistics, subscription refresh state and
// the audit record; the two write endpoints pin a manual policy group to a
// member and reload the configuration file.
//
// A subscription's skipped entries are a page of their own rather than a field
// of its summary: a provider that serves a broken list would otherwise make
// every ordinary read carry the whole explanation of what went wrong.
//
// A write either takes full effect or changes nothing. Each one is recorded in
// a bounded audit log with its time, action and outcome, which is served by
// /v1/audit and mirrored to the process log.
//
// Every endpoint reports state, never content: the failure record carries the
// destination and a category, and the resolver view reports counts, because the
// [Host] table names internal services.
package api
