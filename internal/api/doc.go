// Package api serves the loopback-only HTTP/JSON API that the CLI and the
// desktop UI both consume, guarded by a random token.
//
// The listener refuses any address that is not loopback, and every request has
// to carry the token generated at startup. This stage exposes read-only
// endpoints (health, status, configuration, rules, policies and rule match
// explanation) on top of a Provider; write endpoints are added in a later
// stage without changing the transport.
package api
