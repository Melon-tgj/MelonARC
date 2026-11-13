package inbound

import (
	"context"
	"errors"
	"net"
	"syscall"
	"time"

	"github.com/melon-tgj/melonarc/internal/dns"
	"github.com/melon-tgj/melonarc/internal/outbound"
)

// The stages a request can fail in.
const (
	// StageRoute covers everything before a dial: no rule matched, the policy
	// target is unknown, the resolution looped.
	StageRoute = "route"
	// StageDial covers the outbound that could not carry the request.
	StageDial = "dial"
)

// The reasons a request was not carried, reduced to a category.
//
// A category is deliberately coarse: it says what an operator needs to know to
// decide where to look, and it never repeats a remote message, a payload or
// anything else that grows with traffic.
const (
	// CategoryRejected is a destination a rule blocks on purpose.
	CategoryRejected = "rejected"
	// CategoryUnsupported is a protocol this build does not implement.
	CategoryUnsupported = "unsupported"
	// CategoryRefused is a peer that refused the connection.
	CategoryRefused = "refused"
	// CategoryTimeout is a dial or handshake that ran out of time.
	CategoryTimeout = "timeout"
	// CategoryCancelled is a request abandoned because the listener stopped or
	// the client went away.
	CategoryCancelled = "cancelled"
	// CategoryUnreachable is a network or host that could not be reached.
	CategoryUnreachable = "unreachable"
	// CategoryResolve is a name that did not resolve.
	CategoryResolve = "resolve"
	// CategoryUnroutable is a destination no policy could be chosen for.
	CategoryUnroutable = "unroutable"
	// CategoryUnknown is a failure none of the above describes.
	CategoryUnknown = "unknown"
)

// Failure is one request that was not carried, reduced to the fields an
// operator needs.
//
// It holds the destination, the stage, the category and the policy that was
// chosen; nothing a connection transmitted is ever recorded, and the error text
// is reduced to a category so a record cannot grow with a remote message.
type Failure struct {
	// Time is when the request failed.
	Time time.Time
	// Target is the destination as the client asked for it: "host:port", where
	// the host is a name or an IP literal.
	Target string
	// Network is "tcp" or "udp".
	Network string
	// Stage is StageRoute or StageDial.
	Stage string
	// Category is one of the Category constants.
	Category string
	// Policy is the rule target that was chosen, empty when no rule matched.
	Policy string
}

// categorize reduces a failure to a category. The stage matters: a failure
// before a dial is about the routing table, not about the network.
func categorize(stage string, err error) string {
	switch {
	case err == nil:
		return CategoryUnknown
	case errors.Is(err, outbound.ErrRejected):
		return CategoryRejected
	case errors.Is(err, outbound.ErrUnsupported), errors.Is(err, outbound.ErrUnknownDialer):
		return CategoryUnsupported
	}
	if stage == StageRoute {
		// Nothing else can go wrong before a dial: the destination has no
		// usable policy.
		return CategoryUnroutable
	}
	switch {
	case errors.Is(err, context.Canceled):
		return CategoryCancelled
	case errors.Is(err, context.DeadlineExceeded):
		return CategoryTimeout
	case errors.Is(err, dns.ErrNotFound), errors.Is(err, dns.ErrInvalidName):
		return CategoryResolve
	case errors.Is(err, syscall.ECONNREFUSED):
		return CategoryRefused
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH):
		return CategoryUnreachable
	}
	// A lookup failure that reached the dialer keeps its *net.DNSError shape
	// through the wrapping of the outbound layer.
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return CategoryResolve
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return CategoryTimeout
	}
	return CategoryUnknown
}
