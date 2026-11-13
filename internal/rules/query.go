package rules

import (
	"fmt"
	"net"
	"strings"
)

// Query describes one request to classify. Fields that are unknown are left at
// their zero value: an empty name, a nil address, port 0 or an empty network.
type Query struct {
	// Name is the destination host name, when the request carries one.
	Name string
	// Addr is the destination address, when it is already known.
	Addr []byte
	// Resolved reports that Addr was obtained by looking Name up rather than
	// supplied by the client. An address rule carrying no-resolve only applies
	// to an address the client supplied, so this flag decides whether such a
	// rule may fire: a name the caller refused to resolve must never gain an
	// address rule through the back door of a lookup done for another rule.
	Resolved bool
	// Port is the destination port; 0 means unknown.
	Port int
	// Network is the transport protocol, "tcp" or "udp"; empty means unknown.
	Network string
}

// Decision is the outcome of a match: the rule that won and the target it
// dispatches to.
type Decision struct {
	Rule   *Rule
	Target string
}

// String implements fmt.Stringer.
func (d Decision) String() string {
	if d.Rule == nil {
		return "no match"
	}
	return fmt.Sprintf("#%d %s -> %s", d.Rule.Index(), d.Rule.String(), d.Target)
}

// Step is one entry of a decision path. Steps are recorded for every query
// dimension the engine consulted, whether it matched or not, plus one final
// step for the decision itself.
type Step struct {
	Kind   Kind
	Index  int
	Rule   *Rule
	Match  bool
	Detail string
}

// Explanation is a full accounting of how a query was classified.
type Explanation struct {
	Query    Query
	Decision Decision
	Matched  bool
	Steps    []Step
	// Resolution records the lookup that turned the query name into an
	// address, when the caller performed one. The engine never resolves
	// anything itself: it only renders what it is told, so the report shows
	// whether a lookup happened and where the answer came from.
	Resolution *Resolution
}

// Resolution describes how a name became an address before matching.
type Resolution struct {
	// Source is where the address came from: "hosts" for a static mapping,
	// "cache" for a cached answer, "system" for a fresh system lookup. It is
	// empty when no lookup was made.
	Source string
	// Addrs are the addresses the name resolved to.
	Addrs []net.IP
	// Err is the lookup failure, when the name could not be resolved. Matching
	// still proceeds without an address: domain rules stay usable and an
	// outbound that resolves remotely may still reach the destination.
	Err string
	// Note says why no lookup was made, when Source is empty.
	Note string
}

// String renders the explanation as an indented report, one line per step.
func (e *Explanation) String() string {
	var b strings.Builder
	b.WriteString("query: ")
	b.WriteString(describeQuery(e.Query))
	b.WriteString("\n")
	if e.Resolution != nil {
		b.WriteString("resolution: ")
		b.WriteString(e.Resolution.String())
		b.WriteString("\n")
	}
	for i, s := range e.Steps {
		fmt.Fprintf(&b, "  %2d. %-16s %-4s %s\n", i+1, s.Kind, verdict(s.Match), s.Detail)
	}
	if e.Matched {
		fmt.Fprintf(&b, "decision: %s\n", e.Decision.String())
	} else {
		b.WriteString("decision: no rule matched\n")
	}
	return b.String()
}

// String renders the lookup in one line: where the address came from, or why
// there is none.
func (r *Resolution) String() string {
	switch {
	case r.Err != "":
		return "failed: " + r.Err
	case r.Source == "" && r.Note != "":
		return "not attempted: " + r.Note
	case r.Source == "":
		return "not attempted"
	}
	addrs := make([]string, 0, len(r.Addrs))
	for _, ip := range r.Addrs {
		addrs = append(addrs, ip.String())
	}
	return fmt.Sprintf("%s (%s)", strings.Join(addrs, ", "), r.Source)
}

func verdict(ok bool) string {
	if ok {
		return "hit"
	}
	return "miss"
}

// describeQuery renders a query compactly for reports.
func describeQuery(q Query) string {
	name := q.Name
	if name == "" {
		name = "-"
	}
	addr := "-"
	if len(q.Addr) > 0 {
		addr = ipString(q.Addr)
		if q.Resolved {
			addr += "(resolved)"
		}
	}
	port := "-"
	if q.Port > 0 {
		port = fmt.Sprint(q.Port)
	}
	network := q.Network
	if network == "" {
		network = "-"
	}
	return fmt.Sprintf("name=%s addr=%s port=%s network=%s", name, addr, port, network)
}

// ipString renders an address held as raw bytes.
func ipString(b []byte) string {
	if ip := net.IP(b); ip != nil {
		return ip.String()
	}
	return "-"
}
