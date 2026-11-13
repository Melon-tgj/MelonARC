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
}

// String renders the explanation as an indented report, one line per step.
func (e *Explanation) String() string {
	var b strings.Builder
	b.WriteString("query: ")
	b.WriteString(describeQuery(e.Query))
	b.WriteString("\n")
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
