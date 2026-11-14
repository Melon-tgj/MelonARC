// Package policy defines the outbound abstraction and the Select, URL-Test
// and Fallback policy groups built on top of it.
package policy

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Kind is the behaviour of a policy group.
type Kind string

// The three group behaviours of the MVP.
const (
	// KindSelect routes every request to the member the user picked.
	KindSelect Kind = "select"
	// KindURLTest probes its members and routes to the fastest healthy one.
	KindURLTest Kind = "url-test"
	// KindFallback routes to the first healthy member in declaration order.
	KindFallback Kind = "fallback"
)

// Errors reported by groups and the registry.
var (
	// ErrUnknownMember is returned when a name is not a member of the group.
	ErrUnknownMember = errors.New("policy: unknown member")
	// ErrNotManual is returned when a manual selection is attempted on a group
	// that decides on its own.
	ErrNotManual = errors.New("policy: group does not accept a manual selection")
	// ErrUnknownTarget is returned when a name is neither a leaf nor a group.
	ErrUnknownTarget = errors.New("policy: unknown target")
	// ErrDuplicate is returned when a name is registered twice.
	ErrDuplicate = errors.New("policy: name is already registered")
	// ErrCycle is returned when group membership loops back on itself.
	ErrCycle = errors.New("policy: group cycle")
)

// Prober measures the round trip time to a member. The probe is the only
// network facing part of a group and it is injected, so group behaviour can be
// tested without any network.
type Prober interface {
	Probe(ctx context.Context, member string) (time.Duration, error)
}

// ProbeFunc adapts a function to the Prober interface.
type ProbeFunc func(ctx context.Context, member string) (time.Duration, error)

// Probe implements Prober.
func (f ProbeFunc) Probe(ctx context.Context, member string) (time.Duration, error) {
	return f(ctx, member)
}

// Group is a policy group: an ordered set of members plus the rule that picks
// one of them.
type Group interface {
	// Name is the name rules and other groups use to refer to the group.
	Name() string
	// Kind is the group behaviour.
	Kind() Kind
	// Members lists the member names in declaration order.
	Members() []string
	// Active is the member the group currently routes to. It never returns an
	// empty string for a group with members.
	Active() string
	// Select pins the group to a member. Only KindSelect groups accept it.
	Select(name string) error
	// Start begins the group's background work, which is periodic probing for
	// the groups that need it and nothing for a manual group.
	Start(ctx context.Context)
	// NotifyFailure reports that a member failed in use, so the group can move
	// on without waiting for the next probe round.
	NotifyFailure(name string)
	// Status is a snapshot for the local API.
	Status() Status
	// Close stops background probing.
	Close()
}

// Status is a snapshot of a group.
type Status struct {
	Name    string         `json:"name"`
	Kind    Kind           `json:"kind"`
	Active  string         `json:"active"`
	Members []MemberStatus `json:"members"`
	// Checked is the time of the last probe round, zero when never probed.
	Checked time.Time `json:"checked,omitempty"`
	// AllUnhealthy reports that every member was probed and failed, so the
	// group has no healthy member to move to. A group that has never been
	// probed is not all-unhealthy: an unprobed member is treated as up.
	AllUnhealthy bool `json:"all_unhealthy"`
}

// MemberStatus is the health of one member.
type MemberStatus struct {
	Name    string        `json:"name"`
	Latency time.Duration `json:"latency"`
	Healthy bool          `json:"healthy"`
	// Checked is false before the member has been probed; such a member is
	// treated as healthy so that a group works before its first probe.
	Checked bool `json:"checked"`
	// CheckedAt is when the member was last probed, or when it last failed in
	// use. It is zero when neither has happened.
	CheckedAt time.Time `json:"checked_at,omitempty"`
	// Failures is the number of consecutive failures. A healthy probe resets
	// it to zero; a failed probe or a failure in use adds one.
	Failures int `json:"failures"`
	// Error is the most recent failure, shortened. It is empty after a healthy
	// probe.
	Error string `json:"error,omitempty"`
}

// probeResult is what a probe round learned about one member.
type probeResult struct {
	latency time.Duration
	healthy bool
	checked bool
	at      time.Time
	// err is the reason the probe failed, nil after a healthy one.
	err error
	// failures counts consecutive failures, probe rounds and failures in use
	// alike.
	failures int
}

// Resolution is the outcome of following a target through nested groups.
type Resolution struct {
	// Path starts at the requested name and ends at the leaf.
	Path []string
	// Leaf is the outbound or built-in action that finally handles the request.
	Leaf string
}

// String renders the resolution as "a -> b -> c".
func (r Resolution) String() string {
	return joinPath(r.Path)
}

// Registry holds every routable name: the leaves (proxies and the built-in
// DIRECT / REJECT actions) and the policy groups. It is safe for concurrent use.
type Registry struct {
	mu     sync.RWMutex
	leaves map[string]struct{}
	groups map[string]Group
	order  []string
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{leaves: make(map[string]struct{}), groups: make(map[string]Group)}
}

// AddLeaf registers a terminal target such as a proxy or a built-in action.
func (r *Registry) AddLeaf(name string) error {
	if name == "" {
		return fmt.Errorf("%w: empty name", ErrDuplicate)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.leaves[name]; ok {
		return fmt.Errorf("%w: %s", ErrDuplicate, name)
	}
	if _, ok := r.groups[name]; ok {
		return fmt.Errorf("%w: %s", ErrDuplicate, name)
	}
	r.leaves[name] = struct{}{}
	r.order = append(r.order, name)
	return nil
}

// AddGroup registers a policy group.
func (r *Registry) AddGroup(g Group) error {
	if g == nil {
		return errors.New("policy: nil group")
	}
	name := g.Name()
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.groups[name]; ok {
		return fmt.Errorf("%w: %s", ErrDuplicate, name)
	}
	if _, ok := r.leaves[name]; ok {
		return fmt.Errorf("%w: %s", ErrDuplicate, name)
	}
	r.groups[name] = g
	r.order = append(r.order, name)
	return nil
}

// Group returns a registered group by name.
func (r *Registry) Group(name string) (Group, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	g, ok := r.groups[name]
	return g, ok
}

// Names lists every registered name, sorted.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := append([]string(nil), r.order...)
	sort.Strings(out)
	return out
}

// Selections returns the member every manual group currently routes to, keyed
// by group name.
//
// It is the state a reload has to carry across: a reload builds a whole new
// registry, and the one thing in the old one that belongs to the user rather
// than to the configuration file is the member they picked. Groups that decide
// on their own are left out — their member is a probe result, and the next
// probe round produces a fresh one anyway.
func (r *Registry) Selections() map[string]string {
	groups := r.Groups()
	out := make(map[string]string, len(groups))
	for _, g := range groups {
		if g.Kind() != KindSelect {
			continue
		}
		if active := g.Active(); active != "" {
			out[g.Name()] = active
		}
	}
	return out
}

// Groups lists the registered groups, sorted by name.
func (r *Registry) Groups() []Group {
	r.mu.RLock()
	out := make([]Group, 0, len(r.groups))
	for _, g := range r.groups {
		out = append(out, g)
	}
	r.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

// Resolve follows a target through nested groups until it reaches a leaf.
func (r *Registry) Resolve(name string) (Resolution, error) {
	r.mu.RLock()
	_, isLeaf := r.leaves[name]
	g, isGroup := r.groups[name]
	r.mu.RUnlock()

	if isLeaf {
		return Resolution{Path: []string{name}, Leaf: name}, nil
	}
	if !isGroup {
		return Resolution{}, fmt.Errorf("%w: %s", ErrUnknownTarget, name)
	}

	path := []string{name}
	seen := map[string]bool{name: true}
	current := g
	for {
		next := current.Active()
		path = append(path, next)
		r.mu.RLock()
		_, leaf := r.leaves[next]
		nested, group := r.groups[next]
		r.mu.RUnlock()
		switch {
		case leaf:
			return Resolution{Path: path, Leaf: next}, nil
		case group:
			if seen[next] {
				return Resolution{Path: path}, fmt.Errorf("%w: %s", ErrCycle, joinPath(path))
			}
			seen[next] = true
			current = nested
		default:
			return Resolution{Path: path}, fmt.Errorf("%w: %s", ErrUnknownTarget, next)
		}
	}
}

// Close stops every group's background work.
func (r *Registry) Close() {
	for _, g := range r.Groups() {
		g.Close()
	}
}

// joinPath renders a path as "a -> b".
func joinPath(path []string) string {
	out := ""
	for i, p := range path {
		if i > 0 {
			out += " -> "
		}
		out += p
	}
	return out
}

// validateMembers rejects an empty member list and duplicate members.
func validateMembers(name string, members []string) error {
	if len(members) == 0 {
		return fmt.Errorf("policy: group %q has no members", name)
	}
	seen := make(map[string]bool, len(members))
	for _, m := range members {
		if m == "" {
			return fmt.Errorf("policy: group %q has an empty member name", name)
		}
		if seen[m] {
			return fmt.Errorf("policy: group %q lists %q twice", name, m)
		}
		seen[m] = true
	}
	return nil
}
