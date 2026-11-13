package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/melon-tgj/melonarc/internal/api"
	"github.com/melon-tgj/melonarc/internal/config"
	"github.com/melon-tgj/melonarc/internal/dns"
	"github.com/melon-tgj/melonarc/internal/inbound"
	"github.com/melon-tgj/melonarc/internal/policy"
	"github.com/melon-tgj/melonarc/internal/rules"
)

// defaultRulePage is the number of rules returned when the client does not ask
// for a specific page. A large rule set is never serialised in full by default.
const defaultRulePage = 1000

// daemonState adapts the compiled configuration to the API views.
//
// A reload replaces the whole routing configuration while the API is answering
// requests, so every field a reload touches sits behind one mutex and every
// method takes a snapshot before reading. The handler is deliberately not part
// of that snapshot: it owns its own atomic pointer, and the listeners keep
// referring to the same object across reloads.
type daemonState struct {
	mu       sync.RWMutex
	cfg      *config.Config
	program  *rules.Program
	registry *policy.Registry
	resolver *dns.Resolver

	handler   *inbound.Handler
	metrics   *inbound.Metrics
	version   string
	startedAt time.Time

	// reload is installed once, before the API starts serving. A state built
	// without one answers the reload endpoint with a clear refusal instead of
	// panicking.
	reload func(context.Context) (api.ReloadView, error)
}

// stateSnapshot is the part of the state a reload replaces.
type stateSnapshot struct {
	cfg      *config.Config
	program  *rules.Program
	registry *policy.Registry
	resolver *dns.Resolver
}

// snapshot returns the configuration currently in force.
func (s *daemonState) snapshot() stateSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return stateSnapshot{cfg: s.cfg, program: s.program, registry: s.registry, resolver: s.resolver}
}

// install replaces the configuration and returns the previous one, so the
// caller can stop whatever it was running.
func (s *daemonState) install(next stateSnapshot) stateSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	previous := stateSnapshot{cfg: s.cfg, program: s.program, registry: s.registry, resolver: s.resolver}
	s.cfg, s.program, s.registry, s.resolver = next.cfg, next.program, next.registry, next.resolver
	return previous
}

// Status implements api.Provider.
func (s *daemonState) Status(context.Context) api.StatusView {
	snap := s.snapshot()
	cfgPath := ""
	if snap.cfg != nil {
		cfgPath = snap.cfg.Path
	}
	return api.StatusView{
		Version:       s.version,
		StartedAt:     s.startedAt,
		UptimeSeconds: time.Since(s.startedAt).Seconds(),
		ConfigPath:    cfgPath,
		RuleCount:     snap.program.Len(),
		PolicyCount:   len(snap.registry.Groups()),
	}
}

// Config implements api.Provider. Only the fields needed to describe the
// configuration are exposed; proxy arguments may hold credentials and the [Host]
// table names internal services, so both are left out. The number of mappings is
// reported so an operator can tell the section was read at all.
func (s *daemonState) Config(context.Context) api.ConfigView {
	cfg := s.snapshot().cfg
	fallback := config.DNSFallbackSystem
	if !cfg.General.FallbackToSystem() {
		fallback = config.DNSFallbackNone
	}
	view := api.ConfigView{
		LogLevel:     cfg.General.LogLevel,
		APIListen:    cfg.General.APIListen,
		HTTPListen:   cfg.General.HTTPListen,
		SOCKS5Listen: cfg.General.SOCKS5Listen,
		Path:         cfg.Path,
		Proxies:      make([]api.ProxyView, 0, len(cfg.Proxies)),
		Groups:       make([]api.GroupView, 0, len(cfg.Groups)),
		RuleSets:     make([]api.RuleSetView, 0, len(cfg.RuleSets)),
		HostCount:    len(cfg.Hosts),
		NameServers:  append([]string{}, cfg.General.NameServers...),
		DNSFallback:  fallback,
		GeoIPDB:      cfg.DataPath(cfg.General.GeoIPDB),
		ASNDB:        cfg.DataPath(cfg.General.ASNDB),
	}
	for _, p := range cfg.Proxies {
		view.Proxies = append(view.Proxies, api.ProxyView{
			Name: p.Name, Type: p.Type, Server: p.Server, Port: p.Port,
		})
	}
	for _, g := range cfg.Groups {
		view.Groups = append(view.Groups, api.GroupView{
			Name:            g.Name,
			Type:            string(g.Type),
			Members:         append([]string(nil), g.Members...),
			URL:             g.URL,
			IntervalSeconds: int(g.Interval / time.Second),
		})
	}
	for _, rs := range cfg.RuleSets {
		view.RuleSets = append(view.RuleSets, api.RuleSetView{Name: rs.Name, Path: rs.Path})
	}
	return view
}

// Rules implements api.Provider.
func (s *daemonState) Rules(_ context.Context, limit int) api.RuleListView {
	program := s.snapshot().program
	if limit <= 0 {
		limit = defaultRulePage
	}
	all := program.Rules()
	total := len(all)
	if limit > total {
		limit = total
	}
	rules := make([]api.RuleView, 0, limit)
	for _, r := range all[:limit] {
		rules = append(rules, ruleView(r))
	}
	return api.RuleListView{Total: total, Limit: limit, Rules: rules}
}

// Policies implements api.Provider.
func (s *daemonState) Policies(context.Context) []api.PolicyView {
	groups := s.snapshot().registry.Groups()
	out := make([]api.PolicyView, 0, len(groups))
	for _, g := range groups {
		st := g.Status()
		view := api.PolicyView{
			Name:         st.Name,
			Type:         string(st.Kind),
			Active:       st.Active,
			AllUnhealthy: st.AllUnhealthy,
			Members:      make([]api.MemberView, 0, len(st.Members)),
		}
		if !st.Checked.IsZero() {
			view.Checked = st.Checked.UTC().Format(time.RFC3339)
		}
		for _, m := range st.Members {
			if m.Healthy {
				view.HealthyMembers++
			}
			view.Members = append(view.Members, api.MemberView{
				Name:      m.Name,
				Healthy:   m.Healthy,
				Checked:   m.Checked,
				LatencyMS: float64(m.Latency) / float64(time.Millisecond),
				CheckedAt: formatOptionalTime(m.CheckedAt),
				Failures:  m.Failures,
				Error:     m.Error,
			})
		}
		out = append(out, view)
	}
	return out
}

// SelectPolicy implements api.Provider: it pins a manual group to a member.
//
// The refusals carry the reason a caller can act on — the group does not exist,
// the group decides on its own, the member is not one of its members and here is
// the list — because "400" alone would leave a CLI user guessing.
func (s *daemonState) SelectPolicy(_ context.Context, group, member string) (api.SelectView, error) {
	registry := s.snapshot().registry
	g, ok := registry.Group(group)
	if !ok {
		return api.SelectView{}, api.NotFound("unknown_group",
			fmt.Sprintf("no policy group is named %q", group))
	}
	if g.Kind() != policy.KindSelect {
		return api.SelectView{}, api.Conflict("not_selectable",
			fmt.Sprintf("%q is a %s group: it picks its member from probe results, not from a request", group, g.Kind()))
	}
	previous := g.Active()
	if err := g.Select(member); err != nil {
		if errors.Is(err, policy.ErrUnknownMember) {
			return api.SelectView{}, api.BadRequest("unknown_member",
				fmt.Sprintf("%q is not a member of %q; its members are %s",
					member, group, strings.Join(g.Members(), ", ")))
		}
		return api.SelectView{}, err
	}
	return api.SelectView{Group: group, Previous: previous, Active: g.Active()}, nil
}

// ReloadConfig implements api.Provider by delegating to the reloader the daemon
// installed at startup.
func (s *daemonState) ReloadConfig(ctx context.Context) (api.ReloadView, error) {
	if s.reload == nil {
		return api.ReloadView{}, api.Conflict("reload_unavailable",
			"this daemon was started without a reloader, so the configuration can only be changed by restarting it")
	}
	return s.reload(ctx)
}

// Inbound implements api.Provider.
func (s *daemonState) Inbound(context.Context) api.InboundView {
	snap := s.metrics.Snapshot()
	view := api.InboundView{
		Inbounds:           make([]api.InboundStatsView, 0, len(snap.Protocols)),
		Failures:           snap.Failures,
		Rejected:           snap.Rejected,
		FailureLogCapacity: snap.FailureCapacity,
		FailureLogCount:    snap.FailureCount,
	}
	for _, p := range snap.Protocols {
		view.Inbounds = append(view.Inbounds, api.InboundStatsView{
			Protocol:       p.Protocol,
			Open:           p.Open,
			Accepted:       p.Accepted,
			Datagrams:      p.Datagrams,
			DatagramsTotal: p.DatagramTotal,
		})
		view.Open += p.Open
		view.Accepted += p.Accepted
	}
	return view
}

// Failures implements api.Provider. It serves the records the inbound layer
// keeps; the count is how many it holds, so a client can tell a limit from an
// empty record.
func (s *daemonState) Failures(_ context.Context, limit int) api.FailureListView {
	records := s.metrics.Recent(limit)
	snap := s.metrics.Snapshot()
	view := api.FailureListView{
		Capacity: snap.FailureCapacity,
		Count:    snap.FailureCount,
		Failures: make([]api.FailureView, 0, len(records)),
	}
	for _, f := range records {
		view.Failures = append(view.Failures, api.FailureView{
			Time:     f.Time.UTC().Format(time.RFC3339),
			Target:   f.Target,
			Network:  f.Network,
			Stage:    f.Stage,
			Category: f.Category,
			Policy:   f.Policy,
		})
	}
	return view
}

// DNS implements api.Provider. The resolver reports counts only, never the
// names it was asked for or the [Host] entries it answered from.
func (s *daemonState) DNS(context.Context) api.DNSView {
	resolver := s.snapshot().resolver
	if resolver == nil {
		return api.DNSView{}
	}
	st := resolver.Stats()
	return api.DNSView{
		CacheHits:   st.CacheHits,
		CacheMisses: st.CacheMisses,
		Entries:     st.Entries,
		MaxEntries:  st.MaxEntries,
		Succeeded:   st.Succeeded,
		Failed:      st.Failed,
	}
}

// formatOptionalTime renders a timestamp for a view, leaving it out when unset.
func formatOptionalTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// Explain implements api.Provider. It goes through the pipeline rather than the
// rule program so the report includes the lookup a name goes through: the answer
// describes what a real request would see, not a classification done with an
// address the request never had.
func (s *daemonState) Explain(ctx context.Context, req api.ExplainRequest) (api.ExplainView, error) {
	query := rules.Query{Name: req.Name, Port: req.Port, Network: req.Network}
	if req.Addr != "" {
		query.Addr = net.ParseIP(req.Addr)
	}
	exp, err := s.handler.Explain(ctx, query)
	if err != nil {
		return api.ExplainView{}, err
	}

	view := api.ExplainView{
		Query: api.QueryView{
			Name:    req.Name,
			Addr:    req.Addr,
			Port:    req.Port,
			Network: req.Network,
		},
		Matched: exp.Matched,
		Steps:   make([]api.StepView, 0, len(exp.Steps)),
		Report:  exp.String(),
	}
	if exp.Matched {
		rv := ruleView(exp.Decision.Rule)
		view.Rule = &rv
		view.Target = exp.Decision.Target
	}
	if res := exp.Resolution; res != nil {
		rv := &api.ResolutionView{Source: res.Source, Error: res.Err, Note: res.Note}
		for _, ip := range res.Addrs {
			rv.Addrs = append(rv.Addrs, ip.String())
		}
		view.Resolution = rv
	}
	for _, st := range exp.Steps {
		step := api.StepView{
			Type:   string(st.Kind),
			Index:  st.Index,
			Match:  st.Match,
			Detail: st.Detail,
		}
		if st.Rule != nil {
			step.Rule = st.Rule.String()
		}
		view.Steps = append(view.Steps, step)
	}
	return view, nil
}

// ruleView converts a compiled rule to its wire form.
func ruleView(r *rules.Rule) api.RuleView {
	return api.RuleView{
		Index:     r.Index(),
		Type:      string(r.Kind),
		Payload:   r.Payload,
		Target:    r.Target,
		Source:    r.Source,
		Line:      r.Line,
		NoResolve: r.NoResolve,
	}
}
