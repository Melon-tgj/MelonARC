package main

import (
	"context"
	"net"
	"time"

	"github.com/melon-tgj/melonarc/internal/api"
	"github.com/melon-tgj/melonarc/internal/config"
	"github.com/melon-tgj/melonarc/internal/policy"
	"github.com/melon-tgj/melonarc/internal/rules"
)

// defaultRulePage is the number of rules returned when the client does not ask
// for a specific page. A large rule set is never serialised in full by default.
const defaultRulePage = 1000

// daemonState adapts the compiled configuration to the read-only API views.
type daemonState struct {
	cfg       *config.Config
	program   *rules.Program
	registry  *policy.Registry
	version   string
	startedAt time.Time
}

// Status implements api.Provider.
func (s *daemonState) Status(context.Context) api.StatusView {
	cfgPath := ""
	if s.cfg != nil {
		cfgPath = s.cfg.Path
	}
	return api.StatusView{
		Version:       s.version,
		StartedAt:     s.startedAt,
		UptimeSeconds: time.Since(s.startedAt).Seconds(),
		ConfigPath:    cfgPath,
		RuleCount:     s.program.Len(),
		PolicyCount:   len(s.registry.Groups()),
	}
}

// Config implements api.Provider. Only the fields needed to describe the
// configuration are exposed; proxy arguments may hold credentials and are
// deliberately left out.
func (s *daemonState) Config(context.Context) api.ConfigView {
	view := api.ConfigView{
		LogLevel:  s.cfg.General.LogLevel,
		APIListen: s.cfg.General.APIListen,
		Path:      s.cfg.Path,
		Proxies:   make([]api.ProxyView, 0, len(s.cfg.Proxies)),
		Groups:    make([]api.GroupView, 0, len(s.cfg.Groups)),
		RuleSets:  make([]api.RuleSetView, 0, len(s.cfg.RuleSets)),
		Hosts:     make([]api.HostView, 0, len(s.cfg.Hosts)),
	}
	for _, p := range s.cfg.Proxies {
		view.Proxies = append(view.Proxies, api.ProxyView{
			Name: p.Name, Type: p.Type, Server: p.Server, Port: p.Port,
		})
	}
	for _, g := range s.cfg.Groups {
		view.Groups = append(view.Groups, api.GroupView{
			Name:            g.Name,
			Type:            string(g.Type),
			Members:         append([]string(nil), g.Members...),
			URL:             g.URL,
			IntervalSeconds: int(g.Interval / time.Second),
		})
	}
	for _, rs := range s.cfg.RuleSets {
		view.RuleSets = append(view.RuleSets, api.RuleSetView{Name: rs.Name, Path: rs.Path})
	}
	for _, h := range s.cfg.Hosts {
		addrs := make([]string, 0, len(h.Addrs))
		for _, a := range h.Addrs {
			addrs = append(addrs, a.String())
		}
		view.Hosts = append(view.Hosts, api.HostView{Name: h.Name, Addrs: addrs})
	}
	return view
}

// Rules implements api.Provider.
func (s *daemonState) Rules(_ context.Context, limit int) api.RuleListView {
	if limit <= 0 {
		limit = defaultRulePage
	}
	all := s.program.Rules()
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
	groups := s.registry.Groups()
	out := make([]api.PolicyView, 0, len(groups))
	for _, g := range groups {
		st := g.Status()
		view := api.PolicyView{
			Name:    st.Name,
			Type:    string(st.Kind),
			Active:  st.Active,
			Members: make([]api.MemberView, 0, len(st.Members)),
		}
		if !st.Checked.IsZero() {
			view.Checked = st.Checked.UTC().Format(time.RFC3339)
		}
		for _, m := range st.Members {
			view.Members = append(view.Members, api.MemberView{
				Name:      m.Name,
				Healthy:   m.Healthy,
				Checked:   m.Checked,
				LatencyMS: float64(m.Latency) / float64(time.Millisecond),
			})
		}
		out = append(out, view)
	}
	return out
}

// Explain implements api.Provider.
func (s *daemonState) Explain(_ context.Context, req api.ExplainRequest) (api.ExplainView, error) {
	query := rules.Query{Name: req.Name, Port: req.Port, Network: req.Network}
	if req.Addr != "" {
		query.Addr = net.ParseIP(req.Addr)
	}
	exp := s.program.Explain(query)

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
