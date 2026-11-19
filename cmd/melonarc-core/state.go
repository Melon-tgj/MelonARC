package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/melon-tgj/melonarc/internal/api"
	"github.com/melon-tgj/melonarc/internal/config"
	"github.com/melon-tgj/melonarc/internal/dns"
	"github.com/melon-tgj/melonarc/internal/inbound"
	"github.com/melon-tgj/melonarc/internal/outbound"
	"github.com/melon-tgj/melonarc/internal/policy"
	"github.com/melon-tgj/melonarc/internal/rules"
	"github.com/melon-tgj/melonarc/internal/store"
	"github.com/melon-tgj/melonarc/internal/subscription"
	"github.com/melon-tgj/melonarc/internal/sysproxy"
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
	// dialers owns the resources outbounds keep between connections. It is
	// part of the snapshot so a reload can retire the set it replaced.
	dialers *outbound.Set

	// commitMu is the reload commit point. A reload takes it to read the pins
	// in force and to swap the routing state in, and SelectPolicy takes it to
	// write a pin. The two operations are therefore ordered against each other:
	// a pin is either written before the swap (and inherited by the registry
	// being installed) or after it (and written into that registry). Without
	// this an API caller could be told "ok" for a switch that the reload, which
	// read the old selections before the caller ran, silently overwrote.
	//
	// mu is nested inside it, never the other way round.
	commitMu sync.Mutex

	// resolvers is the holder the TUN inbound reads the current resolver from.
	// The device is created once at startup, so the DNS answers it gives have to
	// follow a reload through this pointer rather than through a field copied
	// into the service. install updates it in the same critical section as the
	// snapshot, which is what makes "the state and the device agree" true at
	// every instant. Nil means no device was started, or a test that does not
	// care; the field is then simply not updated.
	resolvers *inbound.ResolverHolder

	handler   *inbound.Handler
	metrics   *inbound.Metrics
	version   string
	startedAt time.Time

	// history is the observation record. It is deliberately outside the
	// snapshot a reload replaces: the history outlives every configuration,
	// and a reload must not swap the file out from under the records that are
	// still arriving. Nil is valid and reports an empty history.
	history *store.Store

	// subs holds the last good result of every subscription, which is where the
	// skip detail of the last completed refresh lives. It is not part of the
	// snapshot a reload replaces: the manager keeps its state across reloads on
	// purpose, so a reload inside an interval does not refetch and the detail
	// survives a configuration swap. Nil is valid and reports no subscriptions.
	subs *subscription.Manager

	// baseline is the [General] section the process actually started with.
	// A reload cannot apply every setting in that section, so the settings it
	// could not apply keep this value until the daemon restarts; comparing it
	// with the file in force is what answers "what is waiting for a restart".
	// Nil means the daemon did not record one, and nothing is reported.
	baseline *config.General

	// reload is installed once, before the API starts serving. A state built
	// without one answers the reload endpoint with a clear refusal instead of
	// panicking.
	reload func(context.Context) (api.ReloadView, error)

	// proxyStatus is the desktop proxy controller the startup path used. The
	// API reads it so the four-state report describes what this process really
	// did, rather than what the configuration file says it should have done.
	// Nil is valid and reports nothing applied, nothing failed.
	proxyStatus systemProxyStatus
}

// systemProxyStatus is the slice of the controller the API needs. It is a
// separate interface so a test can supply a fixed answer without a desktop.
type systemProxyStatus interface {
	Status() sysproxy.Status
}

// stateSnapshot is the part of the state a reload replaces.
type stateSnapshot struct {
	cfg      *config.Config
	program  *rules.Program
	registry *policy.Registry
	resolver *dns.Resolver
	dialers  *outbound.Set
}

// snapshot returns the configuration currently in force.
func (s *daemonState) snapshot() stateSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return stateSnapshot{
		cfg: s.cfg, program: s.program, registry: s.registry,
		resolver: s.resolver, dialers: s.dialers,
	}
}

// install replaces the configuration and returns the previous one, so the
// caller can stop whatever it was running.
//
// Everything a request can observe changes here, under one lock: the snapshot
// the API serves from, and the resolver the TUN device answers DNS with. A
// reload that installed only one of the two would leave the daemon describing a
// configuration it is not running.
func (s *daemonState) install(next stateSnapshot) stateSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	previous := stateSnapshot{
		cfg: s.cfg, program: s.program, registry: s.registry,
		resolver: s.resolver, dialers: s.dialers,
	}
	s.cfg, s.program, s.registry, s.resolver, s.dialers =
		next.cfg, next.program, next.registry, next.resolver, next.dialers
	s.resolvers.Store(next.resolver)
	return previous
}

// baselineGeneral returns the [General] settings the process started with and
// reports whether one was recorded.
func (s *daemonState) baselineGeneral() (config.General, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.baseline == nil {
		return config.General{}, false
	}
	return *s.baseline, true
}

// pendingRestart lists the settings whose value in the loaded configuration
// cannot take effect until the daemon restarts.
//
// It is cumulative where the reload answer is per-call: a reload reports what
// it could not apply just now, while this reports everything that is still
// waiting, however many reloads ago it was changed. Changing a setting back to
// the value the process started with clears it, which is why the comparison is
// against the baseline and not against a list of attempts.
func (s *daemonState) pendingRestart(current config.General) []string {
	baseline, ok := s.baselineGeneral()
	if !ok {
		return []string{}
	}
	return restartRequired(baseline, current)
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
		LogLevel:       cfg.General.LogLevel,
		APIListen:      cfg.General.APIListen,
		HTTPListen:     cfg.General.HTTPListen,
		SOCKS5Listen:   cfg.General.SOCKS5Listen,
		Path:           cfg.Path,
		Proxies:        make([]api.ProxyView, 0, len(cfg.Proxies)),
		Groups:         make([]api.GroupView, 0, len(cfg.Groups)),
		RuleSets:       make([]api.RuleSetView, 0, len(cfg.RuleSets)),
		HostCount:      len(cfg.Hosts),
		NameServers:    append([]string{}, cfg.General.NameServers...),
		DNSFallback:    fallback,
		GeoIPDB:        cfg.DataPath(cfg.General.GeoIPDB),
		ASNDB:          cfg.DataPath(cfg.General.ASNDB),
		TUNEnable:      cfg.General.TUN.Enable,
		SystemProxy:    cfg.General.SystemProxy,
		PendingRestart: s.pendingRestart(cfg.General),
	}
	if len(cfg.General.SystemProxyBypass) > 0 {
		view.SystemProxyBypass = append([]string(nil), cfg.General.SystemProxyBypass...)
	}
	if cfg.General.TUN.Enable {
		view.TUNName = cfg.General.TUN.Name
		view.TUNAddress = cfg.General.TUN.Address
		view.TUNMTU = cfg.General.TUN.MTU
		view.TUNRoutes = append([]string(nil), cfg.General.TUN.Routes...)
	}
	view.SystemProxyState = s.systemProxyStateView(cfg.General.SystemProxy, view.PendingRestart)
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

// systemProxyStateView collapses the configuration and the runtime takeover
// facts into the single state a client draws, while carrying the raw facts
// beside it. Precedence is deliberate: a retained, unrecoverable takeover is
// the one state the user must not miss, then a setting that needs a restart,
// then a takeover this process actually made, then the configured value.
func (s *daemonState) systemProxyStateView(configured bool, pending []string) api.SystemProxyView {
	view := api.SystemProxyView{
		Configured:     configured,
		PendingRestart: slices.Contains(pending, "system-proxy"),
		State:          api.SystemProxyOff,
	}
	if s.proxyStatus != nil {
		status := s.proxyStatus.Status()
		view.Applied = status.Applied
		view.RecoveryFailed = status.RecoveryFailed
		view.Detail = status.Detail
	}
	switch {
	case view.RecoveryFailed:
		view.State = api.SystemProxyRecoveryFailed
	case view.PendingRestart:
		view.State = api.SystemProxyPendingRestart
	case view.Applied:
		view.State = api.SystemProxyApplied
	case configured:
		view.State = api.SystemProxyConfigured
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
//
// The read of the registry and the write of the pin happen under the reload
// commit lock: a reload that is installing a new registry at that moment either
// has not started its swap yet (so it will inherit this pin) or has finished it
// (so this pin goes into the new registry). A pin can no longer be written into
// a registry that is about to be replaced.
func (s *daemonState) SelectPolicy(_ context.Context, group, member string) (api.SelectView, error) {
	s.commitMu.Lock()
	defer s.commitMu.Unlock()
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
	active := g.Active()
	s.recordSelection(group, previous, active)
	return api.SelectView{Group: group, Previous: previous, Active: active}, nil
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

// UpdateConfig writes the settings the native shell owns. The file write and
// the reload commit share commitMu so a policy pin cannot be written into a
// configuration that is being replaced at the same instant. The caller reloads
// separately and then reads the resulting state; this method only reports what
// it wrote and which changes a restart will need.
func (s *daemonState) UpdateConfig(_ context.Context, req api.ConfigUpdateRequest) (api.ConfigUpdateView, error) {
	snap := s.snapshot()
	if snap.cfg == nil || snap.cfg.Path == "" {
		return api.ConfigUpdateView{}, api.Conflict("config_not_file_backed",
			"this daemon was started without a configuration file, so settings cannot be saved")
	}
	patch := config.GeneralPatch{LogLevel: req.LogLevel, SystemProxy: req.SystemProxy}
	s.commitMu.Lock()
	err := config.UpdateGeneralFile(snap.cfg.Path, patch)
	s.commitMu.Unlock()
	if err != nil {
		return api.ConfigUpdateView{}, api.Unprocessable("config_not_written", err.Error())
	}
	view := api.ConfigUpdateView{
		Path:            snap.cfg.Path,
		RestartRequired: []string{},
	}
	if req.LogLevel != nil {
		view.LogLevel = strings.ToLower(strings.TrimSpace(*req.LogLevel))
	} else {
		view.LogLevel = snap.cfg.General.LogLevel
	}
	if req.SystemProxy != nil {
		view.SystemProxy = *req.SystemProxy
		if view.SystemProxy != snap.cfg.General.SystemProxy {
			view.RestartRequired = append(view.RestartRequired, "system-proxy")
		}
	} else {
		view.SystemProxy = snap.cfg.General.SystemProxy
	}
	return view, nil
}

// Inbound implements api.Provider.
func (s *daemonState) Inbound(context.Context) api.InboundView {
	return inboundView(s.metrics.Snapshot())
}

// inboundView turns an inbound snapshot into the wire view.
//
// It is a function of its argument rather than a method because one field it
// carries cannot be produced on this machine: a TUN name address pool that ran
// out needs a device and a saturated lease table. Keeping the mapping pure is
// what lets the test feed it a snapshot with that counter set.
func inboundView(snap inbound.Snapshot) api.InboundView {
	view := api.InboundView{
		Inbounds:                        make([]api.InboundStatsView, 0, len(snap.Protocols)),
		Failures:                        snap.Failures,
		Rejected:                        snap.Rejected,
		FakeIPPoolExhaustedQueriesTotal: snap.NameAddressExhausted,
		FailureLogCapacity:              snap.FailureCapacity,
		FailureLogCount:                 snap.FailureCount,
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

// History implements api.Provider. It describes the observation record and
// carries none of it: the endpoints under /v1/history/ serve the records.
//
// Enabled is separate from "the counts are zero" on purpose. A daemon that keeps
// a history and has carried nothing yet and a daemon that keeps none look the
// same in the numbers and mean different things to a caller.
func (s *daemonState) History(context.Context) api.HistoryView {
	st := s.history.Status()
	view := api.HistoryView{
		Enabled:     s.history != nil,
		Path:        st.Path,
		Bytes:       st.Bytes,
		Connections: st.Connections,
		Events:      st.Events,
		Samples:     st.Samples,
		Capacity: api.HistoryCapacityView{
			Connections: st.Capacity.Connections,
			Events:      st.Capacity.Events,
			Samples:     st.Capacity.Samples,
		},
		Flushes:   st.Flushes,
		LastFlush: formatOptionalTime(st.LastFlush),
		LastError: st.LastError,
		Notice:    st.Notice,
	}
	view.Up, view.Down = s.metrics.Traffic()
	return view
}

// HistoryConnections implements api.Provider.
func (s *daemonState) HistoryConnections(_ context.Context, limit int, since time.Time) api.ConnectionListView {
	records := s.history.Connections(limit, since)
	view := api.ConnectionListView{
		Count:       len(records),
		Connections: make([]api.ConnectionView, 0, len(records)),
	}
	for _, c := range records {
		view.Connections = append(view.Connections, api.ConnectionView{
			Time:     c.At.UTC().Format(time.RFC3339),
			Protocol: c.Protocol,
			// The port is part of the destination a client asked for, so it is
			// rendered the way it was written: host:port, bracketed when the
			// host is an address literal.
			Target:     net.JoinHostPort(c.Host, strconv.Itoa(c.Port)),
			Network:    c.Network,
			Rule:       c.Rule,
			Policy:     c.Policy,
			Outbound:   c.Outbound,
			Up:         c.Up,
			Down:       c.Down,
			DurationMS: float64(c.Duration) / float64(time.Millisecond),
		})
	}
	return view
}

// HistoryEvents implements api.Provider.
func (s *daemonState) HistoryEvents(_ context.Context, limit int, kind string, since time.Time) api.EventListView {
	records := s.history.Events(limit, kind, since)
	view := api.EventListView{
		Count:  len(records),
		Events: make([]api.EventView, 0, len(records)),
	}
	for _, e := range records {
		view.Events = append(view.Events, api.EventView{
			Time:   e.At.UTC().Format(time.RFC3339),
			Kind:   e.Kind,
			Name:   e.Name,
			Detail: e.Detail,
			OK:     e.OK,
		})
	}
	return view
}

// HistoryTraffic implements api.Provider. The totals of the returned window are
// summed here rather than reported from a counter: a series a client can draw
// and the sum over it have to agree, and only the samples can promise that.
func (s *daemonState) HistoryTraffic(_ context.Context, limit int, since time.Time) api.TrafficListView {
	samples := s.history.Samples(limit, since)
	view := api.TrafficListView{
		Count:   len(samples),
		Samples: make([]api.TrafficView, 0, len(samples)),
	}
	for _, sample := range samples {
		view.Up += sample.Up
		view.Down += sample.Down
		view.Samples = append(view.Samples, api.TrafficView{
			Time: sample.At.UTC().Format(time.RFC3339),
			Up:   sample.Up,
			Down: sample.Down,
		})
	}
	return view
}

// formatOptionalTime renders a timestamp for a view, leaving it out when unset.
func formatOptionalTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// Subscriptions implements api.Provider. The list follows the configuration in
// force rather than the manager's memory: a reload that removed a subscription
// leaves the manager holding its last result, and reporting that entry would
// describe a subscription the daemon no longer has.
//
// Each entry is a summary. The skipped entries are one page of their own, which
// is what keeps this answer small exactly when a provider is serving a broken
// list.
func (s *daemonState) Subscriptions(context.Context) api.SubscriptionListView {
	cfg := s.snapshot().cfg
	view := api.SubscriptionListView{Subscriptions: make([]api.SubscriptionView, 0, len(cfg.Subscriptions))}
	for _, sub := range cfg.Subscriptions {
		view.Subscriptions = append(view.Subscriptions, s.subscriptionView(sub.Name))
	}
	return view
}

// subscriptionView reports one subscription, with the zero answer for a name the
// manager does not know: a configuration can declare a subscription whose first
// fetch has not finished, and "nothing yet" is the honest answer for it.
func (s *daemonState) subscriptionView(name string) api.SubscriptionView {
	view := api.SubscriptionView{Name: name}
	if s.subs == nil {
		return view
	}
	st, ok := s.subs.Status(name)
	if !ok {
		return view
	}
	view.Nodes = st.Nodes
	view.Skipped = len(st.Skipped)
	view.FetchedAt = formatOptionalTime(st.FetchedAt)
	view.NextAt = formatOptionalTime(st.NextAt)
	view.Attempts = st.Attempts
	view.Error = st.Error
	return view
}

// SubscriptionSkipped implements api.Provider: one page of the skip detail the
// last completed refresh left behind.
//
// A name the loaded configuration does not declare is a 404 with its own code,
// so a typo is not mistaken for a clean subscription. A subscription that never
// completed a refresh answers an empty page with Refreshed false: it is a real
// subscription, and "no refresh has finished" is a different fact from "the
// last refresh skipped nothing".
func (s *daemonState) SubscriptionSkipped(_ context.Context, name string, offset, limit int) (api.SkippedListView, error) {
	name = strings.TrimSpace(name)
	if !declaresSubscription(s.snapshot().cfg, name) {
		return api.SkippedListView{}, api.NotFound("unknown_subscription",
			fmt.Sprintf("no subscription is named %q", name))
	}
	// The page a caller would have got from a real subscription, so an empty
	// answer does not report a window the caller never asked for.
	offset, limit = subscription.ClampSkippedPage(offset, limit)
	view := api.SkippedListView{
		Subscription: name,
		Offset:       offset,
		Limit:        limit,
		Skipped:      []api.SkippedEntryView{},
	}
	if s.subs == nil {
		return view, nil
	}
	page, ok := s.subs.Skipped(name, offset, limit)
	if !ok {
		// Declared, but the manager has not seen it: the first import has not
		// finished, or the reload that declared it kept the previous
		// configuration. The page is empty and says no refresh completed.
		return view, nil
	}
	view.Refreshed = page.Refreshed
	view.FetchedAt = formatOptionalTime(page.FetchedAt)
	view.Total = page.Total
	view.Offset = page.Offset
	view.Limit = page.Limit
	for _, skip := range page.Items {
		view.Skipped = append(view.Skipped, api.SkippedEntryView{Item: skip.Item, Reason: skip.Reason})
	}
	return view, nil
}

// RefreshSubscription implements api.Provider: it forces one declared
// subscription to fetch now and, when its nodes changed, rebuilds the routing
// artefacts through the same reload path a scheduled update uses.
//
// A name the configuration does not declare is a NotFound before the network is
// touched. A failed fetch is not a request error: the previous nodes were kept
// and the reason is carried in the view, exactly as a scheduled refresh reports
// it. The history records the attempt whether or not it changed the nodes.
func (s *daemonState) RefreshSubscription(ctx context.Context, name string) (api.SubscriptionRefreshView, error) {
	name = strings.TrimSpace(name)
	if !declaresSubscription(s.snapshot().cfg, name) {
		return api.SubscriptionRefreshView{}, api.NotFound("unknown_subscription",
			fmt.Sprintf("no subscription is named %q", name))
	}
	view := api.SubscriptionRefreshView{Subscription: name}
	if s.subs == nil {
		return view, nil
	}

	status, changed, err := s.subs.RefreshNow(ctx, name)
	view.Nodes = status.Nodes
	view.Skipped = len(status.Skipped)
	view.FetchedAt = formatOptionalTime(status.FetchedAt)
	view.Attempts = status.Attempts
	view.Error = status.Error
	if errors.Is(err, subscription.ErrUnknownSubscription) {
		// Declared in the file but not imported yet (a reload that declared it
		// kept the previous configuration). Same answer as the skipped page:
		// known to the configuration, nothing completed yet.
		return view, nil
	}
	// A failed fetch that fell back to a cached body returns a nil error from
	// the manager but still carries the reason in Status.Error. Both signals
	// have to be clean before the attempt counts as refreshed.
	view.Refreshed = err == nil && status.Error == ""

	// A node list that changed has to reach the dialers and groups. The reload
	// re-imports every subscription, but one just refreshed is not due again,
	// so it reuses the result we already installed instead of fetching twice.
	recordErr := err
	if changed && err == nil {
		if _, reloadErr := s.reload(ctx); reloadErr != nil {
			recordErr = reloadErr
			view.Error = reloadErr.Error()
		} else {
			view.Reloaded = true
		}
	}
	s.recordRefresh(subscriptionNodes(s.subs), recordErr)
	return view, nil
}

// declaresSubscription reports whether the configuration declares that name.
func declaresSubscription(cfg *config.Config, name string) bool {
	if cfg == nil {
		return false
	}
	for _, sub := range cfg.Subscriptions {
		if sub.Name == name {
			return true
		}
	}
	return false
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
