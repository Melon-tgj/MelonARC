package main

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/melon-tgj/melonarc/internal/api"
	"github.com/melon-tgj/melonarc/internal/config"
	"github.com/melon-tgj/melonarc/internal/geoip"
	"github.com/melon-tgj/melonarc/internal/inbound"
	"github.com/melon-tgj/melonarc/internal/policy"
	"github.com/melon-tgj/melonarc/internal/subscription"
)

// reloader rebuilds every routing artefact from the configuration file and
// installs the result in one step.
//
// It exists because a configuration is not one object: the rule program, the
// outbound dialers, the policy registry and the resolver are separate graphs
// that have to agree with each other. Rebuilding them all before touching
// anything is what makes a rejected configuration cost nothing: the daemon
// either gains a consistent new set or keeps the consistent old one.
type reloader struct {
	path    string
	handler *inbound.Handler
	state   *daemonState
	metrics *inbound.Metrics
	// datasets holds the MaxMind DB files the previous configuration opened. A
	// reload reuses a handle whose file did not change and opens a new one when
	// it did; the old handles stay open for the lifetime of the process.
	datasets *geoip.Cache
	// subs fetches the subscriptions a configuration declares. It holds the
	// last good result of each one, so a reload inside an interval does not
	// touch the network.
	subs   *subscription.Manager
	level  *slog.LevelVar
	logger *slog.Logger
	// ctx lives as long as the daemon and carries the probe loops of the
	// groups a reload starts.
	ctx context.Context

	// mu serialises reloads. Two concurrent reloads would each start a set of
	// probe goroutines and one of the two sets would never be stopped.
	mu sync.Mutex
	// beforeCommit runs after the new configuration is built and before the
	// swap starts. Production leaves it nil; a test uses it to place a request
	// in the window between "the build finished" and "the build took effect",
	// which is the window a pin used to fall into.
	beforeCommit func()
}

// reload re-reads the configuration file and installs it.
//
// A failure at any point leaves the running configuration untouched and is
// reported as a rejected request: the caller gets the problems, and the previous
// configuration stays in force. The daemon does not restart partially.
//
// The context is taken for the Provider signature but the rebuild is not
// interruptible: once the new artefacts exist, stopping halfway would leave the
// daemon with neither the old nor the new configuration. The caller waits, and
// the API bounds the wait with its own timeout.
func (r *reloader) reload(ctx context.Context) (api.ReloadView, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	start := time.Now()
	// Taken for the per-call restart report: what this reload could not apply is
	// measured against the configuration in force when it began. The pins are
	// read again at the commit point — only the state at that instant is the
	// right source for them.
	previous := r.state.snapshot()

	cfg, err := config.Load(r.path)
	if err != nil {
		return api.ReloadView{}, r.rejected(err)
	}
	// A reload replaces the nodes a subscription contributed as well: the file,
	// the fetched nodes and the groups over them are one configuration, and
	// swapping only part of it would leave the old nodes reachable.
	if r.subs != nil {
		if err := r.subs.Import(ctx, cfg); err != nil {
			return api.ReloadView{}, r.rejected(err)
		}
	}
	program, err := compileRules(cfg, r.datasets, r.logger)
	if err != nil {
		return api.ReloadView{}, r.rejected(err)
	}
	resolver, err := buildResolver(cfg)
	if err != nil {
		return api.ReloadView{}, r.rejected(err)
	}
	dialers, err := buildDialers(cfg, resolver, r.logger)
	if err != nil {
		return api.ReloadView{}, r.rejected(err)
	}
	// The configuration is accepted at this point, so the warning describes
	// something the daemon will actually be running with.
	warnUnusableProtocols(cfg, r.logger)
	// The registry is built without the pins of the running one. Which member a
	// manual group should start on is a fact about the state at the moment of
	// the swap, not about the state when the rebuild began: the user may pin a
	// group while the build runs, and that pin has to survive. It is applied in
	// commit, under the same lock the swap takes.
	registry, err := buildRegistry(cfg, dialers)
	if err != nil {
		return api.ReloadView{}, r.rejected(err)
	}
	// The new groups are real from this point on: their probe loops are about to
	// start, so every path that does not commit has to stop them again.
	committed := false
	defer func() {
		if !committed {
			registry.Close()
		}
	}()

	router, err := inbound.NewPolicyRouter(registry, dialers)
	if err != nil {
		return api.ReloadView{}, r.rejected(err)
	}
	next := stateSnapshot{
		cfg: cfg, program: program, registry: registry,
		resolver: resolver, dialers: dialers,
	}

	// Probing starts before the swap so a URL-Test group has a first round in
	// flight by the time the first connection reaches it, exactly as at startup.
	startGroups(r.ctx, registry, r.logger)
	if r.beforeCommit != nil {
		r.beforeCommit()
	}

	// The swap: one critical section, shared with SelectPolicy. A pin lands
	// either before it (and is inherited by the registry being installed) or
	// after it (and applies to that registry); there is no moment in between
	// where it could be written into a registry nobody will ever read again.
	replaced, dropped, err := r.commit(next, router)
	if err != nil {
		return api.ReloadView{}, r.rejected(err)
	}
	committed = true

	// The previous groups stop probing after the swap. A connection that is
	// still being carried holds its own dialer, so nothing in flight is cut.
	// The outbounds of the replaced set are retired the same way: a QUIC
	// outbound would otherwise keep a connection to its server alive for a
	// configuration that no longer exists.
	if replaced.registry != nil {
		replaced.registry.Close()
	}
	if replaced.dialers != nil && replaced.dialers != dialers {
		replaced.dialers.Disown()
	}
	r.level.Set(logLevel(cfg.General.LogLevel))

	view := api.ReloadView{
		OK:               true,
		Path:             cfg.Path,
		RuleCount:        program.Len(),
		ProxyCount:       len(cfg.Proxies),
		GroupCount:       len(cfg.Groups),
		HostCount:        len(cfg.Hosts),
		RestartRequired:  restartRequired(previous.cfg.General, cfg.General),
		PendingRestart:   r.state.pendingRestart(cfg.General),
		SelectionDropped: dropped,
		ElapsedMS:        float64(time.Since(start)) / float64(time.Millisecond),
	}
	r.logger.Info("configuration reloaded",
		"path", cfg.Path, "rules", view.RuleCount, "proxies", view.ProxyCount,
		"groups", view.GroupCount, "hosts", view.HostCount,
		"elapsed", time.Since(start).Round(time.Millisecond),
		"restart_required", view.RestartRequired)
	for _, setting := range view.RestartRequired {
		r.logger.Warn("a reloaded setting needs a restart to take effect", "setting", setting)
	}
	for _, dropped := range view.SelectionDropped {
		r.logger.Warn("a pinned policy member did not survive the reload", "detail", dropped)
	}
	// The history records the reload itself, not only its outcome: a reader
	// asking why a pin moved or a rule changed needs the moment it happened.
	r.state.recordReload(cfg.Path, true, fmt.Sprintf("rules %d, proxies %d, groups %d, hosts %d",
		view.RuleCount, view.ProxyCount, view.GroupCount, view.HostCount))
	return view, nil
}

// commit installs a finished rebuild, and reports what it replaced together with
// the pins it could not keep.
//
// It is the one place a reload changes what the daemon is running. The window it
// closes is this: a pin used to be read from the registry in force when the
// rebuild *started* and written into the new one when it was installed, so a
// user who switched a group in between got "ok" from the API and then had the
// switch silently overwritten by the value from before the reload. Reading the
// pins here — from the registry that is still in force — and applying them to
// the registry that is about to replace it makes the two orders the only two
// possible ones: a pin is either carried into the new registry, or it is written
// into that new registry because the swap has already happened.
//
// The section is short by construction: everything expensive (reading the file,
// compiling rules, opening datasets, building groups and dialers) happens before
// it, and only pointer stores and the pin bookkeeping are inside.
func (r *reloader) commit(next stateSnapshot, router inbound.Router) (stateSnapshot, []string, error) {
	r.state.commitMu.Lock()
	defer r.state.commitMu.Unlock()

	// The pins of the registry that is still in force, read now rather than when
	// the rebuild began: a switch that landed during the rebuild is exactly the
	// one that must not be lost.
	current := r.state.snapshot()
	carry := carriedSelections(current.registry)
	applySelections(carry, next.registry)
	dropped := droppedSelections(carry, next.registry)

	if err := r.handler.Replace(inbound.HandlerOptions{
		Matcher:  next.program,
		Router:   router,
		Resolver: next.resolver,
		Metrics:  r.metrics,
		Logger:   r.logger,
	}); err != nil {
		// Nothing was installed: Replace validates its options before it
		// stores anything, so the running configuration is untouched and the
		// caller can reject the reload as usual.
		return stateSnapshot{}, nil, err
	}
	// The API snapshot and the resolver the TUN device answers with change in
	// the same section, so the daemon never describes a configuration it is not
	// running — the data plane, the views and the device's DNS all move here.
	return r.state.install(next), dropped, nil
}

// applySelections puts the pins inherited from the previous registry onto the
// rebuilt one, by name.
//
// A pin whose member the new configuration no longer declares is left out: the
// group falls back to its first member, and droppedSelections reports it. This
// is the "member was removed" half of the reload contract, and it has to happen
// here rather than during the build because the pin is only known at the
// moment of the swap.
func applySelections(carry map[string]string, reg *policy.Registry) {
	if len(carry) == 0 || reg == nil {
		return
	}
	for name, member := range carry {
		group, ok := reg.Group(name)
		if !ok || group.Kind() != policy.KindSelect {
			continue
		}
		// Select only fails for a member this group does not declare, which is
		// the removed-node case: the group keeps its first member and the
		// report says so.
		_ = group.Select(member)
	}
}

// rejected turns a reload failure into the answer the API reports.
//
// The sentence about the previous configuration is part of the message rather
// than a separate field: it is the one thing a user has to know after a
// rejected reload, and a client that only prints error.message then still says
// it.
func (r *reloader) rejected(err error) error {
	// A refused reload is history too: the configuration file changed and the
	// daemon does not agree with it, which is exactly the state a later reader
	// has to be able to tell from "the file was never reloaded".
	r.state.recordReload(r.path, false, err.Error())
	return api.Unprocessable("reload_rejected",
		fmt.Sprintf("%v\nthe previous configuration is still in force", err))
}

// restartRequired lists the settings a reload cannot apply, in the order the
// [General] section documents them.
//
// These are the settings a running process cannot change for itself: a listener
// that is already bound (and the credentials it was built with), the address the
// API answers on, and the directory the token file lives in. Everything else in
// the file — rules, proxies, groups, [Host] entries, the log level — applies
// immediately.
func restartRequired(previous, next config.General) []string {
	out := make([]string, 0, 5)
	if previous.APIListen != next.APIListen {
		out = append(out, "api-listen")
	}
	if previous.HTTPListen != next.HTTPListen {
		out = append(out, "http-listen")
	}
	if previous.SOCKS5Listen != next.SOCKS5Listen {
		out = append(out, "socks5-listen")
	}
	if previous.SOCKS5Username != next.SOCKS5Username || previous.SOCKS5Password != next.SOCKS5Password {
		out = append(out, "socks5-credentials")
	}
	if previous.DataDir != next.DataDir {
		out = append(out, "data-dir")
	}
	// A device, its address, MTU and routes are created once at startup. They
	// are privileged operations with rollback, not something a reload can swap
	// while packets are in flight.
	if previous.TUN.Enable != next.TUN.Enable {
		out = append(out, "tun-enable")
	}
	if previous.TUN.Name != next.TUN.Name {
		out = append(out, "tun-name")
	}
	if previous.TUN.Address != next.TUN.Address {
		out = append(out, "tun-address")
	}
	if previous.TUN.MTU != next.TUN.MTU {
		out = append(out, "tun-mtu")
	}
	if !slices.Equal(previous.TUN.Routes, next.TUN.Routes) {
		out = append(out, "tun-route")
	}
	if previous.TUN.UDPTimeout != next.TUN.UDPTimeout {
		out = append(out, "tun-udp-timeout")
	}
	// The desktop proxy is a startup setting. Writing it from a reload would
	// change where every application on the machine sends its traffic as a side
	// effect of editing a rule list, and the addresses it points at cannot
	// change without rebinding the listeners anyway.
	if previous.SystemProxy != next.SystemProxy || !slices.Equal(previous.SystemProxyBypass, next.SystemProxyBypass) {
		out = append(out, "system-proxy")
	}
	return out
}
