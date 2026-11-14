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
	level    *slog.LevelVar
	logger   *slog.Logger
	// ctx lives as long as the daemon and carries the probe loops of the
	// groups a reload starts.
	ctx context.Context

	// mu serialises reloads. Two concurrent reloads would each start a set of
	// probe goroutines and one of the two sets would never be stopped.
	mu sync.Mutex
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
func (r *reloader) reload(context.Context) (api.ReloadView, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	start := time.Now()
	previous := r.state.snapshot()

	cfg, err := config.Load(r.path)
	if err != nil {
		return api.ReloadView{}, r.rejected(err)
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
	if err := r.handler.Replace(inbound.HandlerOptions{
		Matcher:  program,
		Router:   router,
		Resolver: resolver,
		Metrics:  r.metrics,
		Logger:   r.logger,
	}); err != nil {
		return api.ReloadView{}, r.rejected(err)
	}

	// Probing starts before the swap so a URL-Test group has a first round in
	// flight by the time the first connection reaches it, exactly as at startup.
	startGroups(r.ctx, registry, r.logger)
	r.state.install(stateSnapshot{
		cfg: cfg, program: program, registry: registry,
		resolver: resolver, dialers: dialers,
	})
	committed = true

	// The previous groups stop probing after the swap. A connection that is
	// still being carried holds its own dialer, so nothing in flight is cut.
	// The outbounds of the replaced set are retired the same way: a QUIC
	// outbound would otherwise keep a connection to its server alive for a
	// configuration that no longer exists.
	if previous.registry != nil {
		previous.registry.Close()
	}
	if previous.dialers != nil && previous.dialers != dialers {
		previous.dialers.Disown()
	}
	r.level.Set(logLevel(cfg.General.LogLevel))

	view := api.ReloadView{
		OK:              true,
		Path:            cfg.Path,
		RuleCount:       program.Len(),
		ProxyCount:      len(cfg.Proxies),
		GroupCount:      len(cfg.Groups),
		HostCount:       len(cfg.Hosts),
		RestartRequired: restartRequired(previous.cfg.General, cfg.General),
		ElapsedMS:       float64(time.Since(start)) / float64(time.Millisecond),
	}
	r.logger.Info("configuration reloaded",
		"path", cfg.Path, "rules", view.RuleCount, "proxies", view.ProxyCount,
		"groups", view.GroupCount, "hosts", view.HostCount,
		"elapsed", time.Since(start).Round(time.Millisecond),
		"restart_required", view.RestartRequired)
	for _, setting := range view.RestartRequired {
		r.logger.Warn("a reloaded setting needs a restart to take effect", "setting", setting)
	}
	return view, nil
}

// rejected turns a reload failure into the answer the API reports.
//
// The sentence about the previous configuration is part of the message rather
// than a separate field: it is the one thing a user has to know after a
// rejected reload, and a client that only prints error.message then still says
// it.
func (r *reloader) rejected(err error) error {
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
	return out
}
