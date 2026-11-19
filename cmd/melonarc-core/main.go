// Command melonarc-core is the entry point of the MelonARC core daemon.
//
// The daemon owns every privileged operation (TUN device, routes, system
// proxy) and exposes a local API that the CLI and the desktop UI share.
//
// The daemon wires the configuration, the rule engine, the policy groups, the
// outbound dialers and the local API together and puts the inbound listeners in
// front of them: a connection accepted on the HTTP or SOCKS5 port is classified
// by the rules, resolved through the policy groups and carried by the outbound
// the rule chose.
//
// The API token is generated at startup and written to the data directory, which
// is where the CLI and the UI read it. The configuration file can be re-read
// through the API: the whole routing configuration is rebuilt and swapped in, so
// a rejected file changes nothing and an accepted one applies to the next
// connection.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/melon-tgj/melonarc/internal/api"
	"github.com/melon-tgj/melonarc/internal/config"
	"github.com/melon-tgj/melonarc/internal/datadir"
	"github.com/melon-tgj/melonarc/internal/dns"
	"github.com/melon-tgj/melonarc/internal/geoip"
	"github.com/melon-tgj/melonarc/internal/inbound"
	"github.com/melon-tgj/melonarc/internal/outbound"
	"github.com/melon-tgj/melonarc/internal/policy"
	"github.com/melon-tgj/melonarc/internal/rules"
	"github.com/melon-tgj/melonarc/internal/store"
	"github.com/melon-tgj/melonarc/internal/subscription"
	"github.com/melon-tgj/melonarc/internal/sysproxy"
	"github.com/melon-tgj/melonarc/internal/version"
)

// shutdownTimeout bounds the graceful stop of the local API.
const shutdownTimeout = 5 * time.Second

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "melonarc-core: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("melonarc-core", flag.ContinueOnError)
	configPath := fs.String("config", "", "path to the configuration file")
	apiListen := fs.String("api-listen", "", "override the local API listen address")
	dataDirFlag := fs.String("data-dir", "", "override the data directory of the configuration")
	superviseStdin := fs.Bool("supervise-stdin", false,
		"treat the end of standard input as a shutdown request (the desktop shell keeps the pipe open while it runs)")
	check := fs.Bool("check", false, "validate the configuration and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *configPath == "" {
		fs.Usage()
		return errors.New("-config is required")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return fmt.Errorf("configuration is not usable:\n%w", err)
	}
	logger, level := newLogger(cfg.General.LogLevel)
	logger.Info("configuration loaded", "path", cfg.Path, "rules", len(cfg.Rules),
		"proxies", len(cfg.Proxies), "groups", len(cfg.Groups))

	// The data set cache is process wide, so a reload reuses the mapping of a
	// file that did not change instead of mapping it again. It is closed last:
	// a request that started before a reload may still read through the previous
	// rule program.
	datasets := geoip.NewCache()
	defer datasets.Close()

	program, err := compileRules(cfg, datasets, logger)
	if err != nil {
		return fmt.Errorf("rule set is not usable:\n%w", err)
	}
	logger.Info("rules compiled", "total", program.Len(), "sets", program.Stats().RuleSets)

	// The data directory holds the API token. It is resolved before the check
	// exit so that -check can report the path without creating anything.
	dataDir, err := resolveDataDir(cfg, *dataDirFlag, logger)
	if err != nil {
		return fmt.Errorf("the data directory is not usable:\n%w", err)
	}

	if *check {
		printSummary(cfg, program, dataDir)
		return nil
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// The desktop shell can be killed in a way that leaves no chance to send a
	// signal: a crash, a force quit, a reboot of the session. The pipe it holds
	// open on standard input is the one thing the kernel still closes for us, so
	// its end of file is treated as the same request as SIGTERM and the daemon
	// keeps its ordinary shutdown order. The flag is off by default: a terminal
	// or a null device would report end of file at once, which would make an
	// unsupervised start exit immediately.
	if *superviseStdin {
		if err := checkLivenessPipe(os.Stdin); err != nil {
			return err
		}
		go watchLiveness(os.Stdin, logger, stop)
	}

	// The observation history is a side channel: it records what the daemon
	// carried and never takes part in carrying it. It is opened before anything
	// can be carried, and a file it cannot write is a warning rather than a
	// startup failure — a proxy that refuses to run because its history file is
	// on a full disk is worse than one without a history.
	//
	// Closing is deferred here so it runs last, after the listeners have stopped
	// and their final connection records have been appended.
	history, err := store.Open(store.Options{
		Path:   filepath.Join(dataDir, store.FileName),
		Logger: logger,
	})
	if err != nil {
		return fmt.Errorf("the observation history is not usable:\n%w", err)
	}
	defer func() {
		if err := history.Close(); err != nil {
			logger.Warn("history shutdown", "error", err)
		}
	}()
	if st := history.Status(); st.Notice != "" {
		logger.Warn("the previous history was not loaded", "notice", st.Notice)
	}

	// Subscriptions are fetched here rather than inside config.Load: loading a
	// file has to stay offline and free of side effects so that -check and the
	// tests are safe, and this is the first point where the data directory that
	// keeps the last good body is known.
	//
	// A subscription that can be neither fetched nor read from the cache stops
	// startup. Continuing would leave the rules and groups that point at it
	// without a target, which is a configuration that looks loaded and cannot
	// route.
	subs := subscription.New(subscription.Options{CacheDir: dataDir, Logger: logger})
	if err := subs.Import(ctx, cfg); err != nil {
		return fmt.Errorf("subscription is not usable:\n%w", err)
	}
	if len(cfg.Subscriptions) > 0 {
		logger.Info("subscriptions imported", "subscriptions", len(cfg.Subscriptions),
			"proxies", len(cfg.Proxies))
	}

	resolver, err := buildResolver(cfg)
	if err != nil {
		return fmt.Errorf("name resolution is not usable:\n%w", err)
	}
	dialers, err := buildDialers(cfg, resolver, logger)
	if err != nil {
		return fmt.Errorf("outbound is not usable:\n%w", err)
	}
	warnUnusableProtocols(cfg, logger)
	registry, err := buildRegistry(cfg, dialers)
	if err != nil {
		return fmt.Errorf("policy groups are not usable:\n%w", err)
	}
	// Registered first, so the groups stop last: they keep probing while the
	// listeners drain and the API answers its final requests.
	defer registry.Close()
	startGroups(ctx, registry, logger)

	// One observation object for the whole inbound layer: the listeners count
	// what they carry, the pipeline records what it could not carry, and the
	// API reads both from the same place. The history is the observer, so every
	// record the layer keeps is also written down.
	metrics := inbound.NewMetrics(inbound.DefaultFailureCapacity, historyObserver{store: history})

	handler, err := buildHandler(program, registry, dialers, resolver, metrics, logger)
	if err != nil {
		return fmt.Errorf("routing pipeline is not usable:\n%w", err)
	}
	services, err := startInbounds(cfg.General, handler, metrics, logger)
	if err != nil {
		return fmt.Errorf("inbound is not usable:\n%w", err)
	}
	// The device is opened after the socket listeners. If it fails, the
	// listeners that are already serving are closed before the error is
	// returned, so startup never leaves a half-enabled inbound layer behind.
	//
	// The resolver is handed over as a holder rather than as a value: the device
	// outlives every configuration, while the resolver behind it does not. A
	// reload swaps the resolver in the holder, so the DNS answers the device
	// gives follow the file instead of staying at what startup read.
	resolvers := inbound.NewResolverHolder(resolver)
	tunSrv, err := startTUN(cfg.General, handler, resolvers, metrics, logger)
	if err != nil {
		closeInbounds(services, logger)
		return fmt.Errorf("tun inbound is not usable:\n%w", err)
	}

	// The desktop proxy is the last thing brought up and the first thing taken
	// down: it points every application on the machine at a listener that is
	// already answering, and on shutdown it stops pointing there before the
	// listener goes away. A failure here is a startup failure with rollback,
	// like a device that cannot be opened — a machine whose proxy setting was
	// half written would look configured and break half its traffic.
	proxy := sysproxy.New(logger, filepath.Join(dataDir, sysproxy.SnapshotFile))
	if err := applySystemProxy(ctx, cfg.General, proxy, logger); err != nil {
		if tunSrv != nil {
			tunCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
			if cerr := tunSrv.Close(tunCtx); cerr != nil {
				logger.Warn("tun shutdown after a failed start", "error", cerr)
			}
			cancel()
		}
		closeInbounds(services, logger)
		return err
	}

	// The settings in force at startup are the reference a reload is measured
	// against: anything a reload cannot apply still has this value, which is
	// what "pending_restart" reports. It is a copy, so a later reload that
	// builds a new configuration cannot move the reference.
	baseline := cfg.General
	state := &daemonState{
		cfg:       cfg,
		program:   program,
		registry:  registry,
		handler:   handler,
		metrics:   metrics,
		resolver:  resolver,
		dialers:   dialers,
		resolvers: resolvers,
		version:   version.Version,
		startedAt: time.Now(),
		baseline:  &baseline,
		history:   history,
		// The API reports the subscription state the daemon is running with,
		// including the skip detail of each last refresh. It is the same
		// manager the loader and the refresh loop use, so the detail a client
		// reads is the one the refresh produced.
		subs: subs,
	}
	// The reloader keeps the probe context alive for the groups it starts, and
	// the state reaches it through the API. Both are wired before the API
	// starts answering, so a reload request cannot arrive at a nil function.
	state.reload = (&reloader{
		path:     cfg.Path,
		handler:  handler,
		state:    state,
		metrics:  metrics,
		datasets: datasets,
		level:    level,
		logger:   logger,
		subs:     subs,
		ctx:      ctx,
	}).reload

	// The refresh loop owns subscription updates from here on. A refresh that
	// changes the node list goes through the same reload path an API request
	// uses, so a provider's update lands the same way a hand edit does: one
	// atomic swap or nothing.
	go subs.Run(ctx, func() {
		_, err := state.reload(ctx)
		if err != nil {
			logger.Warn("reload after a subscription update was rejected", "error", err)
		}
		state.recordRefresh(subscriptionNodes(subs), err)
	})

	// Traffic is sampled from the counters the connections feed, so the series
	// and the totals can never disagree about what the daemon carried.
	go sampleTraffic(ctx, metrics, history, store.SampleInterval, logger)

	// Shutdown runs in the reverse order of startup: stop accepting
	// connections and close the ones in flight, then close the local API that
	// reports on the daemon, and only then let the groups stop probing.
	var apiSrv *api.Server
	defer func() {
		shutdown, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		// Stop pointing the machine at the listeners before they stop
		// answering: an application that opens a connection after this must not
		// be sent to a port that is closing.
		if err := proxy.Release(shutdown); err != nil {
			logger.Warn("system proxy", "error", err)
		}
		// Stop the packet loop next: it is the only inbound that can still
		// generate new dials after the socket listeners stopped accepting.
		if tunSrv != nil {
			if err := tunSrv.Close(shutdown); err != nil {
				logger.Warn("tun shutdown", "device", tunSrv.Name(), "error", err)
			}
			logger.Debug("inbound stopped", "protocol", tunSrv.Protocol())
		}
		closeInbounds(services, logger)
		if apiSrv != nil {
			if err := apiSrv.Close(shutdown); err != nil {
				logger.Warn("api shutdown", "error", err)
			}
		}
	}()

	addr := cfg.General.APIListen
	if *apiListen != "" {
		addr = *apiListen
	}
	if addr != "" {
		srv, err := api.New(api.Options{
			Addr:     addr,
			Provider: state,
			Version:  version.Version,
			Logger:   logger,
		})
		if err != nil {
			return err
		}
		apiSrv = srv
		// The token is written before the server starts answering: a client
		// that finds the file can use it immediately, and the file never holds
		// a token of a daemon that failed to start.
		tokenPath, err := datadir.WriteToken(dataDir, srv.Token())
		if err != nil {
			return fmt.Errorf("the api token cannot be distributed:\n%w\nset data-dir to a writable directory", err)
		}
		srv.Start()
		announceAPI(srv, tokenPath, logger)
	} else {
		logger.Warn("no api-listen address, the local API stays off")
	}

	logger.Info("core running, press Ctrl+C to stop")
	<-ctx.Done()
	logger.Info("stopping")
	return nil
}

// buildHandler assembles the pipeline every inbound listener shares: the
// compiled rules classify, the policy registry resolves, the outbound set dials,
// the resolver turns a name destination into an address when a rule needs one,
// and the metrics collect the requests that could not be carried.
func buildHandler(program *rules.Program, registry *policy.Registry, dialers *outbound.Set, resolver *dns.Resolver, metrics *inbound.Metrics, logger *slog.Logger) (*inbound.Handler, error) {
	router, err := inbound.NewPolicyRouter(registry, dialers)
	if err != nil {
		return nil, err
	}
	return inbound.NewHandler(inbound.HandlerOptions{
		Matcher:  program,
		Router:   router,
		Resolver: resolver,
		Metrics:  metrics,
		Logger:   logger,
	})
}

// buildResolver turns the [Host] section into the resolver's static table and the
// dns-nameserver list into a plaintext client. The cache and the request
// coalescing are built here rather than per listener, because every listener and
// every direct dial shares the same answers.
//
// Without dns-nameserver the resolver keeps asking the system resolver, which is
// the configuration every earlier stage had.
func buildResolver(cfg *config.Config) (*dns.Resolver, error) {
	opts := dns.Options{
		Hosts:            cfg.HostMap(),
		FallbackToSystem: cfg.General.FallbackToSystem(),
	}
	if len(cfg.General.NameServers) > 0 {
		upstream, err := dns.NewUpstream(cfg.General.NameServers, cfg.General.DNSTimeout)
		if err != nil {
			return nil, err
		}
		opts.Exchange = upstream.Exchange
	}
	return dns.New(opts)
}

// startInbounds binds the listeners the [General] section asks for. A listener
// whose address is empty stays off; binding a second one after the first
// succeeded and failing leaves nothing half started.
func startInbounds(g config.General, handler *inbound.Handler, metrics *inbound.Metrics, logger *slog.Logger) ([]*inbound.Service, error) {
	services := make([]*inbound.Service, 0, 2)
	if g.HTTPListen != "" {
		srv, err := inbound.NewHTTP(inbound.HTTPOptions{
			Addr:    g.HTTPListen,
			Handler: handler,
			Metrics: metrics,
			Logger:  logger,
		})
		if err != nil {
			closeInbounds(services, logger)
			return nil, err
		}
		services = append(services, srv)
	}
	if g.SOCKS5Listen != "" {
		srv, err := inbound.NewSOCKS5(inbound.SOCKS5Options{
			Addr:     g.SOCKS5Listen,
			Username: g.SOCKS5Username,
			Password: g.SOCKS5Password,
			Handler:  handler,
			Metrics:  metrics,
			Logger:   logger,
		})
		if err != nil {
			closeInbounds(services, logger)
			return nil, err
		}
		services = append(services, srv)
	}
	if len(services) == 0 {
		logger.Warn("no inbound listener is configured, nothing will be proxied")
		return services, nil
	}
	for _, srv := range services {
		logger.Info("inbound listening", "protocol", srv.Protocol(), "addr", srv.Addr())
	}
	return services, nil
}

// startTUN opens the device when the configuration asks for one. It is off by
// default, and on the other platforms openDevice reports the missing driver
// instead of the daemon starting without an inbound it was told to enable.
//
// The resolver is taken as the shared holder, not as a value: the device is
// created once, and the DNS answers it gives have to follow the configuration a
// reload installs.
func startTUN(g config.General, handler *inbound.Handler, resolvers *inbound.ResolverHolder, metrics *inbound.Metrics, logger *slog.Logger) (*inbound.TUNService, error) {
	if !g.TUN.Enable {
		return nil, nil
	}
	return inbound.NewTUN(inbound.TUNOptions{
		Name:       g.TUN.Name,
		Address:    g.TUN.Address,
		MTU:        g.TUN.MTU,
		Routes:     g.TUN.Routes,
		UDPTimeout: g.TUN.UDPTimeout,
		Handler:    handler,
		Resolvers:  resolvers,
		Metrics:    metrics,
		Logger:     logger,
	})
}

// closeInbounds stops every listener, waiting a bounded time for the
// connections they still carry.
func closeInbounds(services []*inbound.Service, logger *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	for _, srv := range services {
		if err := srv.Close(ctx); err != nil {
			logger.Warn("inbound shutdown", "protocol", srv.Protocol(), "error", err)
			continue
		}
		logger.Debug("inbound stopped", "protocol", srv.Protocol())
	}
}

// newLogger builds the process logger together with the level control a reload
// writes to: changing log-level in the configuration is the one [General]
// setting that takes effect without a restart.
func newLogger(level string) (*slog.Logger, *slog.LevelVar) {
	control := new(slog.LevelVar)
	control.Set(logLevel(level))
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: control})), control
}

// logLevel maps a configured level name to a slog level. Validate has already
// rejected anything else, so the default is only a fallback for callers that
// build a logger from an empty string.
func logLevel(name string) slog.Level {
	switch name {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// compileRules compiles the rule list together with the declared rule sets and
// the MaxMind DB files the address rules read.
//
// A data set is opened before the rules are compiled, so a file that is missing
// or damaged is reported as what it is — with its path and the reason — instead
// of turning into a rule that silently matches nothing. A configuration whose
// rules cannot be evaluated does not take effect; that has been the rule since
// the first stage, and a broken data file is no exception.
func compileRules(cfg *config.Config, datasets *geoip.Cache, logger *slog.Logger) (*rules.Program, error) {
	opts := rules.Options{
		Rules:    cfg.Rules,
		RuleSets: cfg.RuleSetPaths(),
		Root:     cfg.BaseDir,
	}
	if path := cfg.DataPath(cfg.General.GeoIPDB); path != "" {
		db, err := datasets.Country(path)
		if err != nil {
			return nil, fmt.Errorf("geoip-db: %w", err)
		}
		opts.GeoIP = db
		logger.Info("geoip database loaded", "path", db.Path(), "type", db.Type(), "ip_version", db.IPVersion())
	}
	if path := cfg.DataPath(cfg.General.ASNDB); path != "" {
		db, err := datasets.ASN(path)
		if err != nil {
			return nil, fmt.Errorf("asn-db: %w", err)
		}
		opts.ASN = db
		logger.Info("asn database loaded", "path", db.Path(), "type", db.Type(), "ip_version", db.IPVersion())
	}
	return rules.Compile(opts)
}

// buildDialers turns the [Proxy] entries into outbound dialers. A protocol of a
// later stage becomes an Unsupported dialer so the member stays unusable instead
// of the daemon refusing a configuration that lists it.
//
// DIRECT is the one dialer that resolves names itself, so it gets the resolver's
// lookup: a name the pipeline already resolved is answered from the cache, and
// the [Host] table applies to direct connections as well as to rules.
func buildDialers(cfg *config.Config, resolver *dns.Resolver, logger *slog.Logger) (*outbound.Set, error) {
	set := outbound.NewSet()
	direct := outbound.NewDirect()
	if resolver != nil {
		direct.Lookup = resolver.Lookup
	}
	if err := set.Add(config.TargetDirect, direct); err != nil {
		return nil, err
	}
	if err := set.Add(config.TargetReject, outbound.NewReject()); err != nil {
		return nil, err
	}
	for _, p := range cfg.Proxies {
		dialer, err := outbound.New(outbound.Spec{
			Name:   p.Name,
			Type:   p.Type,
			Server: p.Server,
			Port:   p.Port,
			Args:   p.Args,
		})
		if err != nil {
			return nil, err
		}
		if unsupported, ok := dialer.(*outbound.Unsupported); ok {
			logger.Warn("outbound protocol is not implemented in this build; the member stays unusable",
				"proxy", p.Name, "type", unsupported.Protocol)
		}
		if err := set.Add(p.Name, dialer); err != nil {
			return nil, err
		}
	}
	return set, nil
}

// buildRegistry turns the declared proxies and groups into a policy registry.
// Each probing group gets its own prober bound to the group's url=, and that
// prober reaches a member through the member's own outbound.
//
// Every manual group starts on its first member. Carrying a pin across a rebuild
// is not part of the build any more: which member the user picked is only known
// at the moment the new registry replaces the old one, so applySelections does it
// there (see reloader.commit).
func buildRegistry(cfg *config.Config, dialers *outbound.Set) (*policy.Registry, error) {
	reg := policy.NewRegistry()
	for _, name := range config.BuiltinTargets() {
		if err := reg.AddLeaf(name); err != nil {
			return nil, err
		}
	}
	for _, p := range cfg.Proxies {
		if err := reg.AddLeaf(p.Name); err != nil {
			return nil, err
		}
	}
	// The resolver reads the registry at probe time, after every group has been
	// added, so a member that is a nested group resolves to its current member.
	resolve := func(name string) (outbound.Dialer, error) {
		resolution, err := reg.Resolve(name)
		if err != nil {
			return nil, err
		}
		return dialers.Dialer(resolution.Leaf)
	}
	for _, g := range cfg.Groups {
		var (
			group policy.Group
			err   error
		)
		switch g.Type {
		case config.GroupSelect:
			// A manual group routes to the member the user picked and never
			// probes, so it needs no prober.
			group, err = policy.NewSelect(g.Name, g.Members, "")
		case config.GroupURLTest:
			prober, perr := outbound.NewProber(g.URL, resolve)
			if perr != nil {
				return nil, perr
			}
			group, err = policy.NewURLTest(g.Name, g.Members, prober, g.Interval, g.Timeout, g.Tolerance)
		case config.GroupFallback:
			prober, perr := outbound.NewProber(g.URL, resolve)
			if perr != nil {
				return nil, perr
			}
			group, err = policy.NewFallback(g.Name, g.Members, prober, g.Interval, g.Timeout)
		default:
			return nil, fmt.Errorf("group %q has unknown type %q", g.Name, g.Type)
		}
		if err != nil {
			return nil, err
		}
		if err := reg.AddGroup(group); err != nil {
			return nil, err
		}
	}
	return reg, nil
}

// carriedSelections returns the state a rebuild has to preserve. A daemon that
// is starting has no previous registry, and nil is the answer for it.
func carriedSelections(reg *policy.Registry) map[string]string {
	if reg == nil {
		return nil
	}
	return reg.Selections()
}

// droppedSelections lists the groups whose pinned member the rebuild could not
// keep, as "group: member" pairs.
//
// It is what turns a silently disappearing node into something the operator
// sees: the group still works, but it is no longer on the member that was
// chosen, and only a report can say so.
func droppedSelections(carry map[string]string, reg *policy.Registry) []string {
	if len(carry) == 0 || reg == nil {
		return nil
	}
	out := make([]string, 0, len(carry))
	for name, member := range carry {
		group, ok := reg.Group(name)
		if !ok {
			out = append(out, name+": group is gone, "+member+" cannot be selected")
			continue
		}
		if group.Active() != member {
			out = append(out, name+": "+member+" is not a member any more, using "+group.Active())
		}
	}
	sort.Strings(out)
	return out
}

// systemProxy is the part of the desktop proxy controller the daemon uses, so
// the startup path can be driven in a test without a desktop to write to.
type systemProxy interface {
	Enable(ctx context.Context, s sysproxy.Settings) error
	Release(ctx context.Context) error
	// Recover puts back a takeover a previous process did not release. It runs
	// even when the new configuration does not ask for a system proxy.
	Recover(ctx context.Context) error
}

// sysproxySettings renders the desktop proxy setting a configuration asks for.
//
// The listeners are used exactly as they are bound: the inbound only ever
// listens on loopback, which is also the only address a desktop proxy field can
// be given without the machine proxying its own network.
func sysproxySettings(g config.General) sysproxy.Settings {
	return sysproxy.Settings{
		HTTP:   g.HTTPListen,
		SOCKS5: g.SOCKS5Listen,
		Bypass: g.SystemProxyBypass,
	}
}

// applySystemProxy points the desktop proxy at the listeners when the
// configuration asks for it.
//
// It is called after the listeners are bound, so a setting that is written
// always points at something that answers. The error is returned rather than
// logged because a daemon that was told to configure the machine and could not
// must not report itself as running.
func applySystemProxy(ctx context.Context, g config.General, p systemProxy, logger *slog.Logger) error {
	// A hard kill can leave the machine pointing at a listener that is gone.
	// This runs before the configuration is consulted, so turning system-proxy
	// off after such a kill still puts the user's settings back.
	if err := p.Recover(ctx); err != nil {
		return fmt.Errorf("a system proxy takeover from a previous run could not be restored:\n%w", err)
	}
	if !g.SystemProxy {
		return nil
	}
	if err := p.Enable(ctx, sysproxySettings(g)); err != nil {
		return fmt.Errorf("system-proxy is on but the desktop setting could not be written:\n%w", err)
	}
	logger.Info("desktop proxy points at the listeners", "http", g.HTTPListen, "socks5", g.SOCKS5Listen)
	return nil
}

// startGroups starts periodic probing for the groups that need it.
func startGroups(ctx context.Context, reg *policy.Registry, logger *slog.Logger) {
	for _, g := range reg.Groups() {
		if g.Kind() == policy.KindSelect {
			continue
		}
		g.Start(ctx)
		logger.Debug("group probing started", "group", g.Name(), "kind", g.Kind())
	}
}

// announceAPI tells the operator where the local API is and where its token
// lives. The token value itself is deliberately never printed or logged:
// terminal output, crash reports and diagnostic bundles are routinely copied,
// and a copied token is a stolen credential. Only the file path is published.
func announceAPI(srv *api.Server, tokenPath string, logger *slog.Logger) {
	fmt.Printf("api: %s\napi token file: %s\n", srv.URL(), tokenPath)
	logger.Info("api listening", "addr", srv.Addr(), "token_file", tokenPath)
}

// printSummary reports what a validated configuration would activate.
func printSummary(cfg *config.Config, program *rules.Program, dataDir string) {
	// The banner is the only place a validation run says which build it is:
	// -check touches nothing else, and "which binary accepted this file" is the
	// first question when a preview build and a source build disagree.
	fmt.Printf("melonarc-core %s\n", version.Version)
	stats := program.Stats()
	fmt.Printf("configuration: %s\n", cfg.Path)
	fmt.Printf("rules: %d (final: %v, rule sets: %v)\n", stats.Total, stats.Final, stats.RuleSets)
	fmt.Printf("indexes: %d suffixes, %d exact names, %d keywords, %d ipv4 ranges, %d ipv6 ranges, %d port ranges\n",
		stats.Suffixes, stats.Domains, stats.Keywords, stats.Ranges4, stats.Ranges6, stats.Ports)
	fmt.Printf("proxies: %d\ngroups: %d\n", len(cfg.Proxies), len(cfg.Groups))
	if len(cfg.Subscriptions) > 0 {
		// -check does not fetch, so the nodes behind these names are not in the
		// proxy count. Saying so is what keeps the two numbers from looking
		// inconsistent.
		fmt.Printf("subscriptions: %d (not fetched by -check)\n", len(cfg.Subscriptions))
	}
	fmt.Printf("hosts: %d\n", len(cfg.Hosts))
	fmt.Printf("dns: %s\n", upstreamNote(cfg.General))
	fmt.Printf("geoip: %s, asn: %s\n", pathOrOff(cfg.DataPath(cfg.General.GeoIPDB)), pathOrOff(cfg.DataPath(cfg.General.ASNDB)))
	fmt.Printf("inbound: http %s, socks5 %s%s\n",
		listenOrOff(cfg.General.HTTPListen), listenOrOff(cfg.General.SOCKS5Listen), authNote(cfg.General))
	fmt.Printf("tun: %s\n", tunNote(cfg.General))
	fmt.Printf("system-proxy: %s\n", systemProxyNote(cfg.General))
	fmt.Printf("data: %s\n", dataDir)
	fmt.Printf("token: %s\n", datadir.TokenPath(dataDir))
	// -check reports where the history would live without touching it: it is a
	// read-only operation and a validation run must not create a file.
	fmt.Printf("history: %s (not touched by -check)\n", filepath.Join(dataDir, store.FileName))
}

// upstreamNote renders the DNS setting: the servers in the order they are asked,
// or the system resolver when none is configured, and what happens when they all
// fail.
func upstreamNote(g config.General) string {
	if len(g.NameServers) == 0 {
		return "system resolver"
	}
	servers := make([]string, 0, len(g.NameServers))
	for _, server := range g.NameServers {
		if addr, err := dns.ParseNameServer(server); err == nil {
			servers = append(servers, addr)
			continue
		}
		servers = append(servers, server)
	}
	fallback := config.DNSFallbackSystem
	if !g.FallbackToSystem() {
		fallback = config.DNSFallbackNone
	}
	return fmt.Sprintf("%s (fallback: %s)", strings.Join(servers, ", "), fallback)
}

// pathOrOff renders a configured data set path for the summary.
func pathOrOff(path string) string {
	if path == "" {
		return "off"
	}
	return path
}

// listenOrOff renders a listen address for the summary.
func listenOrOff(addr string) string {
	if addr == "" {
		return "off"
	}
	return addr
}

// tunNote renders the device settings for -check. It prints no credentials and
// touches no device: the summary describes what a start would activate.
func tunNote(g config.General) string {
	if !g.TUN.Enable {
		return "off"
	}
	routes := "device prefix and name address range"
	if len(g.TUN.Routes) > 0 {
		routes = strings.Join(g.TUN.Routes, ", ")
	}
	return fmt.Sprintf("%s %s mtu %d (routes: %s, udp-timeout %s)",
		g.TUN.Name, g.TUN.Address, g.TUN.MTU, routes, g.TUN.UDPTimeout)
}

// systemProxyNote renders the desktop proxy setting for -check. It is a
// description of what a start would write, not a probe: a validation run does
// not touch the desktop setting, and on a machine without one the failure
// appears when the daemon starts.
func systemProxyNote(g config.General) string {
	if !g.SystemProxy {
		return "off"
	}
	listeners := make([]string, 0, 2)
	if g.HTTPListen != "" {
		listeners = append(listeners, "http "+g.HTTPListen)
	}
	if g.SOCKS5Listen != "" {
		listeners = append(listeners, "socks5 "+g.SOCKS5Listen)
	}
	note := "on (" + strings.Join(listeners, ", ") + ")"
	if len(g.SystemProxyBypass) > 0 {
		note += ", bypass " + strings.Join(g.SystemProxyBypass, ", ")
	}
	return note
}

// authNote says whether the SOCKS5 inbound asks for credentials.
func authNote(g config.General) string {
	if g.SOCKS5Username == "" {
		return ""
	}
	return " (authenticated)"
}
