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
)

// version is the build version placeholder, overridden at link time later on.
const version = "0.1.0-dev"

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
	dataDir, err := datadir.Resolve(cfg.BaseDir, cfg.General.DataDir)
	if err != nil {
		return fmt.Errorf("the data directory is not usable:\n%w", err)
	}

	if *check {
		printSummary(cfg, program, dataDir)
		return nil
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	resolver, err := buildResolver(cfg)
	if err != nil {
		return fmt.Errorf("name resolution is not usable:\n%w", err)
	}
	dialers, err := buildDialers(cfg, resolver, logger)
	if err != nil {
		return fmt.Errorf("outbound is not usable:\n%w", err)
	}
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
	// API reads both from the same place.
	metrics := inbound.NewMetrics(inbound.DefaultFailureCapacity)

	handler, err := buildHandler(program, registry, dialers, resolver, metrics, logger)
	if err != nil {
		return fmt.Errorf("routing pipeline is not usable:\n%w", err)
	}
	services, err := startInbounds(cfg.General, handler, metrics, logger)
	if err != nil {
		return fmt.Errorf("inbound is not usable:\n%w", err)
	}

	state := &daemonState{
		cfg:       cfg,
		program:   program,
		registry:  registry,
		handler:   handler,
		metrics:   metrics,
		resolver:  resolver,
		version:   version,
		startedAt: time.Now(),
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
		ctx:      ctx,
	}).reload

	// Shutdown runs in the reverse order of startup: stop accepting
	// connections and close the ones in flight, then close the local API that
	// reports on the daemon, and only then let the groups stop probing.
	var apiSrv *api.Server
	defer func() {
		shutdown, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
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
			Version:  version,
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
		fmt.Printf("api: %s\napi token: %s\napi token file: %s\n", srv.URL(), srv.Token(), tokenPath)
		logger.Info("api listening", "addr", srv.Addr(), "token_file", tokenPath)
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

// printSummary reports what a validated configuration would activate.
func printSummary(cfg *config.Config, program *rules.Program, dataDir string) {
	stats := program.Stats()
	fmt.Printf("configuration: %s\n", cfg.Path)
	fmt.Printf("rules: %d (final: %v, rule sets: %v)\n", stats.Total, stats.Final, stats.RuleSets)
	fmt.Printf("indexes: %d suffixes, %d exact names, %d keywords, %d ipv4 ranges, %d ipv6 ranges, %d port ranges\n",
		stats.Suffixes, stats.Domains, stats.Keywords, stats.Ranges4, stats.Ranges6, stats.Ports)
	fmt.Printf("proxies: %d\ngroups: %d\n", len(cfg.Proxies), len(cfg.Groups))
	fmt.Printf("hosts: %d\n", len(cfg.Hosts))
	fmt.Printf("dns: %s\n", upstreamNote(cfg.General))
	fmt.Printf("geoip: %s, asn: %s\n", pathOrOff(cfg.DataPath(cfg.General.GeoIPDB)), pathOrOff(cfg.DataPath(cfg.General.ASNDB)))
	fmt.Printf("inbound: http %s, socks5 %s%s\n",
		listenOrOff(cfg.General.HTTPListen), listenOrOff(cfg.General.SOCKS5Listen), authNote(cfg.General))
	fmt.Printf("data: %s\n", dataDir)
	fmt.Printf("token: %s\n", datadir.TokenPath(dataDir))
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

// authNote says whether the SOCKS5 inbound asks for credentials.
func authNote(g config.General) string {
	if g.SOCKS5Username == "" {
		return ""
	}
	return " (authenticated)"
}
