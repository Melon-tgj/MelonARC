// Command melonarc-core is the entry point of the MelonARC core daemon.
//
// The daemon owns every privileged operation (TUN device, routes, system
// proxy) and exposes a local API that the CLI and the desktop UI share.
//
// This stage wires the configuration, the rule engine, the policy groups and
// the local API together. Inbound listeners and outbound protocols arrive in
// later stages; until then the daemon validates a configuration, compiles it
// and serves it read only.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/melon-tgj/melonarc/internal/api"
	"github.com/melon-tgj/melonarc/internal/config"
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
	logger := newLogger(cfg.General.LogLevel)
	logger.Info("configuration loaded", "path", cfg.Path, "rules", len(cfg.Rules),
		"proxies", len(cfg.Proxies), "groups", len(cfg.Groups))

	program, err := compileRules(cfg)
	if err != nil {
		return fmt.Errorf("rule set is not usable:\n%w", err)
	}
	logger.Info("rules compiled", "total", program.Len(), "sets", program.Stats().RuleSets)

	if *check {
		printSummary(cfg, program)
		return nil
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	registry, err := buildRegistry(cfg)
	if err != nil {
		return fmt.Errorf("policy groups are not usable:\n%w", err)
	}
	defer registry.Close()
	startGroups(ctx, registry, logger)

	state := &daemonState{
		cfg:       cfg,
		program:   program,
		registry:  registry,
		version:   version,
		startedAt: time.Now(),
	}

	addr := cfg.General.APIListen
	if *apiListen != "" {
		addr = *apiListen
	}
	if addr != "" {
		srv, err := api.New(api.Options{Addr: addr, Provider: state, Version: version})
		if err != nil {
			return err
		}
		srv.Start()
		fmt.Printf("api: %s\napi token: %s\n", srv.URL(), srv.Token())
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
			defer cancel()
			if err := srv.Close(shutdownCtx); err != nil {
				logger.Warn("api shutdown", "error", err)
			}
		}()
	} else {
		logger.Warn("no api-listen address, the local API stays off")
	}

	logger.Info("core running, press Ctrl+C to stop")
	<-ctx.Done()
	logger.Info("stopping")
	return nil
}

// newLogger builds the process logger from the configured level.
func newLogger(level string) *slog.Logger {
	var l slog.Level
	switch level {
	case "debug":
		l = slog.LevelDebug
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}

// compileRules compiles the rule list together with the declared rule sets.
func compileRules(cfg *config.Config) (*rules.Program, error) {
	return rules.Compile(rules.Options{
		Rules:    cfg.Rules,
		RuleSets: cfg.RuleSetPaths(),
		Root:     cfg.BaseDir,
	})
}

// buildRegistry turns the declared proxies and groups into a policy registry.
func buildRegistry(cfg *config.Config) (*policy.Registry, error) {
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
	prober := unavailableProber()
	for _, g := range cfg.Groups {
		var (
			group policy.Group
			err   error
		)
		switch g.Type {
		case config.GroupSelect:
			group, err = policy.NewSelect(g.Name, g.Members, "")
		case config.GroupURLTest:
			group, err = policy.NewURLTest(g.Name, g.Members, prober, g.Interval, g.Timeout, g.Tolerance)
		case config.GroupFallback:
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

// unavailableProber stands in for the outbound layer: until a dialer exists no
// member can be reached, so every probe fails and groups keep their declared
// order instead of pretending a member is healthy.
func unavailableProber() policy.Prober {
	return policy.ProbeFunc(func(context.Context, string) (time.Duration, error) {
		return 0, errors.New("outbound protocols are not implemented in this build")
	})
}

// printSummary reports what a validated configuration would activate.
func printSummary(cfg *config.Config, program *rules.Program) {
	stats := program.Stats()
	fmt.Printf("configuration: %s\n", cfg.Path)
	fmt.Printf("rules: %d (final: %v, rule sets: %v)\n", stats.Total, stats.Final, stats.RuleSets)
	fmt.Printf("indexes: %d suffixes, %d exact names, %d keywords, %d ipv4 ranges, %d ipv6 ranges, %d port ranges\n",
		stats.Suffixes, stats.Domains, stats.Keywords, stats.Ranges4, stats.Ranges6, stats.Ports)
	fmt.Printf("proxies: %d\ngroups: %d\n", len(cfg.Proxies), len(cfg.Groups))
}
