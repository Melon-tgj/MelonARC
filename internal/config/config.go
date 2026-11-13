package config

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/melon-tgj/melonarc/internal/rules"
)

// Config is a parsed and validated native configuration file.
type Config struct {
	// Path is the absolute path the configuration was loaded from, empty when
	// it was parsed from memory.
	Path string
	// BaseDir is the directory relative rule set paths are resolved against.
	BaseDir string

	General  General
	Proxies  []Proxy
	Groups   []Group
	RuleSets []RuleSet
	Rules    []*rules.Rule
	Hosts    []HostEntry
}

// General holds the process wide settings of the [General] section.
type General struct {
	// LogLevel is one of debug, info, warn, error.
	LogLevel string
	// APIListen is the loopback address of the local API, empty when the API
	// should not be started.
	APIListen string
}

// Proxy is one entry of the [Proxy] section. Everything after the type is kept
// verbatim as Args: interpreting it belongs to the outbound implementation, and
// keeping it raw means a password containing "=" is not mistaken for settings.
type Proxy struct {
	Name   string
	Type   string
	Server string
	Port   int
	Args   []string
	Line   int
}

// GroupType is the behaviour of a policy group.
type GroupType string

// The three policy group types of the MVP.
const (
	GroupSelect   GroupType = "select"
	GroupURLTest  GroupType = "url-test"
	GroupFallback GroupType = "fallback"
)

// Group is one entry of the [Proxy Group] section.
type Group struct {
	Name      string
	Type      GroupType
	Members   []string
	URL       string
	Interval  time.Duration
	Tolerance time.Duration
	Timeout   time.Duration
	Line      int
}

// RuleSet is a declared external rule set.
type RuleSet struct {
	Name string
	Path string
	Line int
}

// HostEntry is one entry of the [Host] section.
type HostEntry struct {
	Name  string
	Addrs []net.IP
	Line  int
}

// Reserved target names that always exist.
const (
	TargetDirect = "DIRECT"
	TargetReject = "REJECT"
)

// BuiltinTargets lists the targets available without any declaration.
func BuiltinTargets() []string { return []string{TargetDirect, TargetReject} }

// knownProxyTypes lists the outbound types this build understands. The
// protocols themselves arrive in a later stage; the names are validated here so
// a typo fails at load time instead of at dial time.
var knownProxyTypes = map[string]bool{
	"ss": true, "vmess": true, "vless": true, "trojan": true, "snell": true,
	"hysteria2": true, "tuic": true, "socks5": true, "http": true, "https": true,
}

// logLevels is the accepted set of log levels.
var logLevels = map[string]bool{"debug": true, "info": true, "warn": true, "error": true}

// Issue is one configuration problem, with the line it was found on when the
// problem is tied to a line.
type Issue struct {
	Line    int
	Section string
	Message string
}

// String renders the issue as "section line N: message".
func (i Issue) String() string {
	switch {
	case i.Line > 0 && i.Section != "":
		return fmt.Sprintf("%s line %d: %s", i.Section, i.Line, i.Message)
	case i.Line > 0:
		return fmt.Sprintf("line %d: %s", i.Line, i.Message)
	case i.Section != "":
		return fmt.Sprintf("%s: %s", i.Section, i.Message)
	default:
		return i.Message
	}
}

// Errors is the aggregated result of parsing or validation. Every problem is
// reported, not just the first one, so a configuration can be fixed in one pass.
type Errors struct {
	Issues []Issue
}

// Error implements error.
func (e *Errors) Error() string {
	if len(e.Issues) == 0 {
		return "configuration is valid"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d configuration problem(s):", len(e.Issues))
	for _, issue := range e.Issues {
		b.WriteString("\n  - ")
		b.WriteString(issue.String())
	}
	return b.String()
}

// add appends an issue, using a printf style message.
func (e *Errors) add(line int, section, format string, args ...interface{}) {
	e.Issues = append(e.Issues, Issue{Line: line, Section: section, Message: fmt.Sprintf(format, args...)})
}

// Err returns the error, or nil when no issue was recorded.
func (e *Errors) Err() error {
	if len(e.Issues) == 0 {
		return nil
	}
	return e
}

// ProxyByName returns the proxy with the given name.
func (c *Config) ProxyByName(name string) (Proxy, bool) {
	for _, p := range c.Proxies {
		if p.Name == name {
			return p, true
		}
	}
	return Proxy{}, false
}

// GroupByName returns the group with the given name.
func (c *Config) GroupByName(name string) (Group, bool) {
	for _, g := range c.Groups {
		if g.Name == name {
			return g, true
		}
	}
	return Group{}, false
}

// RuleSetByName returns the declared rule set with the given name.
func (c *Config) RuleSetByName(name string) (RuleSet, bool) {
	for _, r := range c.RuleSets {
		if r.Name == name {
			return r, true
		}
	}
	return RuleSet{}, false
}

// HostByName returns the address mapping for a name.
func (c *Config) HostByName(name string) ([]net.IP, bool) {
	for _, h := range c.Hosts {
		if h.Name == name {
			return h.Addrs, true
		}
	}
	return nil, false
}

// RuleSetPaths returns the name to path map the rule compiler expects.
func (c *Config) RuleSetPaths() map[string]string {
	out := make(map[string]string, len(c.RuleSets))
	for _, r := range c.RuleSets {
		out[r.Name] = r.Path
	}
	return out
}
