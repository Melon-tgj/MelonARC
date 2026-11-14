package config

import (
	"fmt"
	"net"
	"path/filepath"
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
	// Subscriptions are the [Subscription] declarations. They are fetched by
	// the daemon, not by this package: parsing a configuration must stay
	// offline and free of side effects so that -check and the tests are safe.
	Subscriptions []Subscription
}

// Subscription is one entry of the [Subscription] section: a URL that returns
// a list of share links, and how often to refresh it.
//
// A subscription is also a target that rules and groups may point at. Once its
// links are imported it becomes a select group holding every node it
// contributed, so a rule can say "Subscription" without knowing the node names
// a provider might change tomorrow.
type Subscription struct {
	Name     string
	URL      string
	Interval time.Duration
	Line     int
}

// General holds the process wide settings of the [General] section.
type General struct {
	// LogLevel is one of debug, info, warn, error.
	LogLevel string
	// APIListen is the loopback address of the local API, empty when the API
	// should not be started.
	APIListen string
	// HTTPListen is the loopback address of the HTTP inbound, empty when that
	// listener is off.
	HTTPListen string
	// SOCKS5Listen is the loopback address of the SOCKS5 inbound, empty when
	// that listener is off.
	SOCKS5Listen string
	// SOCKS5Username and SOCKS5Password make the SOCKS5 inbound ask for
	// username and password authentication. Both empty means it accepts
	// without authentication.
	SOCKS5Username string
	SOCKS5Password string
	// DataDir is where the core keeps its local state, such as the API token
	// file. Empty means the platform's configuration directory plus the
	// product name; a relative value is resolved against the directory of the
	// configuration file, the same rule rule sets follow.
	DataDir string
	// NameServers are the plaintext DNS servers, in the order they are asked.
	// Empty means names go to the system resolver, which is also the fallback
	// when every server here fails.
	NameServers []string
	// DNSFallback is "system" or "none": whether a failed upstream lookup falls
	// back to the system resolver. Empty means "system", which is the default
	// because an unreachable upstream should not take name resolution away.
	DNSFallback string
	// DNSTimeout bounds one attempt against one upstream server, over one
	// transport. The whole lookup is still bounded by the resolver's own
	// timeout.
	DNSTimeout time.Duration
	// GeoIPDB is the MaxMind DB file that answers GEOIP rules, empty when no
	// such rule exists. A relative value is resolved against the directory of
	// the configuration file.
	GeoIPDB string
	// ASNDB is the MaxMind DB file that answers IP-ASN rules, empty when no
	// such rule exists.
	ASNDB string
	// TUN holds the device settings of the TUN inbound. It is off unless
	// Enable is true: creating a device and installing routes is privileged
	// and must never happen because a configuration was merely loaded.
	TUN TUN
	// SystemProxy points the desktop proxy of the machine at the inbound
	// listeners while the daemon runs, and puts it back when it stops.
	//
	// It is off by default and it is a startup setting, not a reloadable one:
	// writing the desktop setting is a side effect on the machine, and a reload
	// that changes the routing must not also change what every other
	// application on the machine sends where. A change to it is reported by
	// pending_restart until the daemon is restarted.
	SystemProxy bool
	// SystemProxyBypass adds hosts the desktop proxy must not be used for. The
	// loopback names are always bypassed, because the API and the token file
	// live there.
	SystemProxyBypass []string
}

// TUN is one [General] device setting group. A zero value means "off": the
// parser leaves the fields empty and Validate fills in the defaults only when
// Enable is true, so a configuration from an earlier stage is unchanged.
type TUN struct {
	Enable     bool
	Name       string
	Address    string
	MTU        int
	Routes     []string
	UDPTimeout time.Duration
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

// The values dns-fallback accepts.
const (
	// DNSFallbackSystem asks the system resolver when every configured upstream
	// failed.
	DNSFallbackSystem = "system"
	// DNSFallbackNone fails the lookup instead, so a configuration can insist
	// that names are only ever answered by the servers it names.
	DNSFallbackNone = "none"
)

// BuiltinTargets lists the targets available without any declaration.
func BuiltinTargets() []string { return []string{TargetDirect, TargetReject} }

// knownProxyTypes lists the outbound types this build understands. The
// protocols themselves arrive in a later stage; the names are validated here so
// a typo fails at load time instead of at dial time.
var knownProxyTypes = map[string]bool{
	"ss": true, "vmess": true, "vless": true, "trojan": true, "snell": true,
	"hysteria2": true, "tuic": true, "socks5": true, "socks5-tls": true,
	"http": true, "https": true,
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

// HostMap returns the [Host] table in the shape the resolver takes: name to
// addresses. Names are already lower case from parsing, but they are normalised
// here too so the resolver does not depend on how the parser spelled them.
func (c *Config) HostMap() map[string][]net.IP {
	out := make(map[string][]net.IP, len(c.Hosts))
	for _, h := range c.Hosts {
		out[strings.ToLower(h.Name)] = append([]net.IP(nil), h.Addrs...)
	}
	return out
}

// RuleSetPaths returns the name to path map the rule compiler expects.
func (c *Config) RuleSetPaths() map[string]string {
	out := make(map[string]string, len(c.RuleSets))
	for _, r := range c.RuleSets {
		out[r.Name] = r.Path
	}
	return out
}

// FallbackToSystem reports whether a failed upstream lookup may be answered by
// the system resolver. The default is yes: falling back keeps a stale
// nameserver setting from taking name resolution away entirely, and the answer
// is still cached and reported with its own source.
func (g General) FallbackToSystem() bool {
	return !strings.EqualFold(g.DNSFallback, DNSFallbackNone)
}

// DataPath resolves a path taken from the configuration against the directory of
// the configuration file, the same rule rule sets follow. An absolute path is
// kept as written, so a data set can live outside the configuration directory.
//
// Nothing is checked here: whether the file exists is a question for the loader,
// because -check has to work without touching the file system.
func (c *Config) DataPath(path string) string {
	if path == "" || filepath.IsAbs(path) || c.BaseDir == "" {
		return path
	}
	return filepath.Join(c.BaseDir, path)
}
