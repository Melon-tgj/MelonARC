package config

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/melon-tgj/melonarc/internal/dns"
	"github.com/melon-tgj/melonarc/internal/outbound"
	"github.com/melon-tgj/melonarc/internal/rules"
)

// maxNameLen bounds the length of a proxy or group name.
const maxNameLen = 128

// Validate runs the semantic checks that decide whether a configuration may
// take effect: every reference must resolve, every rule set must be declared,
// the rule list must end with FINAL and the local API must stay on loopback.
// All problems are reported together.
func (c *Config) Validate() error {
	issues := &Errors{}
	c.normaliseTargets()
	c.validateGeneral(issues)
	targets := c.validateProxies(issues)
	// Subscriptions are checked before groups so their names can be offered as
	// valid targets: a group or a rule may point at a subscription the same way
	// it points at a proxy, and the nodes behind it are only known once it has
	// been fetched.
	virtual := c.validateSubscriptions(issues, targets)
	c.validateGroups(issues, targets, virtual)
	c.validateRuleSets(issues)
	c.validateRules(issues, targets, virtual)
	c.validateHosts(issues)
	return issues.Err()
}

// normaliseTargets upper-cases the built-in targets so that "direct" in a rule
// means the same thing as "DIRECT". Proxy and group names stay case sensitive.
func (c *Config) normaliseTargets() {
	for _, r := range c.Rules {
		switch {
		case strings.EqualFold(r.Target, TargetDirect):
			r.Target = TargetDirect
		case strings.EqualFold(r.Target, TargetReject):
			r.Target = TargetReject
		}
	}
}

func (c *Config) validateGeneral(issues *Errors) {
	if c.General.LogLevel == "" {
		c.General.LogLevel = defaultLogLevel
	}
	if !logLevels[c.General.LogLevel] {
		issues.add(0, "[General]", "log-level %q is not one of debug, info, warn, error", c.General.LogLevel)
	}
	c.validateListen(issues, "api-listen", c.General.APIListen)
	c.validateListen(issues, "http-listen", c.General.HTTPListen)
	c.validateListen(issues, "socks5-listen", c.General.SOCKS5Listen)
	c.validateInboundAuth(issues)
	c.validateDataDir(issues)
	c.validateDNS(issues)
	c.validateDatasets(issues)
	c.validateTUN(issues)
	c.validateSystemProxy(issues)
}

// Constants for the desktop proxy setting. The entry bound keeps the value that
// goes into a desktop field from being unbounded, and the separator is rejected
// because the Windows value is a semicolon separated list: an entry containing
// one would silently become two entries.
const (
	maxBypassEntries = 128
	maxBypassLen     = 255
)

// validateSystemProxy checks the desktop proxy setting.
//
// The two errors it can report are the same shape as the ones the TUN settings
// use: a setting that is written but has no effect is a configuration the
// operator believes is in force, and turning the desktop proxy on with nothing
// to point it at would send every application on the machine to a port that
// does not answer.
func (c *Config) validateSystemProxy(issues *Errors) {
	g := &c.General
	if !g.SystemProxy {
		if len(g.SystemProxyBypass) > 0 {
			issues.add(0, "[General]", "system-proxy-bypass is set but system-proxy is off, so it has no effect")
		}
		return
	}
	if g.HTTPListen == "" && g.SOCKS5Listen == "" {
		issues.add(0, "[General]", "system-proxy is on but no inbound listener is configured: "+
			"the desktop proxy would point at a port nothing answers on")
		return
	}
	if len(g.SystemProxyBypass) > maxBypassEntries {
		issues.add(0, "[General]", "system-proxy-bypass lists more than %d entries", maxBypassEntries)
	}
	for _, entry := range g.SystemProxyBypass {
		switch {
		case entry == "":
			issues.add(0, "[General]", "system-proxy-bypass contains an empty entry")
		case len(entry) > maxBypassLen:
			issues.add(0, "[General]", "system-proxy-bypass entry %q is longer than %d bytes", entry, maxBypassLen)
		case strings.ContainsAny(entry, ";"):
			issues.add(0, "[General]", "system-proxy-bypass entry %q contains ';', which separates entries", entry)
		}
	}
}

// validateTUN checks the device settings and fills in their defaults. It is
// shape-only: a TUN device is opened when the daemon starts, never during a
// validation run, so -check stays free of privileged operations.
//
// The "settings written while the device is off" error follows the same rule as
// SOCKS5 credentials with no listener: a setting that is silently ignored is a
// configuration the operator believes is in force.
func (c *Config) validateTUN(issues *Errors) {
	t := &c.General.TUN
	if !t.Enable {
		if t.Name != "" || t.Address != "" || t.MTU != 0 || t.Routes != nil || t.UDPTimeout != 0 {
			issues.add(0, "[General]", "tun-* settings are written but tun-enable is off, so they have no effect")
		}
		return
	}
	if t.Name == "" {
		t.Name = defaultTUNName
	}
	if t.Address == "" {
		t.Address = defaultTUNAddress
	}
	if t.MTU == 0 {
		t.MTU = defaultTUNMTU
	}
	if t.UDPTimeout == 0 {
		t.UDPTimeout = defaultTUNUDPTimeout
	}
	if !validTUNName(t.Name) {
		issues.add(0, "[General]", "tun-name %q must be 1-%d ASCII letters, digits, '-', '_' or '.' and must not start with '-' or '.'",
			t.Name, maxTUNNameLen)
	}
	addr, network, err := net.ParseCIDR(t.Address)
	switch {
	case err != nil:
		issues.add(0, "[General]", "tun-address %q is not an IPv4 address with a prefix: %v", t.Address, err)
	case addr.To4() == nil:
		issues.add(0, "[General]", "tun-address %q is not IPv4", t.Address)
	case addr.IsLoopback() || addr.IsUnspecified() || addr.IsMulticast():
		issues.add(0, "[General]", "tun-address %q cannot be a loopback, unspecified or multicast address", t.Address)
	default:
		if ones, _ := network.Mask.Size(); ones < 1 || ones > 32 {
			issues.add(0, "[General]", "tun-address %q has an invalid prefix length", t.Address)
		}
	}
	if t.MTU < minTUNMTU || t.MTU > maxTUNMTU {
		issues.add(0, "[General]", "tun-mtu %d is outside %d-%d", t.MTU, minTUNMTU, maxTUNMTU)
	}
	if len(t.Routes) > maxTUNRoutes {
		issues.add(0, "[General]", "tun-route lists more than %d prefixes", maxTUNRoutes)
	}
	for _, route := range t.Routes {
		ip, _, err := net.ParseCIDR(route)
		if err != nil || ip.To4() == nil {
			issues.add(0, "[General]", "tun-route %q is not an IPv4 prefix", route)
		}
	}
	if t.UDPTimeout <= 0 || t.UDPTimeout > 24*time.Hour {
		issues.add(0, "[General]", "tun-udp-timeout must be positive and no longer than a day")
	}
}

// validTUNName checks the shape of a network interface name. Linux limits it to
// 15 bytes and forbids '/' and whitespace, so this package accepts a narrower
// ASCII set than the kernel does and reports the rest at load time.
func validTUNName(name string) bool {
	if name == "" || len(name) > maxTUNNameLen {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-' || c == '_' || c == '.':
		default:
			return false
		}
	}
	return name[0] != '-' && name[0] != '.'
}

// validateDNS checks the plaintext upstream settings.
//
// The server addresses are parsed with the same function the client uses, so a
// configuration that validates is a configuration the client can ask. Whether a
// server answers is a different question, and one validation must not answer: it
// stays read-only and offline.
func (c *Config) validateDNS(issues *Errors) {
	for _, server := range c.General.NameServers {
		if _, err := dns.ParseNameServer(server); err != nil {
			issues.add(0, "[General]", "dns-nameserver: %v", err)
		}
	}
	if c.General.DNSFallback != "" {
		switch c.General.DNSFallback {
		case DNSFallbackSystem, DNSFallbackNone:
		default:
			issues.add(0, "[General]", "dns-fallback %q is not one of system, none", c.General.DNSFallback)
		}
		if len(c.General.NameServers) == 0 {
			issues.add(0, "[General]", "dns-fallback is set but dns-nameserver is empty, so it has no effect")
		}
	}
	if c.General.DNSTimeout <= 0 {
		issues.add(0, "[General]", "dns-timeout must be positive")
	}
}

// maxDatasetPathLen bounds a configured data file path, for the same reason
// data-dir is bounded: it is a path, not a document.
const maxDatasetPathLen = 4096

// validateDatasets checks the shape of the two MaxMind DB paths. Their existence
// is not checked here: loading them belongs to the rule compiler, which reports a
// missing or corrupt file with the path and the reason, and a validation run
// stays free of file system side effects.
func (c *Config) validateDatasets(issues *Errors) {
	for _, path := range []struct {
		key   string
		value string
	}{
		{"geoip-db", c.General.GeoIPDB},
		{"asn-db", c.General.ASNDB},
	} {
		if path.value == "" {
			continue
		}
		if len(path.value) > maxDatasetPathLen {
			issues.add(0, "[General]", "%s is longer than %d bytes", path.key, maxDatasetPathLen)
			continue
		}
		for i := 0; i < len(path.value); i++ {
			if path.value[i] < 0x20 || path.value[i] == 0x7f {
				issues.add(0, "[General]", "%s must not contain control characters", path.key)
				break
			}
		}
	}
}

// maxDataDirLen bounds the data directory setting. It is a path, not a message:
// a longer value is a pasted document rather than something a user typed.
const maxDataDirLen = 4096

// validateDataDir checks the shape of data-dir only. Whether the directory
// exists is deliberately not part of validation: a configuration has to be
// checkable without creating anything, and the directory is made when the core
// first writes to it.
func (c *Config) validateDataDir(issues *Errors) {
	dir := c.General.DataDir
	if dir == "" {
		return
	}
	if len(dir) > maxDataDirLen {
		issues.add(0, "[General]", "data-dir is longer than %d bytes", maxDataDirLen)
		return
	}
	for i := 0; i < len(dir); i++ {
		if dir[i] < 0x20 || dir[i] == 0x7f {
			issues.add(0, "[General]", "data-dir must not contain control characters")
			return
		}
	}
}

// validateListen checks one host:port listen setting. An empty value means the
// service stays off. Every listener of this daemon stays on the loopback
// interface: an inbound proxy that is reachable from the network would be an
// open relay the moment it has no credentials, and sharing one across a LAN is
// not in the MVP.
func (c *Config) validateListen(issues *Errors, key, addr string) {
	if addr == "" {
		return
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		issues.add(0, "[General]", "%s %q must be host:port", key, addr)
		return
	}
	if n, err := parsePortNumber(port); err != nil {
		issues.add(0, "[General]", "%s port: %v", key, err)
	} else if n == 0 {
		issues.add(0, "[General]", "%s needs a fixed port, %q is 0", key, port)
	}
	if !isLoopbackHost(host) {
		if key == "api-listen" {
			issues.add(0, "[General]", "api-listen %q is not a loopback address; the local API never listens on a routable interface", addr)
			return
		}
		issues.add(0, "[General]", "%s %q is not a loopback address; the inbound listens on loopback only", key, addr)
	}
}

// maxCredentialLen bounds an inbound credential: both protocols carry each half
// in one length byte.
const maxCredentialLen = 255

// validateInboundAuth checks the optional SOCKS5 inbound credentials. Half a
// pair is a configuration mistake, not a silent fallback to no authentication.
func (c *Config) validateInboundAuth(issues *Errors) {
	user, pass := c.General.SOCKS5Username, c.General.SOCKS5Password
	switch {
	case user == "" && pass == "":
		return
	case user == "":
		issues.add(0, "[General]", "socks5-password is set without socks5-username")
		return
	case pass == "":
		issues.add(0, "[General]", "socks5-username is set without socks5-password")
		return
	}
	if len(user) > maxCredentialLen || len(pass) > maxCredentialLen {
		issues.add(0, "[General]", "socks5-username and socks5-password are limited to %d bytes each", maxCredentialLen)
	}
	for _, s := range []string{user, pass} {
		for i := 0; i < len(s); i++ {
			if s[i] < 0x20 || s[i] == 0x7f {
				issues.add(0, "[General]", "socks5 credentials must not contain control characters")
				break
			}
		}
	}
	if c.General.SOCKS5Listen == "" {
		issues.add(0, "[General]", "socks5 credentials are set but socks5-listen is off, so they have no effect")
	}
}

// isLoopbackHost reports whether a host names the loopback interface.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// parsePortNumber parses a decimal port number.
func parsePortNumber(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("%q is not a number", s)
	}
	if n < 0 || n > 65535 {
		return 0, fmt.Errorf("%q is outside 0-65535", s)
	}
	return n, nil
}

// validateProxies checks every [Proxy] entry and returns the set of names that
// rules and groups may point at.
func (c *Config) validateProxies(issues *Errors) map[string]bool {
	targets := map[string]bool{TargetDirect: true, TargetReject: true}
	seen := make(map[string]int, len(c.Proxies))
	for _, p := range c.Proxies {
		if err := validName(p.Name); err != nil {
			issues.add(p.Line, "[Proxy]", "%v", err)
		} else if _, dup := seen[p.Name]; dup {
			issues.add(p.Line, "[Proxy]", "proxy %q is defined more than once", p.Name)
		}
		seen[p.Name] = p.Line
		if isBuiltinName(p.Name) {
			issues.add(p.Line, "[Proxy]", "%q is a reserved target and cannot be redefined", p.Name)
		}
		if !knownProxyTypes[p.Type] {
			issues.add(p.Line, "[Proxy]", "proxy %q has unknown type %q", p.Name, p.Type)
		}
		if p.Server == "" {
			issues.add(p.Line, "[Proxy]", "proxy %q has no server", p.Name)
		} else if strings.ContainsAny(p.Server, " \t") {
			issues.add(p.Line, "[Proxy]", "proxy %q: server %q contains whitespace", p.Name, p.Server)
		}
		if p.Port < 1 || p.Port > 65535 {
			issues.add(p.Line, "[Proxy]", "proxy %q needs a port between 1 and 65535", p.Name)
		}
		// The TLS options are shared by every secured outbound. Checking them
		// here (rather than only when the daemon assembles its dialers) gives a
		// bad sni or a TLS option on a plaintext type a section and a line in
		// the aggregated report, in the same shape as every other problem.
		if err := outbound.ValidateTLSOptions(p.Type, p.Args); err != nil {
			issues.add(p.Line, "[Proxy]", "proxy %q: %v", p.Name, err)
		}
		targets[p.Name] = true
	}
	return targets
}

// validateGroups checks every [Proxy Group] entry, including the reference
// graph formed by nested groups.
func (c *Config) validateGroups(issues *Errors, targets, virtual map[string]bool) {
	groups := make(map[string]*Group, len(c.Groups))
	for i := range c.Groups {
		g := &c.Groups[i]
		if prev, dup := groups[g.Name]; dup {
			issues.add(g.Line, "[Proxy Group]", "group %q is already defined on line %d", g.Name, prev.Line)
			continue
		}
		groups[g.Name] = g
		if err := validName(g.Name); err != nil {
			issues.add(g.Line, "[Proxy Group]", "%v", err)
		}
		if isBuiltinName(g.Name) {
			issues.add(g.Line, "[Proxy Group]", "%q is a reserved target and cannot be redefined", g.Name)
		}
		if _, taken := targets[g.Name]; taken && !isBuiltinName(g.Name) {
			issues.add(g.Line, "[Proxy Group]", "group %q has the same name as a proxy", g.Name)
		}
		switch g.Type {
		case GroupSelect, GroupURLTest, GroupFallback:
		default:
			issues.add(g.Line, "[Proxy Group]", "group %q has unknown type %q", g.Name, g.Type)
		}
		// A subscription group is filled by the import, so it is legitimately
		// empty until the first fetch has succeeded.
		if len(g.Members) == 0 && !virtual[g.Name] {
			issues.add(g.Line, "[Proxy Group]", "group %q has no members", g.Name)
		}
		if g.Type == GroupURLTest || g.Type == GroupFallback {
			if g.URL == "" {
				issues.add(g.Line, "[Proxy Group]", "group %q needs url= to probe its members", g.Name)
			} else if u, err := url.Parse(g.URL); err != nil || u.Host == "" {
				issues.add(g.Line, "[Proxy Group]", "group %q: url %q is not an absolute URL", g.Name, g.URL)
			} else if u.Scheme != "http" && u.Scheme != "https" {
				issues.add(g.Line, "[Proxy Group]", "group %q: url scheme %q is not http or https", g.Name, u.Scheme)
			}
		}
		if g.Interval <= 0 {
			issues.add(g.Line, "[Proxy Group]", "group %q: interval must be positive", g.Name)
		}
		if g.Timeout <= 0 {
			issues.add(g.Line, "[Proxy Group]", "group %q: timeout must be positive", g.Name)
		}
		if g.Tolerance < 0 {
			issues.add(g.Line, "[Proxy Group]", "group %q: tolerance must not be negative", g.Name)
		}
		targets[g.Name] = true
	}

	// Members are checked once every group name is known, so a group may refer
	// to one defined further down the file.
	for _, g := range c.Groups {
		for _, m := range g.Members {
			if m == g.Name {
				issues.add(g.Line, "[Proxy Group]", "group %q lists itself as a member", g.Name)
				continue
			}
			if !targets[m] && !virtual[m] {
				issues.add(g.Line, "[Proxy Group]", "group %q refers to unknown member %q", g.Name, m)
			}
		}
	}

	reportCycles(c.Groups, issues)
}

// reportCycles finds cycles in the group graph and reports each one once.
func reportCycles(groups []Group, issues *Errors) {
	members := make(map[string][]string, len(groups))
	for _, g := range groups {
		members[g.Name] = g.Members
	}
	const (
		white = 0
		grey  = 1
		black = 2
	)
	state := make(map[string]int, len(groups))
	reported := make(map[string]bool)

	var visit func(name string, path []string)
	visit = func(name string, path []string) {
		state[name] = grey
		path = append(path, name)
		for _, m := range members[name] {
			if _, ok := members[m]; !ok {
				continue
			}
			switch state[m] {
			case grey:
				cycle := append(append([]string(nil), path...), m)
				key := cycleKey(cycle)
				if !reported[key] {
					reported[key] = true
					issues.add(0, "[Proxy Group]", "policy group cycle: %s", strings.Join(cycle, " -> "))
				}
			case white:
				visit(m, path)
			}
		}
		state[name] = black
	}
	for _, g := range groups {
		if state[g.Name] == white {
			visit(g.Name, nil)
		}
	}
}

// cycleKey normalises a cycle so rotations of the same loop collapse.
func cycleKey(cycle []string) string {
	if len(cycle) < 2 {
		return ""
	}
	body := cycle[:len(cycle)-1]
	min := 0
	for i, s := range body {
		if s < body[min] {
			min = i
		}
	}
	rotated := append(append([]string(nil), body[min:]...), body[:min]...)
	return strings.Join(rotated, "->")
}

func (c *Config) validateRuleSets(issues *Errors) {
	seen := make(map[string]int, len(c.RuleSets))
	for _, rs := range c.RuleSets {
		if err := validName(rs.Name); err != nil {
			issues.add(rs.Line, "[Rule]", "rule set: %v", err)
		}
		if prev, dup := seen[rs.Name]; dup {
			issues.add(rs.Line, "[Rule]", "rule set %q is declared again (first on line %d)", rs.Name, prev)
		}
		seen[rs.Name] = rs.Line
		if strings.TrimSpace(rs.Path) == "" {
			issues.add(rs.Line, "[Rule]", "rule set %q has an empty path", rs.Name)
		}
	}
}

func (c *Config) validateRules(issues *Errors, targets, virtual map[string]bool) {
	if len(c.Rules) == 0 {
		issues.add(0, "[Rule]", "the rule list is empty")
		return
	}
	declared := make(map[string]bool, len(c.RuleSets))
	for _, rs := range c.RuleSets {
		declared[rs.Name] = true
	}

	finalLine := 0
	for i, r := range c.Rules {
		if r.Kind == rules.KindFinal {
			if finalLine != 0 {
				issues.add(r.Line, "[Rule]", "FINAL appears more than once (first on line %d)", finalLine)
				continue
			}
			finalLine = r.Line
			if i != len(c.Rules)-1 {
				issues.add(r.Line, "[Rule]", "FINAL must be the last rule")
			}
		}
		if r.Kind.IsSet() {
			if !declared[r.Payload] {
				issues.add(r.Line, "[Rule]", "%s refers to undeclared rule set %q", r.Kind, r.Payload)
			}
		}
		if !targets[r.Target] && !virtual[r.Target] {
			issues.add(r.Line, "[Rule]", "rule targets unknown policy or outbound %q", r.Target)
		}
	}
	if finalLine == 0 {
		issues.add(0, "[Rule]", "the rule list must end with FINAL")
	}
}

func (c *Config) validateHosts(issues *Errors) {
	seen := make(map[string]int, len(c.Hosts))
	for _, h := range c.Hosts {
		if err := validHostName(h.Name); err != nil {
			issues.add(h.Line, "[Host]", "%v", err)
		}
		if prev, dup := seen[h.Name]; dup {
			issues.add(h.Line, "[Host]", "host %q is already mapped on line %d", h.Name, prev)
		}
		seen[h.Name] = h.Line
		if len(h.Addrs) == 0 {
			issues.add(h.Line, "[Host]", "host %q has no address", h.Name)
		}
	}
}

// isBuiltinName reports whether a name is reserved for a built-in target.
func isBuiltinName(name string) bool {
	return strings.EqualFold(name, TargetDirect) || strings.EqualFold(name, TargetReject)
}

// validName checks a proxy, group or rule set name. The character set matches
// what a rule line can carry, since these names are written into rules.
func validName(name string) error {
	if name == "" {
		return fmt.Errorf("name is empty")
	}
	if len(name) > maxNameLen {
		return fmt.Errorf("name %q is longer than %d bytes", name, maxNameLen)
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-' || c == '_' || c == '.' || c == '/':
		default:
			return fmt.Errorf("name %q contains an unsupported character %q", name, c)
		}
	}
	switch name[0] {
	case '-', '.', '/':
		return fmt.Errorf("name %q must start with a letter, digit or underscore", name)
	}
	return nil
}

// validHostName checks a [Host] key.
func validHostName(name string) error {
	if name == "" {
		return fmt.Errorf("host name is empty")
	}
	if len(name) > 253 {
		return fmt.Errorf("host name %q is longer than 253 bytes", name)
	}
	if strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") || strings.Contains(name, "..") {
		return fmt.Errorf("host name %q has an empty label", name)
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-' || c == '_' || c == '.':
		default:
			return fmt.Errorf("host name %q contains an unsupported character %q", name, c)
		}
	}
	return nil
}
