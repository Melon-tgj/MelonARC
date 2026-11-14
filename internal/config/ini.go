package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/melon-tgj/melonarc/internal/rules"
)

// Section names of the native format.
const (
	sectionGeneral      = "general"
	sectionProxy        = "proxy"
	sectionProxyGrp     = "proxy group"
	sectionRule         = "rule"
	sectionHost         = "host"
	sectionSubscription = "subscription"
	ruleSetKeyword      = "rule-set"
	defaultAPIListen    = "127.0.0.1:7946"
	defaultLogLevel     = "info"
)

// Defaults for the inbound listeners. They are on by default because the
// daemon exists to carry traffic: a configuration that says nothing about
// them still gives a local application something to point at.
const (
	defaultHTTPListen   = "127.0.0.1:7890"
	defaultSOCKS5Listen = "127.0.0.1:7891"
)

// listenOff is the value that switches a listener off. An empty value cannot be
// written as "key = " because that is a syntax error, so the setting needs a
// word of its own.
const listenOff = "off"

// Defaults for the TUN device. Enabling the device installs the route to its
// own prefix plus the name address range; taking over the whole routing table
// is a separate, explicit choice made with tun-route.
const (
	defaultTUNName       = "melonarc0"
	defaultTUNAddress    = "198.18.0.1/24"
	defaultTUNMTU        = 1500
	defaultTUNUDPTimeout = 30 * time.Second
	maxTUNRoutes         = 64
	minTUNMTU            = 576
	maxTUNMTU            = 65535
	maxTUNNameLen        = 15 // IFNAMSIZ includes the terminating NUL
)

// Defaults for policy group timings.
const (
	defaultInterval  = 300 * time.Second
	defaultTimeout   = 5 * time.Second
	defaultTolerance = 50 * time.Millisecond
)

// Defaults for subscription updates. Six hours matches how often providers
// publish changes; a shorter floor keeps a typo from turning into a request
// every few seconds against somebody else's server.
const (
	defaultSubscriptionInterval = 6 * time.Hour
	minSubscriptionInterval     = 5 * time.Minute
)

// defaultDNSTimeout bounds one attempt against one plaintext upstream, over one
// transport.
//
// It is deliberately smaller than a quarter of the resolver's own budget: a
// question costs one datagram and one stream attempt per server, so two
// configured servers spend at most four attempts, and a five second lookup
// budget still has a second left for the system fallback. A larger value spends
// the budget on a server that is not talking and quietly turns the configured
// fallback into "give up".
const defaultDNSTimeout = time.Second

// Load reads, parses and validates a configuration file. Both the parse result
// and the errors are returned: a caller that wants to show every problem at
// once can inspect the partial configuration, but a non-nil error means the
// configuration must not be activated.
func Load(path string) (*Config, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", path, err)
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, err
	}
	cfg, perr := Parse(data)
	if cfg != nil {
		cfg.Path = abs
		cfg.BaseDir = filepath.Dir(abs)
	}
	if perr != nil {
		return cfg, perr
	}
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// Parse turns configuration text into a Config. It checks syntax only; use
// Validate for the semantic checks that decide whether the configuration may
// take effect.
func Parse(data []byte) (*Config, error) {
	cfg := &Config{General: General{
		LogLevel:     defaultLogLevel,
		APIListen:    defaultAPIListen,
		HTTPListen:   defaultHTTPListen,
		SOCKS5Listen: defaultSOCKS5Listen,
		DNSTimeout:   defaultDNSTimeout,
	}}
	issues := &Errors{}
	seen := make(map[string]int) // "section/key" -> first line
	section := ""
	seenSection := false
	brokenSection := false

	for _, ln := range splitLines(data) {
		text := cleanLine(ln.text)
		if text == "" {
			continue
		}
		if strings.HasPrefix(text, "[") {
			name, err := parseSectionHeader(text)
			if err != nil {
				issues.add(ln.number, "", "%v", err)
				section = ""
				brokenSection = true
				continue
			}
			section = name
			brokenSection = false
			seenSection = true
			continue
		}
		if !seenSection {
			issues.add(ln.number, "", "entry appears before any section header")
			continue
		}
		if brokenSection {
			issues.add(ln.number, "", "entry is not inside a known section")
			continue
		}

		switch section {
		case sectionGeneral:
			key, value, ok := splitKeyValue(text)
			if !ok {
				issues.add(ln.number, "[General]", "expected key = value, got %q", text)
				continue
			}
			if err := parseGeneralEntry(cfg, key, value, ln.number, seen); err != nil {
				issues.add(ln.number, "[General]", "%v", err)
			}
		case sectionProxy:
			key, value, ok := splitKeyValue(text)
			if !ok {
				issues.add(ln.number, "[Proxy]", "expected name = type, arguments, got %q", text)
				continue
			}
			if prev, dup := seen["proxy/"+strings.ToLower(key)]; dup {
				issues.add(ln.number, "[Proxy]", "proxy %q is already defined on line %d", key, prev)
				continue
			}
			seen["proxy/"+strings.ToLower(key)] = ln.number
			cfg.Proxies = append(cfg.Proxies, parseProxy(key, value, ln.number))
		case sectionProxyGrp:
			key, value, ok := splitKeyValue(text)
			if !ok {
				issues.add(ln.number, "[Proxy Group]", "expected name = type, members, got %q", text)
				continue
			}
			if prev, dup := seen["group/"+strings.ToLower(key)]; dup {
				issues.add(ln.number, "[Proxy Group]", "group %q is already defined on line %d", key, prev)
				continue
			}
			seen["group/"+strings.ToLower(key)] = ln.number
			group, err := parseGroup(key, value, ln.number)
			if err != nil {
				issues.add(ln.number, "[Proxy Group]", "%v", err)
				continue
			}
			cfg.Groups = append(cfg.Groups, group)
		case sectionRule:
			parseRuleEntry(cfg, text, ln.number, issues, seen)
		case sectionHost:
			key, value, ok := splitKeyValue(text)
			if !ok {
				issues.add(ln.number, "[Host]", "expected name = address, got %q", text)
				continue
			}
			if prev, dup := seen["host/"+strings.ToLower(key)]; dup {
				issues.add(ln.number, "[Host]", "host %q is already defined on line %d", key, prev)
				continue
			}
			seen["host/"+strings.ToLower(key)] = ln.number
			entry, err := parseHost(key, value, ln.number)
			if err != nil {
				issues.add(ln.number, "[Host]", "%v", err)
				continue
			}
			cfg.Hosts = append(cfg.Hosts, entry)
		case sectionSubscription:
			key, value, ok := splitKeyValue(text)
			if !ok {
				issues.add(ln.number, "[Subscription]", "expected name = url, got %q", text)
				continue
			}
			if prev, dup := seen["subscription/"+strings.ToLower(key)]; dup {
				issues.add(ln.number, "[Subscription]", "subscription %q is already defined on line %d", key, prev)
				continue
			}
			seen["subscription/"+strings.ToLower(key)] = ln.number
			sub, err := parseSubscription(key, value, ln.number)
			if err != nil {
				issues.add(ln.number, "[Subscription]", "%v", err)
				continue
			}
			cfg.Subscriptions = append(cfg.Subscriptions, sub)
		}
	}
	// A subscription declares a group of its own. The nodes it contributes are
	// only known once it has been fetched, but the name has to be a valid
	// target at load time, so rules and groups can point at it and -check can
	// run without touching the network. The import fills in the members.
	for _, sub := range cfg.Subscriptions {
		cfg.Groups = append(cfg.Groups, Group{
			Name:      sub.Name,
			Type:      GroupSelect,
			Interval:  defaultInterval,
			Timeout:   defaultTimeout,
			Tolerance: defaultTolerance,
			Line:      sub.Line,
		})
	}
	return cfg, issues.Err()
}

// parseSectionHeader reads "[Name]" and returns the canonical section name.
func parseSectionHeader(text string) (string, error) {
	if !strings.HasSuffix(text, "]") || len(text) < 3 {
		return "", fmt.Errorf("malformed section header %q", text)
	}
	name := strings.TrimSpace(text[1 : len(text)-1])
	fields := strings.Fields(strings.ToLower(name))
	normalised := strings.Join(fields, " ")
	switch normalised {
	case sectionGeneral, sectionProxy, sectionProxyGrp, sectionRule, sectionHost, sectionSubscription:
		return normalised, nil
	}
	return "", fmt.Errorf("unknown section %q", name)
}

// parseGeneralEntry applies one [General] setting.
func parseGeneralEntry(cfg *Config, key, value string, line int, seen map[string]int) error {
	k := strings.ToLower(key)
	if prev, dup := seen["general/"+k]; dup {
		return fmt.Errorf("%s is already set on line %d", k, prev)
	}
	seen["general/"+k] = line

	switch k {
	case "log-level":
		// The accepted set is checked by Validate, so that parsing reports
		// syntax and validation reports semantics.
		cfg.General.LogLevel = strings.ToLower(value)
	case "api-listen":
		cfg.General.APIListen = value
	case "http-listen":
		cfg.General.HTTPListen = listenAddress(value)
	case "socks5-listen":
		cfg.General.SOCKS5Listen = listenAddress(value)
	case "socks5-username":
		cfg.General.SOCKS5Username = value
	case "socks5-password":
		cfg.General.SOCKS5Password = value
	case "data-dir":
		cfg.General.DataDir = value
	case "dns-nameserver":
		// The addresses keep the order they were written in: that order is the
		// order they are asked, which is the only way to express a preference.
		cfg.General.NameServers = splitList(value)
	case "dns-fallback":
		cfg.General.DNSFallback = strings.ToLower(strings.TrimSpace(value))
	case "dns-timeout":
		d, err := parseSeconds(value)
		if err != nil {
			return fmt.Errorf("dns-timeout: %v", err)
		}
		cfg.General.DNSTimeout = d
	case "geoip-db":
		cfg.General.GeoIPDB = value
	case "asn-db":
		cfg.General.ASNDB = value
	case "tun-enable":
		on, err := parseToggle(value)
		if err != nil {
			return fmt.Errorf("tun-enable: %w", err)
		}
		cfg.General.TUN.Enable = on
	case "tun-name":
		cfg.General.TUN.Name = strings.TrimSpace(value)
	case "tun-address":
		cfg.General.TUN.Address = strings.TrimSpace(value)
	case "tun-mtu":
		n, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil {
			return fmt.Errorf("tun-mtu: %q is not a number", value)
		}
		if n <= 0 {
			return fmt.Errorf("tun-mtu: %q must be positive; omit the key to use the default", value)
		}
		cfg.General.TUN.MTU = n
	case "tun-route":
		cfg.General.TUN.Routes = splitList(value)
	case "tun-udp-timeout":
		d, err := parseSeconds(value)
		if err != nil {
			return fmt.Errorf("tun-udp-timeout: %v", err)
		}
		if d <= 0 {
			return fmt.Errorf("tun-udp-timeout: must be positive; omit the key to use the default")
		}
		cfg.General.TUN.UDPTimeout = d
	case "system-proxy":
		on, err := parseToggle(value)
		if err != nil {
			return fmt.Errorf("system-proxy: %w", err)
		}
		cfg.General.SystemProxy = on
	case "system-proxy-bypass":
		cfg.General.SystemProxyBypass = splitList(value)
	default:
		return fmt.Errorf("unknown setting %q", key)
	}
	return nil
}

// parseToggle reads a boolean setting. Only unambiguous words are accepted: a
// typo must be a syntax error, not a silently disabled privileged device.
func parseToggle(value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "on", "true", "yes", "1":
		return true, nil
	case "off", "false", "no", "0":
		return false, nil
	default:
		return false, fmt.Errorf("%q is neither on nor off", value)
	}
}

// listenAddress normalises a listen setting: the word that switches a listener
// off becomes the empty address, everything else is kept as written so that
// Validate can report exactly what the user typed.
func listenAddress(value string) string {
	if strings.EqualFold(strings.TrimSpace(value), listenOff) {
		return ""
	}
	return value
}

// parseProxy splits "type, server, port, ..." and keeps the tail as raw args.
func parseProxy(name, value string, line int) Proxy {
	parts := splitList(value)
	p := Proxy{Name: strings.TrimSpace(name), Line: line, Args: parts}
	if len(parts) == 0 {
		return p
	}
	p.Type = strings.ToLower(parts[0])
	p.Args = parts[1:]
	if len(p.Args) > 0 {
		p.Server = p.Args[0]
	}
	if len(p.Args) > 1 {
		if port, err := strconv.Atoi(p.Args[1]); err == nil {
			p.Port = port
		}
	}
	return p
}

// parseGroup splits "type, member, ..., url=..., interval=..." into a group.
func parseGroup(name, value string, line int) (Group, error) {
	parts := splitList(value)
	g := Group{
		Name:      strings.TrimSpace(name),
		Line:      line,
		Interval:  defaultInterval,
		Timeout:   defaultTimeout,
		Tolerance: defaultTolerance,
	}
	if len(parts) == 0 {
		return g, fmt.Errorf("group %q has no type", name)
	}
	g.Type = GroupType(strings.ToLower(parts[0]))
	for _, part := range parts[1:] {
		key, val, isOption := strings.Cut(part, "=")
		if !isOption {
			g.Members = append(g.Members, part)
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "url":
			g.URL = strings.TrimSpace(val)
		case "interval":
			d, err := parseSeconds(val)
			if err != nil {
				return g, fmt.Errorf("group %q: interval: %v", name, err)
			}
			g.Interval = d
		case "timeout":
			d, err := parseSeconds(val)
			if err != nil {
				return g, fmt.Errorf("group %q: timeout: %v", name, err)
			}
			g.Timeout = d
		case "tolerance":
			d, err := parseSeconds(val)
			if err != nil {
				return g, fmt.Errorf("group %q: tolerance: %v", name, err)
			}
			g.Tolerance = d
		default:
			return g, fmt.Errorf("group %q: unknown option %q", name, strings.TrimSpace(key))
		}
	}
	return g, nil
}

// parseSubscription splits "url [interval=...]" into a subscription.
//
// The url comes first and is the only required part; everything after it is a
// whitespace separated option. A comma separator would have been ambiguous,
// because query strings carry commas of their own.
func parseSubscription(name, value string, line int) (Subscription, error) {
	sub := Subscription{
		Name:     strings.TrimSpace(name),
		Line:     line,
		Interval: defaultSubscriptionInterval,
	}
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return sub, fmt.Errorf("subscription %q has no url", name)
	}
	sub.URL = unquote(fields[0])
	for _, field := range fields[1:] {
		key, val, ok := strings.Cut(field, "=")
		if !ok {
			return sub, fmt.Errorf("subscription %q: option %q is not key=value", name, field)
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "interval":
			d, err := parseSeconds(val)
			if err != nil {
				return sub, fmt.Errorf("subscription %q: interval: %v", name, err)
			}
			sub.Interval = d
		default:
			return sub, fmt.Errorf("subscription %q: unknown option %q", name, strings.TrimSpace(key))
		}
	}
	return sub, nil
}

// parseSeconds accepts a plain number of seconds or a duration such as "5m".
func parseSeconds(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	if n, err := strconv.Atoi(s); err == nil {
		if n < 0 {
			return 0, fmt.Errorf("%q is negative", s)
		}
		return time.Duration(n) * time.Second, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("%q is neither seconds nor a duration", s)
	}
	return d, nil
}

// parseRuleEntry handles both a rule line and a "rule-set name = path"
// declaration inside [Rule].
func parseRuleEntry(cfg *Config, text string, line int, issues *Errors, seen map[string]int) {
	if isRuleSetDeclaration(text) {
		name, path, ok := strings.Cut(strings.TrimSpace(text[len(ruleSetKeyword):]), "=")
		name, path = strings.TrimSpace(name), strings.TrimSpace(path)
		if !ok || name == "" || path == "" {
			issues.add(line, "[Rule]", "expected rule-set <name> = <path>, got %q", text)
			return
		}
		if prev, dup := seen["ruleset/"+strings.ToLower(name)]; dup {
			issues.add(line, "[Rule]", "rule set %q is already declared on line %d", name, prev)
			return
		}
		seen["ruleset/"+strings.ToLower(name)] = line
		cfg.RuleSets = append(cfg.RuleSets, RuleSet{Name: name, Path: path, Line: line})
		return
	}
	rule, err := rules.ParseRule(text)
	if err != nil {
		issues.add(line, "[Rule]", "%v", err)
		return
	}
	rule.Source = "config"
	rule.Line = line
	cfg.Rules = append(cfg.Rules, rule)
}

// isRuleSetDeclaration reports whether a [Rule] line declares a rule set
// instead of holding a rule. The keyword must be followed by a space, so the
// RULE-SET rule type is not mistaken for it.
func isRuleSetDeclaration(text string) bool {
	lower := strings.ToLower(text)
	if !strings.HasPrefix(lower, ruleSetKeyword) {
		return false
	}
	rest := text[len(ruleSetKeyword):]
	return strings.HasPrefix(rest, " ") || strings.HasPrefix(rest, "\t")
}

// parseHost reads "name = address[, address]".
func parseHost(name, value string, line int) (HostEntry, error) {
	entry := HostEntry{Name: strings.ToLower(strings.TrimSpace(name)), Line: line}
	for _, part := range splitList(value) {
		ip := net.ParseIP(part)
		if ip == nil {
			return entry, fmt.Errorf("host %q: %q is not an IP address", name, part)
		}
		entry.Addrs = append(entry.Addrs, ip)
	}
	if len(entry.Addrs) == 0 {
		return entry, fmt.Errorf("host %q has no address", name)
	}
	return entry, nil
}

// splitKeyValue splits "key = value" at the first equals sign.
func splitKeyValue(text string) (key, value string, ok bool) {
	k, v, found := strings.Cut(text, "=")
	if !found {
		return "", "", false
	}
	key, value = strings.TrimSpace(k), unquote(strings.TrimSpace(v))
	if key == "" || value == "" {
		return "", "", false
	}
	return key, value, true
}

// splitList splits a comma separated value and trims every element.
func splitList(value string) []string {
	raw := strings.Split(value, ",")
	out := make([]string, 0, len(raw))
	for _, part := range raw {
		part = unquote(strings.TrimSpace(part))
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return out
}

// unquote removes one layer of matching double quotes.
func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// sourceLine is one line of the file with its 1-based number.
type sourceLine struct {
	number int
	text   string
}

// splitLines splits on any line ending and strips a UTF-8 byte order mark.
func splitLines(data []byte) []sourceLine {
	text := strings.TrimPrefix(string(data), "\ufeff")
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	raw := strings.Split(text, "\n")
	out := make([]sourceLine, 0, len(raw))
	for i, l := range raw {
		out = append(out, sourceLine{number: i + 1, text: l})
	}
	return out
}

// cleanLine trims a line and removes comments. Full-line comments start with
// #, ; or //. A trailing comment starts at a # or ; preceded by whitespace, so
// a value such as a path containing # survives; quote the value to keep a
// trailing comment sequence.
func cleanLine(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || strings.HasPrefix(s, "#") || strings.HasPrefix(s, ";") || strings.HasPrefix(s, "//") {
		return ""
	}
	inQuotes := false
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '"':
			inQuotes = !inQuotes
		case '#', ';':
			if !inQuotes && (s[i-1] == ' ' || s[i-1] == '\t') {
				return strings.TrimSpace(s[:i])
			}
		}
	}
	return s
}
