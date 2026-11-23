package sysproxy

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// The proxy setting of macOS is not one setting. It is one setting per network
// service (Wi-Fi, Ethernet, …), and each of those has five parts that matter
// here: the HTTP proxy, the secure web proxy, the SOCKS firewall proxy, the proxy
// auto-config script and its switch, and the bypass list. A machine can be
// reachable through any of its services, so a takeover covers every service that
// is enabled and records each one separately.
//
// Everything goes through /usr/sbin/networksetup. The preference file behind it
// is a system file with a private format; writing it directly would need root,
// would race the system daemon that owns it, and would make a restore depend on
// a layout the system may change. The command is the supported interface, and it
// is also what the user sees the change through: the network panel shows the
// same values afterwards.
//
// Two details of the tool shape this file.
//
// First, an address and its switch are written by two different commands, and
// the address command also switches the proxy on. The snapshot therefore keeps
// the three parts of one proxy as a single value ("on|127.0.0.1|7890"): an
// address can never be restored without saying whether that proxy was on, and a
// restore that wrote the address alone would switch a proxy on that the user had
// turned off.
//
// Second, writing may require an administrator's consent. The tool is run with
// the privileges of the process, never through sudo or a privileged helper, so
// on a machine that asks for authorisation the first write waits for a person.
// That wait is bounded (writeBudget, below) because the desktop shell that spawns
// this process gives it 15 seconds to answer: a wait that outlives that window
// would be killed in the middle of the dialog and the next attempt would put up
// a second one.

// networksetupCommand is the tool this backend reads and writes through. Tests
// replace the runner, not the name, so the command lines they assert are the
// ones the machine would see.
const networksetupCommand = "networksetup"

// The kinds of setting one network service has. They are the Field.Key values of
// a darwin snapshot and the words its error messages use.
const (
	keyAutoProxyState = "autoproxy-state"
	keyAutoProxyURL   = "autoproxy-url"
	keyAutoDiscovery  = "auto-discovery"
	keyWeb            = "web-proxy"
	keySecureWeb      = "secure-web-proxy"
	keySOCKS          = "socks-proxy"
	keyWebEnabled     = "web-proxy-enabled"
	keySecureWebState = "secure-web-proxy-enabled"
	keySOCKSEnabled   = "socks-proxy-enabled"
	keyBypass         = "bypass-domains"
)

// proxyKind is what one proxy key is read and written with. set is empty for the
// keys that only own the switch: a configuration with no SOCKS listener turns a
// SOCKS proxy off without touching the address that was there.
type proxyKind struct {
	get   string
	set   string
	state string
}

var proxyKinds = map[string]proxyKind{
	keyWeb:            {"-getwebproxy", "-setwebproxy", "-setwebproxystate"},
	keySecureWeb:      {"-getsecurewebproxy", "-setsecurewebproxy", "-setsecurewebproxystate"},
	keySOCKS:          {"-getsocksfirewallproxy", "-setsocksfirewallproxy", "-setsocksfirewallproxystate"},
	keyWebEnabled:     {"-getwebproxy", "", "-setwebproxystate"},
	keySecureWebState: {"-getsecurewebproxy", "", "-setsecurewebproxystate"},
	keySOCKSEnabled:   {"-getsocksfirewallproxy", "", "-setsocksfirewallproxystate"},
}

// writeBudget bounds one batch of writes.
//
// The desktop shell gives a freshly spawned core 15 seconds to answer before it
// kills the attempt and starts another one. A write that waits for an
// administrator must therefore end on its own before that verdict: the process
// exits with a logged reason and one dialog, instead of being killed mid-dialog
// and retried with a second one. Reads are not bounded; reading the setting
// needs no authorisation and cannot put a dialog up.
const writeBudget = 12 * time.Second

// errToolTimedOut is what a write that ran out of its budget reports.
var errToolTimedOut = errors.New("networksetup did not finish in time; macOS may be waiting for an administrator to allow the change")

// errToolCancelled is what a write that was interrupted by a shutdown reports.
var errToolCancelled = errors.New("networksetup was interrupted before it finished")

// networksetup is the proxy setting of a macOS desktop.
type networksetup struct {
	run    runner
	budget time.Duration
}

// newNetworkSetup returns a backend that writes through networksetup.
func newNetworkSetup(run runner) *networksetup {
	return &networksetup{run: run, budget: writeBudget}
}

// Name implements Backend.
func (n *networksetup) Name() string { return "networksetup" }

// proxyValue is one proxy of one network service. The tool reports and writes
// the three parts separately; the snapshot keeps them together because the
// address command always switches the proxy on.
type proxyValue struct {
	enabled bool
	host    string
	port    int
}

// String renders the value the snapshot stores: "on|127.0.0.1|7890".
func (v proxyValue) String() string {
	return stateWord(v.enabled) + "|" + v.host + "|" + strconv.Itoa(v.port)
}

// splitProxyValue parses what String produced.
func splitProxyValue(value string) (proxyValue, error) {
	parts := strings.Split(value, "|")
	if len(parts) != 3 {
		return proxyValue{}, fmt.Errorf("%q is not a proxy value", value)
	}
	enabled, err := parseOnOff(parts[0])
	if err != nil {
		return proxyValue{}, fmt.Errorf("%q: %w", value, err)
	}
	port := 0
	if parts[1] != "" && parts[2] != "" {
		if port, err = strconv.Atoi(parts[2]); err != nil {
			return proxyValue{}, fmt.Errorf("%q has no usable port", value)
		}
	}
	return proxyValue{enabled: enabled, host: parts[1], port: port}, nil
}

// stateWord is how a switch is written into the snapshot.
func stateWord(on bool) string {
	if on {
		return "on"
	}
	return "off"
}

// parseOnOff reads the several spellings the tool uses: the getters print "Yes"
// and "No" for a proxy, "On" and "Off" for the auto-config switch, and a number
// for the authenticated-proxy flag.
func parseOnOff(value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "yes", "on", "1", "true":
		return true, nil
	case "no", "off", "0", "false":
		return false, nil
	}
	return false, fmt.Errorf("%q is neither on nor off", value)
}

// serviceProxy is everything this backend reads from one network service.
//
// The three authenticated flags are read but never written. Whether a proxy asks
// for a password lives next to its address in a place this tool cannot read
// back, so a takeover that replaced an authenticated proxy would leave the user
// with an address and no credential. Plan refuses that case instead of taking it
// over; switching such a proxy off keeps its address and its credential, so that
// case is allowed.
type serviceProxy struct {
	pacOn         bool
	pacURL        string
	autoDiscovery bool
	web           proxyValue
	secure        proxyValue
	socks         proxyValue
	webAuth       bool
	secureAuth    bool
	socksAuth     bool
	bypass        []string
}

// Enabled implements Backend. Any service with any proxy switched on counts:
// the machine is pointed at something, whether that is a manual proxy or a
// configuration script.
func (n *networksetup) Enabled(ctx context.Context) (bool, error) {
	services, err := n.services(ctx)
	if err != nil {
		return false, err
	}
	for _, service := range services {
		current, err := n.readService(ctx, service)
		if err != nil {
			return false, err
		}
		if current.web.enabled || current.secure.enabled || current.socks.enabled ||
			current.pacOn || current.autoDiscovery {
			return true, nil
		}
	}
	return false, nil
}

// Plan implements Backend.
//
// The field order is the write order and it is part of the safety contract: the
// automatic configuration goes off first, because a client prefers a script over
// a manual proxy and would otherwise keep using it; the bypass list is written
// before any proxy is switched on, so the traffic that is meant to stay local
// never makes a detour through this program; and the switches travel with the
// address they belong to, because the tool has no command that writes one
// without the other. A restore walks the list backwards, so the proxies go off
// before the bypass list and the script are put back.
func (n *networksetup) Plan(ctx context.Context, s Settings) (Snapshot, error) {
	if err := s.Validate(); err != nil {
		return Snapshot{}, err
	}
	services, err := n.services(ctx)
	if err != nil {
		return Snapshot{}, err
	}

	httpHost, httpPort := splitListen(s.HTTP)
	socksHost, socksPort := splitListen(s.SOCKS5)
	web := proxyValue{enabled: true, host: httpHost, port: httpPort}
	socks := proxyValue{enabled: true, host: socksHost, port: socksPort}

	fields := make([]Field, 0, len(services)*7)
	for _, service := range services {
		current, err := n.readService(ctx, service)
		if err != nil {
			return Snapshot{}, err
		}
		fields = append(fields,
			Field{Service: service, Key: keyAutoProxyState, Before: stateWord(current.pacOn), Written: "off", Present: true},
			// The address of the script is recorded but never written: the tool
			// can only set it together with switching it on, and the takeover
			// only needs the switch. Keeping it in the record tells whoever
			// reads the file what was there.
			Field{Service: service, Key: keyAutoProxyURL, Before: current.pacURL, Written: current.pacURL, Present: true, Observed: true},
			Field{Service: service, Key: keyAutoDiscovery, Before: stateWord(current.autoDiscovery), Written: "off", Present: true},
			Field{
				Service: service,
				Key:     keyBypass,
				Before:  strings.Join(current.bypass, ","),
				Written: strings.Join(s.BypassList(), ","),
				Present: true,
			},
		)
		if s.HTTP != "" {
			// An authenticated proxy cannot be put back: the tool reports that
			// it asks for a password but never the password itself. Refusing is
			// better than replacing it and handing the user back an address
			// that rejects every request.
			if current.webAuth || current.secureAuth {
				return Snapshot{}, fmt.Errorf("%s: the web proxy is authenticated, and this build cannot read its credential back; turn that proxy off before enabling the system proxy", service)
			}
			// The secure web proxy is the HTTP listener: it answers CONNECT,
			// which is what a client sends to the proxy of an https URL.
			fields = append(fields,
				Field{Service: service, Key: keyWeb, Before: current.web.String(), Written: web.String(), Present: true},
				Field{Service: service, Key: keySecureWeb, Before: current.secure.String(), Written: web.String(), Present: true},
			)
		} else {
			fields = append(fields,
				Field{Service: service, Key: keyWebEnabled, Before: stateWord(current.web.enabled), Written: "off", Present: true},
				Field{Service: service, Key: keySecureWebState, Before: stateWord(current.secure.enabled), Written: "off", Present: true},
			)
		}
		if s.SOCKS5 != "" {
			if current.socksAuth {
				return Snapshot{}, fmt.Errorf("%s: the SOCKS proxy is authenticated, and this build cannot read its credential back; turn that proxy off before enabling the system proxy", service)
			}
			fields = append(fields, Field{Service: service, Key: keySOCKS, Before: current.socks.String(), Written: socks.String(), Present: true})
		} else {
			fields = append(fields, Field{Service: service, Key: keySOCKSEnabled, Before: stateWord(current.socks.enabled), Written: "off", Present: true})
		}
	}
	return Snapshot{Fields: fields}, nil
}

// Commit implements Backend.
func (n *networksetup) Commit(ctx context.Context, snap Snapshot) error {
	ctx, cancel := context.WithTimeout(ctx, n.budgetOrDefault())
	defer cancel()
	for i, f := range snap.Fields {
		if f.Observed {
			continue
		}
		applied, err := n.applyField(ctx, f, f.Written)
		if err != nil {
			return n.rollback(ctx, snap, i, applied, err)
		}
	}
	return nil
}

// Restore implements Backend.
func (n *networksetup) Restore(ctx context.Context, snap Snapshot) (RestoreResult, error) {
	ctx, cancel := context.WithTimeout(ctx, n.budgetOrDefault())
	defer cancel()
	return restoreFields(snap.Fields,
		func(f Field) (string, bool, error) {
			value, err := n.readField(ctx, f)
			return value, true, err
		},
		func(f Field, current string) bool { return current == f.Written },
		func(f Field) error {
			_, err := n.applyField(ctx, f, f.Before)
			return err
		},
		func(f Field) error {
			return fmt.Errorf("%s has no value to delete", fieldName(f))
		},
	)
}

// Apply is the one-shot form of Plan plus Commit, kept for callers that do not
// need the takeover to be recorded and restored later.
func (n *networksetup) Apply(ctx context.Context, s Settings) error {
	snap, err := n.Plan(ctx, s)
	if err != nil {
		return err
	}
	return n.Commit(ctx, snap)
}

// Clear implements Backend.
//
// Only the three switches are turned off: a configuration script and the bypass
// list never point at a listener of this program, and an address left behind
// with its proxy switched off is harmless. Every service is attempted even
// after a failure, because clearing what can be cleared is the whole point of
// this fallback.
func (n *networksetup) Clear(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, n.budgetOrDefault())
	defer cancel()
	services, err := n.services(ctx)
	if err != nil {
		return err
	}
	var problems []error
	for _, service := range services {
		for _, flag := range []string{"-setwebproxystate", "-setsecurewebproxystate", "-setsocksfirewallproxystate"} {
			if err := n.mutate(ctx, flag, service, "off"); err != nil {
				problems = append(problems, err)
			}
		}
	}
	return errors.Join(problems...)
}

// rollback puts back only the fields this takeover actually wrote, in reverse
// order, so the switches that turn a proxy on go back before the addresses do.
// failedAt is the field whose write failed and applied is how many tool commands
// of that field took effect: a group that only got its address is ours only if
// the value read back still matches what this program wrote. It reports
// ErrRollbackIncomplete when a field it wrote could not be put back: part of
// what this program wrote is then still in force, and the controller has to
// keep the takeover record for the next start.
func (n *networksetup) rollback(ctx context.Context, snap Snapshot, failedAt, applied int, cause error) error {
	last := failedAt - 1
	if applied > 0 {
		last = failedAt
	}
	total, problems := 0, []error(nil)
	for i := last; i >= 0; i-- {
		f := snap.Fields[i]
		if f.Observed {
			continue
		}
		total++
		current, err := n.readField(ctx, f)
		if err != nil {
			problems = append(problems, fmt.Errorf("read %s (expected %q): %w", fieldName(f), f.Written, err))
			continue
		}
		if current != f.Written {
			if i == failedAt {
				problems = append(problems, fmt.Errorf("%s was changed after a partial write (current %q, written %q)", fieldName(f), current, f.Written))
			}
			continue
		}
		if _, err := n.applyField(ctx, f, f.Before); err != nil {
			problems = append(problems, fmt.Errorf("restore %s: %w", fieldName(f), err))
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("%w: %w (%d of %d settings could not be put back: %v)",
			cause, ErrRollbackIncomplete, len(problems), total, errors.Join(problems...))
	}
	return fmt.Errorf("%w (the previous settings were restored)", cause)
}

// services lists the network services a takeover applies to: every service the
// system reports as enabled. The tool marks a disabled service with an asterisk
// and prints a sentence about that convention first.
func (n *networksetup) services(ctx context.Context) ([]string, error) {
	out, err := n.invoke(ctx, "-listallnetworkservices")
	if err != nil {
		return nil, err
	}
	var services []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "":
			continue
		case strings.HasPrefix(line, "An asterisk"):
			continue
		case strings.HasPrefix(line, "*"):
			// A disabled service is not carrying traffic and is not ours.
			continue
		}
		services = append(services, line)
	}
	if len(services) == 0 {
		return nil, fmt.Errorf("%s -listallnetworkservices: no enabled network service was found", networksetupCommand)
	}
	return services, nil
}

// readService reads every part of one service.
func (n *networksetup) readService(ctx context.Context, service string) (serviceProxy, error) {
	var current serviceProxy
	pacOn, url, err := n.readPAC(ctx, service)
	if err != nil {
		return current, err
	}
	current.pacOn, current.pacURL = pacOn, url
	if current.autoDiscovery, err = n.readDiscovery(ctx, service); err != nil {
		return current, err
	}
	if current.web, current.webAuth, err = n.readProxy(ctx, service, "-getwebproxy"); err != nil {
		return current, err
	}
	if current.secure, current.secureAuth, err = n.readProxy(ctx, service, "-getsecurewebproxy"); err != nil {
		return current, err
	}
	if current.socks, current.socksAuth, err = n.readProxy(ctx, service, "-getsocksfirewallproxy"); err != nil {
		return current, err
	}
	if current.bypass, err = n.readBypass(ctx, service); err != nil {
		return current, err
	}
	return current, nil
}

// readField reads one field back, which is how a restore learns whether the
// value it wrote is still the value in force.
func (n *networksetup) readField(ctx context.Context, f Field) (string, error) {
	switch f.Key {
	case keyAutoProxyState:
		on, _, err := n.readPAC(ctx, f.Service)
		if err != nil {
			return "", err
		}
		return stateWord(on), nil
	case keyAutoProxyURL:
		_, url, err := n.readPAC(ctx, f.Service)
		return url, err
	case keyAutoDiscovery:
		on, err := n.readDiscovery(ctx, f.Service)
		if err != nil {
			return "", err
		}
		return stateWord(on), nil
	case keyBypass:
		domains, err := n.readBypass(ctx, f.Service)
		if err != nil {
			return "", err
		}
		return strings.Join(domains, ","), nil
	}
	kind, ok := proxyKinds[f.Key]
	if !ok {
		return "", fmt.Errorf("unknown setting %q", f.Key)
	}
	current, _, err := n.readProxy(ctx, f.Service, kind.get)
	if err != nil {
		return "", err
	}
	if kind.set == "" {
		return stateWord(current.enabled), nil
	}
	return current.String(), nil
}

// applyField writes value into one field and reports how many tool commands
// took effect. An address is only written when the value carries one: a restore
// of a service that had no address leaves the one this program wrote behind
// with the proxy switched off, which is how the registry backend treats the
// same case.
func (n *networksetup) applyField(ctx context.Context, f Field, value string) (int, error) {
	applied := 0
	if kind, ok := proxyKinds[f.Key]; ok {
		if kind.set == "" {
			state, err := switchArg(f, value)
			if err != nil {
				return applied, err
			}
			if err := n.mutate(ctx, kind.state, f.Service, state); err != nil {
				return applied, err
			}
			return 1, nil
		}
		proxy, err := splitProxyValue(value)
		if err != nil {
			return applied, fmt.Errorf("write %s: %w", fieldName(f), err)
		}
		if proxy.host != "" {
			if err := n.mutate(ctx, kind.set, f.Service, proxy.host, strconv.Itoa(proxy.port)); err != nil {
				return applied, err
			}
			applied++
		}
		if err := n.mutate(ctx, kind.state, f.Service, stateWord(proxy.enabled)); err != nil {
			return applied, err
		}
		return applied + 1, nil
	}
	switch f.Key {
	case keyAutoProxyState:
		state, err := switchArg(f, value)
		if err != nil {
			return applied, err
		}
		if err := n.mutate(ctx, "-setautoproxystate", f.Service, state); err != nil {
			return applied, err
		}
		return 1, nil
	case keyAutoDiscovery:
		state, err := switchArg(f, value)
		if err != nil {
			return applied, err
		}
		if err := n.mutate(ctx, "-setproxyautodiscovery", f.Service, state); err != nil {
			return applied, err
		}
		return 1, nil
	case keyBypass:
		if err := n.writeBypass(ctx, f.Service, value); err != nil {
			return applied, err
		}
		return 1, nil
	}
	return applied, fmt.Errorf("unknown setting %q", f.Key)
}

// switchArg normalises a switch out of a snapshot. The value is written as the
// tool spells it, and a record that says something else is refused rather than
// handed to the tool.
func switchArg(f Field, value string) (string, error) {
	on, err := parseOnOff(value)
	if err != nil {
		return "", fmt.Errorf("write %s: %w", fieldName(f), err)
	}
	return stateWord(on), nil
}

// writeBypass replaces the bypass list. The tool clears a list with the word
// Empty rather than with no arguments at all.
func (n *networksetup) writeBypass(ctx context.Context, service, value string) error {
	domains := splitList(value)
	args := []string{"-setproxybypassdomains", service}
	if len(domains) == 0 {
		args = append(args, "Empty")
	} else {
		args = append(args, domains...)
	}
	return n.mutate(ctx, args...)
}

// budgetOrDefault is how long one batch of writes may take. The field exists so
// a test can shorten it; a backend built without it still gets the real budget
// rather than a context that has already expired.
func (n *networksetup) budgetOrDefault() time.Duration {
	if n.budget > 0 {
		return n.budget
	}
	return writeBudget
}

// mutate runs one command that changes the setting.
func (n *networksetup) mutate(ctx context.Context, args ...string) error {
	_, err := n.invoke(ctx, args...)
	return err
}

// invoke runs the tool and turns an expired budget into a reason a user can act
// on. A killed process reports "signal: killed", which on its own says nothing
// about the dialog that was on screen.
func (n *networksetup) invoke(ctx context.Context, args ...string) (string, error) {
	out, err := n.run(ctx, networksetupCommand, args...)
	if err == nil {
		return out, nil
	}
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return out, fmt.Errorf("%w (%v)", errToolTimedOut, err)
	case errors.Is(ctx.Err(), context.Canceled):
		return out, fmt.Errorf("%w (%v)", errToolCancelled, err)
	}
	return out, err
}

// readPAC reads the proxy auto-config script: whether it is on and where it
// points.
func (n *networksetup) readPAC(ctx context.Context, service string) (bool, string, error) {
	out, err := n.invoke(ctx, "-getautoproxyurl", service)
	if err != nil {
		return false, "", err
	}
	answer := parseAnswer(out)
	raw, ok := answer["Enabled"]
	if !ok {
		return false, "", fmt.Errorf("%s -getautoproxyurl %s: the answer has no Enabled line", networksetupCommand, service)
	}
	on, err := parseOnOff(raw)
	if err != nil {
		return false, "", fmt.Errorf("%s -getautoproxyurl %s: %w", networksetupCommand, service, err)
	}
	return on, answer["URL"], nil
}

// readDiscovery reads the automatic proxy discovery switch.
func (n *networksetup) readDiscovery(ctx context.Context, service string) (bool, error) {
	out, err := n.invoke(ctx, "-getproxyautodiscovery", service)
	if err != nil {
		return false, err
	}
	for label, value := range parseAnswer(out) {
		if strings.Contains(strings.ToLower(label), "discovery") {
			on, err := parseOnOff(value)
			if err != nil {
				return false, fmt.Errorf("%s -getproxyautodiscovery %s: %w", networksetupCommand, service, err)
			}
			return on, nil
		}
	}
	return false, fmt.Errorf("%s -getproxyautodiscovery %s: the answer has no discovery line", networksetupCommand, service)
}

// readProxy reads one proxy: whether it is on, where it points, and whether it
// asks for a password.
func (n *networksetup) readProxy(ctx context.Context, service, flag string) (proxyValue, bool, error) {
	out, err := n.invoke(ctx, flag, service)
	if err != nil {
		return proxyValue{}, false, err
	}
	answer := parseAnswer(out)
	raw, ok := answer["Enabled"]
	if !ok {
		return proxyValue{}, false, fmt.Errorf("%s %s %s: the answer has no Enabled line", networksetupCommand, flag, service)
	}
	on, err := parseOnOff(raw)
	if err != nil {
		return proxyValue{}, false, fmt.Errorf("%s %s %s: %w", networksetupCommand, flag, service, err)
	}
	port := 0
	if text := answer["Port"]; text != "" {
		if port, err = strconv.Atoi(text); err != nil {
			return proxyValue{}, false, fmt.Errorf("%s %s %s: Port is %q, which is not a number", networksetupCommand, flag, service, text)
		}
	}
	// The line is absent on a system that does not report it; no line means no
	// credential to lose.
	auth := false
	if text := answer["Authenticated Proxy Enabled"]; text != "" {
		if auth, err = parseOnOff(text); err != nil {
			return proxyValue{}, false, fmt.Errorf("%s %s %s: Authenticated Proxy Enabled is %q: %w", networksetupCommand, flag, service, text, err)
		}
	}
	return proxyValue{enabled: on, host: answer["Server"], port: port}, auth, nil
}

// readBypass reads the bypass list. An empty list is a sentence rather than a
// line with a label, so the two shapes are told apart instead of both being read
// as "empty": an answer this backend does not understand has to stop the
// takeover, because a wrong Before value cannot be restored.
func (n *networksetup) readBypass(ctx context.Context, service string) ([]string, error) {
	out, err := n.invoke(ctx, "-getproxybypassdomains", service)
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(out, "\n") {
		label, value, ok := strings.Cut(line, ":")
		if !ok || !strings.HasPrefix(strings.ToLower(strings.TrimSpace(label)), "bypass domain") {
			continue
		}
		return splitList(value), nil
	}
	if strings.Contains(out, "There aren't any") {
		return nil, nil
	}
	return nil, fmt.Errorf("%s -getproxybypassdomains %s: the answer has no bypass domains line: %q",
		networksetupCommand, service, strings.TrimSpace(out))
}

// parseAnswer turns the "Label: value" lines of a getter into a map. A value
// keeps every colon after the first one, so an address or a URL survives.
func parseAnswer(out string) map[string]string {
	answer := make(map[string]string, 4)
	for _, line := range strings.Split(out, "\n") {
		label, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		answer[strings.TrimSpace(label)] = strings.TrimSpace(value)
	}
	return answer
}

// splitList splits a comma separated list and drops empty entries.
func splitList(value string) []string {
	var out []string
	for _, entry := range strings.Split(value, ",") {
		if entry = strings.TrimSpace(entry); entry != "" {
			out = append(out, entry)
		}
	}
	return out
}
