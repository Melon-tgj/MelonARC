package sysproxy

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeNetworkSetup is a networksetup that keeps one proxy setting per network
// service in memory and answers from it. The answers are the text the real tool
// prints, so the backend's parsing is exercised rather than bypassed, and a
// write is visible to the read that follows it.
type fakeNetworkSetup struct {
	// serviceLines is what -listallnetworkservices prints, header line
	// included; an asterisk marks a disabled service.
	serviceLines []string
	state        map[string]*serviceProxy
	// calls is every command line, in order.
	calls []string
	// failFrom makes every mutating call fail from the nth one on, counted
	// from 1. Zero fails nothing.
	failFrom int
	// failAt makes only the nth mutating call fail, so the rollback still has a
	// working tool. Zero fails nothing.
	failAt int
	// mutations counts the mutating calls seen, for failFrom and failAt.
	mutations int
	// block makes a mutating call wait for its context to end: the
	// authorisation dialog nobody answers.
	block bool
}

func newFakeNetworkSetup() *fakeNetworkSetup {
	return &fakeNetworkSetup{
		serviceLines: []string{
			"An asterisk (*) denotes that a network service is disabled.",
			"Wi-Fi",
			"*Bridge",
			"Ethernet",
		},
		state: map[string]*serviceProxy{
			"Wi-Fi": {
				pacOn:  true,
				pacURL: "http://config.corp/proxy.pac",
				web:    proxyValue{enabled: true, host: "proxy.corp", port: 8080},
				bypass: []string{"corp.local", "*.internal"},
			},
			"Ethernet": {},
		},
	}
}

func (f *fakeNetworkSetup) service(name string) (*serviceProxy, error) {
	current, ok := f.state[name]
	if !ok {
		return nil, fmt.Errorf("unknown network service %q", name)
	}
	return current, nil
}

func (f *fakeNetworkSetup) run(ctx context.Context, name string, args ...string) (string, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	if len(args) == 0 {
		return "", errors.New("no arguments")
	}
	if !strings.HasPrefix(args[0], "-set") {
		return f.read(args)
	}
	f.mutations++
	if f.failFrom > 0 && f.mutations >= f.failFrom {
		return "", errors.New("the setting was refused")
	}
	if f.failAt > 0 {
		f.failAt--
		if f.failAt == 0 {
			return "", errors.New("the setting was refused")
		}
	}
	if f.block {
		<-ctx.Done()
		return "", ctx.Err()
	}
	return "", f.write(args)
}

// read answers one getter the way the tool does.
func (f *fakeNetworkSetup) read(args []string) (string, error) {
	switch args[0] {
	case "-listallnetworkservices":
		return strings.Join(f.serviceLines, "\n") + "\n", nil
	case "-getautoproxyurl":
		current, err := f.service(args[1])
		if err != nil {
			return "", err
		}
		enabled := "No"
		if current.pacOn {
			enabled = "Yes"
		}
		return "URL: " + current.pacURL + "\nEnabled: " + enabled + "\n", nil
	case "-getproxyautodiscovery":
		current, err := f.service(args[1])
		if err != nil {
			return "", err
		}
		return "Auto Proxy Discovery: " + switchWord(current.autoDiscovery) + "\n", nil
	case "-getwebproxy", "-getsecurewebproxy", "-getsocksfirewallproxy":
		current, err := f.service(args[1])
		if err != nil {
			return "", err
		}
		proxy, auth := current.web, current.webAuth
		switch args[0] {
		case "-getsecurewebproxy":
			proxy, auth = current.secure, current.secureAuth
		case "-getsocksfirewallproxy":
			proxy, auth = current.socks, current.socksAuth
		}
		enabled := "No"
		if proxy.enabled {
			enabled = "Yes"
		}
		authenticated := "0"
		if auth {
			authenticated = "1"
		}
		return "Enabled: " + enabled + "\nServer: " + proxy.host + "\nPort: " + strconv.Itoa(proxy.port) +
			"\nAuthenticated Proxy Enabled: " + authenticated + "\n", nil
	case "-getproxybypassdomains":
		current, err := f.service(args[1])
		if err != nil {
			return "", err
		}
		if len(current.bypass) == 0 {
			return "There aren't any bypass domains set on \"" + args[1] + "\".\n", nil
		}
		return "Bypass Domain(s): " + strings.Join(current.bypass, ", ") + "\n", nil
	}
	return "", fmt.Errorf("unsupported getter %q", args[0])
}

// write applies one setter to the in-memory setting.
func (f *fakeNetworkSetup) write(args []string) error {
	if len(args) < 3 {
		return fmt.Errorf("%q needs a service and a value", args[0])
	}
	current, err := f.service(args[1])
	if err != nil {
		return err
	}
	switch args[0] {
	case "-setautoproxystate":
		current.pacOn = args[2] == "on"
	case "-setproxyautodiscovery":
		current.autoDiscovery = args[2] == "on"
	case "-setwebproxy", "-setsecurewebproxy", "-setsocksfirewallproxy":
		if len(args) != 4 {
			return fmt.Errorf("%q needs a host and a port", args[0])
		}
		port, err := strconv.Atoi(args[3])
		if err != nil {
			return fmt.Errorf("%q has no usable port: %w", args[0], err)
		}
		proxy := proxyValue{enabled: true, host: args[2], port: port}
		switch args[0] {
		case "-setwebproxy":
			current.web = proxy
		case "-setsecurewebproxy":
			current.secure = proxy
		default:
			current.socks = proxy
		}
	case "-setwebproxystate", "-setsecurewebproxystate", "-setsocksfirewallproxystate":
		on := args[2] == "on"
		switch args[0] {
		case "-setwebproxystate":
			current.web.enabled = on
		case "-setsecurewebproxystate":
			current.secure.enabled = on
		default:
			current.socks.enabled = on
		}
	case "-setproxybypassdomains":
		if args[2] == "Empty" {
			current.bypass = nil
			break
		}
		current.bypass = append([]string{}, args[2:]...)
	default:
		return fmt.Errorf("unsupported setter %q", args[0])
	}
	return nil
}

// switchWord spells a switch the way the discovery getter does.
func switchWord(on bool) string {
	if on {
		return "On"
	}
	return "Off"
}

// writesOf filters the recorded calls down to the ones that changed something.
func (f *fakeNetworkSetup) writesOf(service string) []string {
	var out []string
	for _, call := range f.calls {
		if strings.HasPrefix(call, "networksetup -set") && strings.Contains(call, " "+service+" ") {
			out = append(out, call)
		}
	}
	return out
}

// TestNetworkSetupApplyTakesOverEveryEnabledService checks what a takeover
// writes: every enabled service, the automatic configuration switched off first,
// the three addresses, the bypass list, and the switches last.
func TestNetworkSetupApplyTakesOverEveryEnabledService(t *testing.T) {
	fake := newFakeNetworkSetup()
	backend := newNetworkSetup(fake.run)

	err := backend.Apply(context.Background(), Settings{
		HTTP:   "127.0.0.1:7890",
		SOCKS5: "127.0.0.1:7891",
		Bypass: []string{"*.internal"},
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	want := []string{
		"networksetup -setautoproxystate Wi-Fi off",
		"networksetup -setproxyautodiscovery Wi-Fi off",
		"networksetup -setproxybypassdomains Wi-Fi localhost 127.0.0.1 ::1 *.internal",
		"networksetup -setwebproxy Wi-Fi 127.0.0.1 7890",
		"networksetup -setwebproxystate Wi-Fi on",
		"networksetup -setsecurewebproxy Wi-Fi 127.0.0.1 7890",
		"networksetup -setsecurewebproxystate Wi-Fi on",
		"networksetup -setsocksfirewallproxy Wi-Fi 127.0.0.1 7891",
		"networksetup -setsocksfirewallproxystate Wi-Fi on",
	}
	got := fake.writesOf("Wi-Fi")
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("writes for Wi-Fi:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	// The second service is taken over too, and the disabled one is not.
	if writes := fake.writesOf("Ethernet"); len(writes) != len(want) {
		t.Errorf("Ethernet got %d writes, want %d:\n%s", len(writes), len(want), strings.Join(writes, "\n"))
	}
	for _, call := range fake.calls {
		if strings.Contains(call, "Bridge") {
			t.Errorf("a disabled service was touched: %q", call)
		}
	}

	// The machine now points at the listeners, and the script that was there is
	// off rather than competing with them.
	state := fake.state["Wi-Fi"]
	if !state.web.enabled || state.web.host != "127.0.0.1" || state.web.port != 7890 {
		t.Errorf("web proxy = %+v", state.web)
	}
	if !state.socks.enabled || state.socks.port != 7891 {
		t.Errorf("socks proxy = %+v", state.socks)
	}
	if state.pacOn {
		t.Error("the proxy auto-config script is still on")
	}
	if strings.Join(state.bypass, ",") != "localhost,127.0.0.1,::1,*.internal" {
		t.Errorf("bypass = %v", state.bypass)
	}
}

// TestNetworkSetupPlanRecordsWhatWasThere pins the snapshot: one field per part
// of the setting, per service, with the value in force before the takeover and
// the value this program will write.
func TestNetworkSetupPlanRecordsWhatWasThere(t *testing.T) {
	fake := newFakeNetworkSetup()
	snap, err := newNetworkSetup(fake.run).Plan(context.Background(), Settings{
		HTTP:   "127.0.0.1:7890",
		SOCKS5: "127.0.0.1:7891",
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}

	var wifi []Field
	for _, f := range snap.Fields {
		if f.Service == "Wi-Fi" {
			wifi = append(wifi, f)
		}
	}
	wantKeys := []string{keyAutoProxyState, keyAutoProxyURL, keyAutoDiscovery, keyBypass, keyWeb, keySecureWeb, keySOCKS}
	if len(wifi) != len(wantKeys) {
		t.Fatalf("Wi-Fi fields = %d, want %d: %+v", len(wifi), len(wantKeys), wifi)
	}
	for i, key := range wantKeys {
		if wifi[i].Key != key {
			t.Fatalf("field %d is %q, want %q (the write order is the contract)", i, wifi[i].Key, key)
		}
	}
	before := map[string]string{
		keyAutoProxyState: "on",
		keyAutoProxyURL:   "http://config.corp/proxy.pac",
		keyAutoDiscovery:  "off",
		keyWeb:            "on|proxy.corp|8080",
		keySecureWeb:      "off||0",
		keySOCKS:          "off||0",
		keyBypass:         "corp.local,*.internal",
	}
	written := map[string]string{
		keyAutoProxyState: "off",
		keyAutoDiscovery:  "off",
		keyWeb:            "on|127.0.0.1|7890",
		keySecureWeb:      "on|127.0.0.1|7890",
		keySOCKS:          "on|127.0.0.1|7891",
		keyBypass:         "localhost,127.0.0.1,::1",
	}
	for _, f := range wifi {
		if f.Before != before[f.Key] {
			t.Errorf("%s before = %q, want %q", f.Key, f.Before, before[f.Key])
		}
		if want, ok := written[f.Key]; ok && f.Written != want {
			t.Errorf("%s written = %q, want %q", f.Key, f.Written, want)
		}
	}
	if !wifi[1].Observed {
		t.Error("the proxy auto-config address is not marked as recorded only")
	}
	// Ethernet had nothing configured: the plan still records the absence of a
	// proxy as a value, so a restore knows what to put back.
	for _, f := range snap.Fields {
		if f.Service == "Ethernet" && f.Key == keyWeb && f.Before != "off||0" {
			t.Errorf("an untouched service recorded %q", f.Before)
		}
	}
}

// TestNetworkSetupApplyTurnsOffTheProxyItWasNotGiven checks a configuration with
// one listener: the other proxy is switched off, and its address is left alone.
func TestNetworkSetupApplyTurnsOffTheProxyItWasNotGiven(t *testing.T) {
	fake := newFakeNetworkSetup()
	fake.state["Wi-Fi"].socks = proxyValue{enabled: true, host: "socks.corp", port: 1080}

	if err := newNetworkSetup(fake.run).Apply(context.Background(), Settings{HTTP: "127.0.0.1:7890"}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	got := strings.Join(fake.writesOf("Wi-Fi"), "\n")
	if !strings.Contains(got, "networksetup -setsocksfirewallproxystate Wi-Fi off") {
		t.Errorf("the socks proxy was left on:\n%s", got)
	}
	if strings.Contains(got, "-setsocksfirewallproxy Wi-Fi") {
		t.Errorf("an address was written for a proxy that is not configured:\n%s", got)
	}
	if state := fake.state["Wi-Fi"].socks; state.enabled || state.host != "socks.corp" || state.port != 1080 {
		t.Errorf("the socks address was not kept: %+v", state)
	}
}

// TestNetworkSetupRollbackPutsBackWhatItWrote is the property the package
// exists for: a write that fails in the middle leaves the machine as it was.
func TestNetworkSetupRollbackPutsBackWhatItWrote(t *testing.T) {
	fake := newFakeNetworkSetup()
	fake.failAt = 5 // the first four writes succeed, the fifth is refused
	backend := newNetworkSetup(fake.run)

	err := backend.Apply(context.Background(), Settings{HTTP: "127.0.0.1:7890", SOCKS5: "127.0.0.1:7891"})
	if err == nil {
		t.Fatal("Apply succeeded although a write failed")
	}
	if !strings.Contains(err.Error(), "previous settings were restored") {
		t.Errorf("the error does not say the setting was put back: %v", err)
	}
	if errors.Is(err, ErrRollbackIncomplete) {
		t.Errorf("a rollback that worked was reported as incomplete: %v", err)
	}

	state := fake.state["Wi-Fi"]
	if state.web.enabled != true || state.web.host != "proxy.corp" || state.web.port != 8080 {
		t.Errorf("the web proxy was not put back: %+v", state.web)
	}
	if !state.pacOn || state.pacURL != "http://config.corp/proxy.pac" {
		t.Errorf("the proxy auto-config script was not put back: on=%v url=%q", state.pacOn, state.pacURL)
	}
	if strings.Join(state.bypass, ",") != "corp.local,*.internal" {
		t.Errorf("the bypass list was not put back: %v", state.bypass)
	}
	if state.secure.enabled || state.socks.enabled {
		t.Errorf("a proxy that was off is on: secure=%+v socks=%+v", state.secure, state.socks)
	}
}

// TestNetworkSetupReportsAnIncompleteRollback is the case that decides whether
// the next start can still put the machine back: the write failed and the undo
// failed too, so the error has to say so.
func TestNetworkSetupReportsAnIncompleteRollback(t *testing.T) {
	fake := newFakeNetworkSetup()
	fake.failFrom = 2
	err := newNetworkSetup(fake.run).Apply(context.Background(), Settings{HTTP: "127.0.0.1:7890"})
	if err == nil {
		t.Fatal("Apply succeeded although every write was refused")
	}
	if !errors.Is(err, ErrRollbackIncomplete) {
		t.Errorf("an undone-nothing rollback was not reported as incomplete: %v", err)
	}
	if !strings.Contains(err.Error(), "could not be put back") {
		t.Errorf("the error does not say what is left behind: %v", err)
	}
}

// TestNetworkSetupRestoreKeepsWhatTheUserChanged is the ownership rule: a value
// the user edited while the daemon ran is theirs, not ours to overwrite.
func TestNetworkSetupRestoreKeepsWhatTheUserChanged(t *testing.T) {
	fake := newFakeNetworkSetup()
	path := filepath.Join(t.TempDir(), SnapshotFile)
	c := WithBackend(newNetworkSetup(fake.run), nil, path)
	if err := c.Enable(context.Background(), Settings{HTTP: "127.0.0.1:7890", SOCKS5: "127.0.0.1:7891"}); err != nil {
		t.Fatalf("Enable: %v", err)
	}

	// The user moves the SOCKS proxy to another server while the daemon runs.
	fake.state["Wi-Fi"].socks = proxyValue{enabled: true, host: "user.proxy", port: 1080}
	fake.calls = nil
	if err := c.Release(context.Background()); err != nil {
		t.Fatalf("Release: %v", err)
	}

	for _, call := range fake.calls {
		if strings.HasPrefix(call, "networksetup -setsocksfirewallproxy Wi-Fi") {
			t.Errorf("the proxy the user changed was overwritten: %q", call)
		}
	}
	if state := fake.state["Wi-Fi"].socks; state.host != "user.proxy" || state.port != 1080 {
		t.Errorf("the user's socks proxy was replaced: %+v", state)
	}
	if state := fake.state["Wi-Fi"].web; state.host != "proxy.corp" || state.port != 8080 || !state.enabled {
		t.Errorf("a proxy the user did not change was not put back: %+v", state)
	}
}

// TestNetworkSetupRestoreLeavesAnAddressItCannotUnwrite documents the one
// deliberate asymmetry with the gsettings backend: an address that was empty
// before the takeover is not cleared, because the tool has no command that
// clears one. The proxy is switched off, which is the state that matters.
func TestNetworkSetupRestoreLeavesAnAddressItCannotUnwrite(t *testing.T) {
	fake := newFakeNetworkSetup()
	c := WithBackend(newNetworkSetup(fake.run), nil, "")
	if err := c.Enable(context.Background(), Settings{HTTP: "127.0.0.1:7890", SOCKS5: "127.0.0.1:7891"}); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	fake.calls = nil
	if err := c.Release(context.Background()); err != nil {
		t.Fatalf("Release: %v", err)
	}

	if !containsCall(fake.calls, "networksetup -setsecurewebproxystate Wi-Fi off") {
		t.Errorf("the secure proxy was not switched off:\n%s", strings.Join(fake.calls, "\n"))
	}
	state := fake.state["Wi-Fi"].secure
	if state.enabled {
		t.Error("the secure proxy is on after the release")
	}
	if state.host != "127.0.0.1" || state.port != 7890 {
		t.Errorf("the address this program wrote was expected to stay, got %+v", state)
	}
}

// TestNetworkSetupEnabled checks the answer the controller reports.
func TestNetworkSetupEnabled(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*serviceProxy)
		want   bool
	}{
		{name: "nothing configured", change: func(*serviceProxy) {}, want: false},
		{name: "a manual proxy", change: func(s *serviceProxy) { s.web = proxyValue{enabled: true, host: "proxy.corp", port: 8080} }, want: true},
		{name: "a secure proxy", change: func(s *serviceProxy) { s.secure = proxyValue{enabled: true} }, want: true},
		{name: "a socks proxy", change: func(s *serviceProxy) { s.socks = proxyValue{enabled: true} }, want: true},
		{name: "a configuration script", change: func(s *serviceProxy) { s.pacOn = true }, want: true},
		{name: "automatic discovery", change: func(s *serviceProxy) { s.autoDiscovery = true }, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeNetworkSetup()
			fake.state["Wi-Fi"] = &serviceProxy{}
			tc.change(fake.state["Ethernet"])
			got, err := newNetworkSetup(fake.run).Enabled(context.Background())
			if err != nil {
				t.Fatalf("Enabled: %v", err)
			}
			if got != tc.want {
				t.Errorf("Enabled = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestNetworkSetupClearTurnsEverySwitchOff checks the fallback used for a
// setting left by a build without a snapshot: the switches go off, nothing else
// is written, and no enabled service is skipped.
func TestNetworkSetupClearTurnsEverySwitchOff(t *testing.T) {
	fake := newFakeNetworkSetup()
	if err := newNetworkSetup(fake.run).Clear(context.Background()); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	for _, service := range []string{"Wi-Fi", "Ethernet"} {
		for _, flag := range []string{"-setwebproxystate", "-setsecurewebproxystate", "-setsocksfirewallproxystate"} {
			if !containsCall(fake.calls, "networksetup "+flag+" "+service+" off") {
				t.Errorf("%s %s was not switched off:\n%s", service, flag, strings.Join(fake.calls, "\n"))
			}
		}
	}
	if state := fake.state["Wi-Fi"]; !state.pacOn {
		t.Error("Clear touched the proxy auto-config script, which never points at a listener")
	}
	if strings.Join(fake.state["Wi-Fi"].bypass, ",") != "corp.local,*.internal" {
		t.Errorf("Clear touched the bypass list: %v", fake.state["Wi-Fi"].bypass)
	}
	for _, call := range fake.calls {
		if strings.Contains(call, "Bridge") {
			t.Errorf("a disabled service was touched: %q", call)
		}
	}
}

// TestNetworkSetupRefusesToReplaceAnAuthenticatedProxy checks the one case this
// backend will not take over: a proxy that asks for a password. The tool reports
// that it does, but never the credential, so a restore could only put the address
// back and would leave the user with a proxy that rejects every request.
func TestNetworkSetupRefusesToReplaceAnAuthenticatedProxy(t *testing.T) {
	fake := newFakeNetworkSetup()
	fake.state["Wi-Fi"].webAuth = true
	backend := newNetworkSetup(fake.run)

	_, err := backend.Plan(context.Background(), Settings{HTTP: "127.0.0.1:7890"})
	if err == nil {
		t.Fatal("Plan accepted an authenticated proxy it cannot restore")
	}
	if !strings.Contains(err.Error(), "Wi-Fi") || !strings.Contains(err.Error(), "authenticated") {
		t.Errorf("the error does not name the service and the reason: %v", err)
	}
	for _, call := range fake.calls {
		if strings.HasPrefix(call, "networksetup -set") {
			t.Errorf("the refusal still wrote something: %q", call)
		}
	}

	// Switching that proxy off keeps its address and its credential, so a
	// configuration that does not want an HTTP listener is allowed.
	if _, err := backend.Plan(context.Background(), Settings{SOCKS5: "127.0.0.1:7891"}); err != nil {
		t.Errorf("a takeover that only switches the authenticated proxy off was refused: %v", err)
	}
}

// TestNetworkSetupReportsAMissingService checks the machine with nothing to take
// over: the answer is an error naming the tool, not an empty takeover that looks
// applied.
func TestNetworkSetupReportsAMissingService(t *testing.T) {
	fake := newFakeNetworkSetup()
	fake.serviceLines = []string{"An asterisk (*) denotes that a network service is disabled.", "*Wi-Fi"}
	_, err := newNetworkSetup(fake.run).Plan(context.Background(), Settings{HTTP: "127.0.0.1:7890"})
	if err == nil {
		t.Fatal("Plan accepted a machine with no enabled network service")
	}
	if !strings.Contains(err.Error(), "no enabled network service") {
		t.Errorf("the error does not say what was missing: %v", err)
	}
}

// TestNetworkSetupBoundsAWriteThatWaitsForAPerson checks the budget: a tool that
// waits for an answer nobody gives has to end on its own, well before the shell
// that spawned this process decides the core is dead.
func TestNetworkSetupBoundsAWriteThatWaitsForAPerson(t *testing.T) {
	fake := newFakeNetworkSetup()
	fake.block = true
	backend := newNetworkSetup(fake.run)
	backend.budget = 30 * time.Millisecond

	start := time.Now()
	err := backend.Apply(context.Background(), Settings{HTTP: "127.0.0.1:7890"})
	if err == nil {
		t.Fatal("Apply succeeded although the tool never answered")
	}
	if !errors.Is(err, errToolTimedOut) {
		t.Errorf("a write that ran out of its budget reported %v", err)
	}
	if !strings.Contains(err.Error(), "administrator") {
		t.Errorf("the error does not suggest what the wait was for: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("the budget took %s, want it to end the wait", elapsed)
	}
}

// TestNetworkSetupRestoreReadsEveryPartOfTheSetting checks the restore path's
// reading: it has to see the value this program wrote, not one it assumes.
func TestNetworkSetupRestoreReadsEveryPartOfTheSetting(t *testing.T) {
	fake := newFakeNetworkSetup()
	path := filepath.Join(t.TempDir(), SnapshotFile)
	c := WithBackend(newNetworkSetup(fake.run), nil, path)
	if err := c.Enable(context.Background(), Settings{HTTP: "127.0.0.1:7890", SOCKS5: "127.0.0.1:7891"}); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	fake.calls = nil
	if err := c.Release(context.Background()); err != nil {
		t.Fatalf("Release: %v", err)
	}
	for _, flag := range []string{"-getautoproxyurl", "-getproxyautodiscovery", "-getwebproxy", "-getsocksfirewallproxy", "-getproxybypassdomains"} {
		if !containsCall(fake.calls, "networksetup "+flag+" Wi-Fi") {
			t.Errorf("the restore did not read %s before putting it back:\n%s", flag, strings.Join(fake.calls, "\n"))
		}
	}
	// Everything is back, including the script that was on before.
	if state := fake.state["Wi-Fi"]; !state.pacOn || !state.web.enabled || state.web.host != "proxy.corp" {
		t.Errorf("the setting was not put back: %+v", state)
	}
}

// TestProxyValueRoundTrip pins the snapshot spelling: the value a restore parses
// is the value the plan wrote.
func TestProxyValueRoundTrip(t *testing.T) {
	for _, want := range []proxyValue{
		{enabled: true, host: "127.0.0.1", port: 7890},
		{enabled: false, host: "", port: 0},
		{enabled: false, host: "proxy.corp", port: 3128},
	} {
		got, err := splitProxyValue(want.String())
		if err != nil {
			t.Fatalf("splitProxyValue(%q): %v", want.String(), err)
		}
		if got != want {
			t.Errorf("%q parsed back as %+v, want %+v", want.String(), got, want)
		}
	}
	for _, bad := range []string{"", "on", "on|host", "perhaps|host|1", "on|host|port"} {
		if _, err := splitProxyValue(bad); err == nil {
			t.Errorf("splitProxyValue accepted %q", bad)
		}
	}
}
