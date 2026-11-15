package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/melon-tgj/melonarc/internal/api"
	"github.com/melon-tgj/melonarc/internal/inbound"
)

// gateTimeout bounds how long a test waits for the reload goroutine to reach a
// chosen point. It is a deadlock guard, not a delay: the rendezvous itself is a
// pair of channels, so the test never depends on how long anything takes.
const gateTimeout = 10 * time.Second

// gatedReload is one reload held at its commit point.
type gatedReload struct {
	arrived chan struct{}
	proceed chan struct{}
	done    chan struct{}
	view    api.ReloadView
	err     error
}

// startGatedReload runs a reload and returns once the rebuild is complete and the
// swap has not started. That instant is the window the commit point exists for:
// the new configuration is built, the running one is still in force.
func startGatedReload(t *testing.T, core *testCore) *gatedReload {
	t.Helper()
	g := &gatedReload{
		arrived: make(chan struct{}),
		proceed: make(chan struct{}),
		done:    make(chan struct{}),
	}
	core.reloader.beforeCommit = func() {
		close(g.arrived)
		<-g.proceed
	}
	go func() {
		defer close(g.done)
		g.view, g.err = core.state.ReloadConfig(context.Background())
	}()
	select {
	case <-g.arrived:
	case <-time.After(gateTimeout):
		t.Fatal("the reload never reached its commit point")
	}
	return g
}

// finish lets the held reload commit and returns its answer.
func (g *gatedReload) finish(t *testing.T, core *testCore) api.ReloadView {
	t.Helper()
	core.reloader.beforeCommit = nil
	close(g.proceed)
	select {
	case <-g.done:
	case <-time.After(gateTimeout):
		t.Fatal("the reload never finished after it was allowed to commit")
	}
	if g.err != nil {
		t.Fatalf("reload: %v", g.err)
	}
	return g.view
}

// activeMember reads the member a manual group routes to, through the same view
// the API serves.
func activeMember(t *testing.T, core *testCore, group string) string {
	t.Helper()
	for _, view := range core.state.Policies(context.Background()) {
		if view.Name == group {
			return view.Active
		}
	}
	t.Fatalf("group %q is not in the policy view", group)
	return ""
}

// TestReloadKeepsAPinMadeWhileTheRebuildRuns pins a group in the window between
// "the rebuild finished" and "the rebuild took effect".
//
// That window is the defect the commit point closes: the pin used to be read when
// the rebuild started, so a switch that landed while it ran was answered with
// "ok" and then silently overwritten by the value from before the reload. The
// interleaving is made exact with a hook before the commit, never with timing:
// the reload is parked there, the pin is taken, and only then does the commit
// run.
func TestReloadKeepsAPinMadeWhileTheRebuildRuns(t *testing.T) {
	alpha := startLabelledProxy(t, "alpha")
	beta := startLabelledProxy(t, "beta")
	httpPort := freePort(t)

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "melonarc.ini")
	good := coreConfig(httpPort, [][2]string{proxyEntry("alpha", alpha), proxyEntry("beta", beta)})
	if err := os.WriteFile(cfgPath, []byte(good), 0o600); err != nil {
		t.Fatalf("write configuration: %v", err)
	}
	core := assembleCore(t, cfgPath)

	if got := activeMember(t, core, "manual"); got != "alpha" {
		t.Fatalf("the manual group starts on %q, want alpha", got)
	}

	// Change the file so the reload really rebuilds something, then park the
	// reload at its commit point.
	core.writeConfig(t, strings.Replace(good, "FINAL,manual", "DOMAIN,changed.test,manual\nFINAL,manual", 1))
	g := startGatedReload(t, core)

	// The pin happens now: after the rebuild, before the swap.
	sel, err := core.state.SelectPolicy(context.Background(), "manual", "beta")
	if err != nil {
		t.Fatalf("select during a reload: %v", err)
	}
	if sel.Previous != "alpha" || sel.Active != "beta" {
		t.Fatalf("select answered %+v, want alpha -> beta", sel)
	}
	// The pin went into the registry that is still in force. That is the whole
	// point of the ordering: it is the state the commit has to inherit from.
	if got := activeMember(t, core, "manual"); got != "beta" {
		t.Fatalf("the running registry routes to %q right after the pin, want beta", got)
	}

	view := g.finish(t, core)
	if len(view.SelectionDropped) != 0 {
		t.Fatalf("the reload reported dropped selections %v, want none", view.SelectionDropped)
	}
	if got := activeMember(t, core, "manual"); got != "beta" {
		t.Fatalf("after the reload the group routes to %q, want the pin taken during the rebuild", got)
	}
	// The reload did what the file asked as well: the pin survived, it did not
	// replace the configuration.
	if view.RuleCount != 2 {
		t.Errorf("reloaded rule count = %d, want the two rules of the new file", view.RuleCount)
	}
	// And the next connection goes through the pinned member.
	if got := tunnelThrough(t, core.proxyAddr, "changed.test:443"); got != "beta" {
		t.Fatalf("the connection after the reload was carried by %q, want beta", got)
	}
}

// TestReloadDropsAPinWhoseMemberIsGone is the other half of the same window: a
// pin taken during the rebuild whose member the new configuration no longer
// declares cannot be honoured, and has to be reported rather than disappear.
func TestReloadDropsAPinWhoseMemberIsGone(t *testing.T) {
	alpha := startLabelledProxy(t, "alpha")
	beta := startLabelledProxy(t, "beta")
	httpPort := freePort(t)

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "melonarc.ini")
	good := coreConfig(httpPort, [][2]string{proxyEntry("alpha", alpha), proxyEntry("beta", beta)})
	if err := os.WriteFile(cfgPath, []byte(good), 0o600); err != nil {
		t.Fatalf("write configuration: %v", err)
	}
	core := assembleCore(t, cfgPath)

	// The new file declares the group without beta, so the pin the test takes
	// cannot survive the swap.
	narrowed := strings.Replace(good, "manual = select, alpha, beta", "manual = select, alpha", 1)
	core.writeConfig(t, narrowed)
	g := startGatedReload(t, core)

	sel, err := core.state.SelectPolicy(context.Background(), "manual", "beta")
	if err != nil {
		t.Fatalf("select during a reload: %v", err)
	}
	if sel.Active != "beta" {
		t.Fatalf("select answered %+v, want the pin to beta", sel)
	}

	view := g.finish(t, core)
	if len(view.SelectionDropped) != 1 {
		t.Fatalf("dropped selections = %v, want exactly one", view.SelectionDropped)
	}
	detail := view.SelectionDropped[0]
	if !strings.Contains(detail, "manual") || !strings.Contains(detail, "beta") || !strings.Contains(detail, "alpha") {
		t.Fatalf("dropped selection %q does not say which group, which member and what it fell back to", detail)
	}
	// The group is not left on a member that no longer exists.
	if got := activeMember(t, core, "manual"); got != "alpha" {
		t.Fatalf("the rebuilt group routes to %q, want its remaining first member", got)
	}
	// beta is not in the group any more, so the API refuses to pin it.
	if _, err := core.state.SelectPolicy(context.Background(), "manual", "beta"); err == nil {
		t.Fatal("a member the new configuration dropped can still be selected")
	}
}

// TestReloadRepointsTheDeviceResolver checks the third part of the commit: the
// resolver the TUN device answers DNS with moves with the configuration.
//
// The device is created once, at startup, so it cannot be rebuilt by a reload;
// it reads the resolver from a holder, and install writes that holder inside the
// same critical section as the API snapshot. This test proves the reload half of
// that chain — the device half is proved by the inbound tests.
func TestReloadRepointsTheDeviceResolver(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "melonarc.ini")
	raw := `[General]
log-level = error
http-listen = off
socks5-listen = off
data-dir = ./data

[Host]
svc.test = 10.1.2.3

[Rule]
FINAL,DIRECT
`
	if err := os.WriteFile(cfgPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write configuration: %v", err)
	}
	core := assembleCore(t, cfgPath)

	if core.state.resolvers == nil {
		t.Fatal("the daemon state does not hold the resolver the device reads")
	}
	if got := lookupHost(t, core.state.resolvers.Load(), "svc.test"); got != "10.1.2.3" {
		t.Fatalf("the device resolver answers svc.test with %q, want the file's 10.1.2.3", got)
	}

	// Change the mapping and reload.
	core.writeConfig(t, strings.Replace(raw, "svc.test = 10.1.2.3", "svc.test = 10.9.9.9", 1))
	if _, err := core.state.ReloadConfig(context.Background()); err != nil {
		t.Fatalf("reload: %v", err)
	}

	if got := lookupHost(t, core.state.resolvers.Load(), "svc.test"); got != "10.9.9.9" {
		t.Fatalf("after the reload the device resolver answers %q, want the new 10.9.9.9", got)
	}
	// The device and the API must not disagree about which resolver is current.
	if core.state.resolvers.Load() != inbound.Resolver(core.state.snapshot().resolver) {
		t.Fatal("the device resolver and the configuration snapshot are different objects after a reload")
	}
}

// lookupHost asks the resolver in force for the first address of a name.
func lookupHost(t *testing.T, r inbound.Resolver, name string) string {
	t.Helper()
	if r == nil {
		t.Fatalf("no resolver to ask for %q", name)
	}
	resolved, err := r.Resolve(context.Background(), name)
	if err != nil || len(resolved.IPs) == 0 {
		t.Fatalf("resolve %q: %v (%d addresses)", name, err, len(resolved.IPs))
	}
	return resolved.IPs[0].String()
}
