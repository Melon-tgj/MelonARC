package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/melon-tgj/melonarc/internal/api"
	"github.com/melon-tgj/melonarc/internal/config"
	"github.com/melon-tgj/melonarc/internal/inbound"
	"github.com/melon-tgj/melonarc/internal/subscription"
)

// subscriptionConfig is a configuration whose only target is a subscription.
// The group it declares is filled by the import, which is what makes the rule
// resolvable at runtime.
func subscriptionConfig(httpPort int, url string) string {
	return fmt.Sprintf(`[General]
log-level = error
http-listen = 127.0.0.1:%d
socks5-listen = off
data-dir = ./data

[Subscription]
airport = %s

[Rule]
FINAL,airport
`, httpPort, url)
}

// TestAssembledCoreImportsSubscriptionNodes assembles a whole daemon from a file
// that names a subscription and checks the two things the import has to
// produce: the nodes, under the subscription's prefix, and the group the rules
// point at.
func TestAssembledCoreImportsSubscriptionNodes(t *testing.T) {
	link := "ss://YWVzLTI1Ni1nY206c2VjcmV0@node.example.com:8388#Node"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, link)
	}))
	defer server.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "melonarc.ini")
	text := subscriptionConfig(freePort(t), server.URL)
	if err := os.WriteFile(cfgPath, []byte(text), 0o600); err != nil {
		t.Fatalf("write configuration: %v", err)
	}
	core := assembleCore(t, cfgPath)

	snapshot := core.state.snapshot()
	if len(snapshot.cfg.Proxies) != 1 {
		t.Fatalf("proxies = %d, want the imported node", len(snapshot.cfg.Proxies))
	}
	imported := snapshot.cfg.Proxies[0]
	if imported.Name != "airport/Node" {
		t.Fatalf("imported node is named %q", imported.Name)
	}
	if imported.Server != "node.example.com" || imported.Port != 8388 {
		t.Fatalf("imported node address = %s:%d", imported.Server, imported.Port)
	}
	group, ok := snapshot.cfg.GroupByName("airport")
	if !ok {
		t.Fatal("the subscription group is missing")
	}
	if len(group.Members) != 1 || group.Members[0] != "airport/Node" {
		t.Fatalf("group members = %v", group.Members)
	}
	// The registry is what the router actually resolves; the group has to be a
	// real target there, not just an entry in the configuration.
	if _, err := snapshot.registry.Resolve("airport"); err != nil {
		t.Fatalf("the subscription group is not routable: %v", err)
	}
}

// TestReloadKeepsImportedNodes checks that a reload does not lose the nodes a
// subscription contributed: the file on disk never contained them, so they can
// only survive if the reload imports again.
func TestReloadKeepsImportedNodes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ss://YWVzLTI1Ni1nY206c2VjcmV0@node.example.com:8388#Node")
	}))
	defer server.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "melonarc.ini")
	port := freePort(t)
	if err := os.WriteFile(cfgPath, []byte(subscriptionConfig(port, server.URL)), 0o600); err != nil {
		t.Fatalf("write configuration: %v", err)
	}
	core := assembleCore(t, cfgPath)

	// Rewrite the same file: the reload re-reads it, imports again and must end
	// up with the same node.
	core.writeConfig(t, subscriptionConfig(port, server.URL))
	if _, err := core.state.reload(t.Context()); err != nil {
		t.Fatalf("reload: %v", err)
	}
	snapshot := core.state.snapshot()
	if len(snapshot.cfg.Proxies) != 1 {
		t.Fatalf("after a reload there are %d proxies, want 1", len(snapshot.cfg.Proxies))
	}
	if _, err := snapshot.registry.Resolve("airport"); err != nil {
		t.Fatalf("the group is not routable after a reload: %v", err)
	}
}

// TestSubscriptionRefreshKeepsThePinnedMember is the regression test for the
// complaint this stage answers: a subscription refresh rebuilds every routing
// artefact, and a manual group used to come back on its first member — so a node
// the user picked was silently replaced every time the provider published an
// update. The refresh now goes through the same reload path as a hand edit, and
// that path carries the selection across by group name.
func TestSubscriptionRefreshKeepsThePinnedMember(t *testing.T) {
	// One link per node; the fragment becomes the node name, so the group
	// below is "airport" and its members are "airport/NodeA" and so on.
	links := func(names ...string) string {
		out := ""
		for _, name := range names {
			out += "ss://YWVzLTI1Ni1nY206c2VjcmV0@node.example.com:8388#" + name + "\n"
		}
		return out
	}
	var body atomic.Value
	body.Store(links("NodeA", "NodeB"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, body.Load().(string))
	}))
	defer server.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "melonarc.ini")
	text := subscriptionConfig(freePort(t), server.URL)
	if err := os.WriteFile(cfgPath, []byte(text), 0o600); err != nil {
		t.Fatalf("write configuration: %v", err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load %s: %v", cfgPath, err)
	}

	// The manager's clock is the test's, so the second import is due without
	// waiting six hours for it.
	var clock atomic.Int64
	clock.Store(time.Now().UnixNano())
	subs := subscription.New(subscription.Options{
		Logger: testLogger(),
		Now:    func() time.Time { return time.Unix(0, clock.Load()) },
	})
	if err := subs.Import(context.Background(), cfg); err != nil {
		t.Fatalf("import subscriptions: %v", err)
	}

	// Everything main assembles after the import, minus the listeners: a reload
	// needs the handler, the state and the store of groups, nothing that binds
	// a port.
	program := compileTestRules(t, cfg)
	resolver, err := buildResolver(cfg)
	if err != nil {
		t.Fatalf("buildResolver: %v", err)
	}
	dialers, err := buildDialers(cfg, resolver, testLogger())
	if err != nil {
		t.Fatalf("buildDialers: %v", err)
	}
	registry, err := buildRegistry(cfg, dialers)
	if err != nil {
		t.Fatalf("buildRegistry: %v", err)
	}
	metrics := inbound.NewMetrics(0)
	handler, err := buildHandler(program, registry, dialers, resolver, metrics, testLogger())
	if err != nil {
		t.Fatalf("buildHandler: %v", err)
	}
	baseline := cfg.General
	state := &daemonState{
		cfg: cfg, program: program, registry: registry, handler: handler,
		metrics: metrics, resolver: resolver, dialers: dialers,
		version: "test", startedAt: time.Now(), baseline: &baseline,
	}
	level := new(slog.LevelVar)
	level.Set(logLevel("error"))
	state.reload = (&reloader{
		path: cfgPath, handler: handler, state: state, metrics: metrics,
		level: level, logger: testLogger(), subs: subs, ctx: context.Background(),
	}).reload
	t.Cleanup(func() { state.snapshot().registry.Close() })

	group, ok := registry.Group("airport")
	if !ok {
		t.Fatal("the subscription group was not registered")
	}
	if len(group.Members()) != 2 {
		t.Fatalf("group members = %v, want the two imported nodes", group.Members())
	}
	if err := group.Select("airport/NodeB"); err != nil {
		t.Fatalf("pin the group to NodeB: %v", err)
	}

	// The provider publishes a new list: NodeA is gone, NodeC is new, and the
	// node the user picked is still there under the same name.
	body.Store(links("NodeB", "NodeC"))
	clock.Store(time.Now().Add(7 * time.Hour).UnixNano())
	if _, err := state.reload(context.Background()); err != nil {
		t.Fatalf("reload: %v", err)
	}

	reloaded := state.snapshot()
	fresh, ok := reloaded.registry.Group("airport")
	if !ok {
		t.Fatal("the group is missing after the refresh")
	}
	if got := fresh.Active(); got != "airport/NodeB" {
		t.Fatalf("after the subscription refresh the group routes to %q, want the pinned airport/NodeB", got)
	}
	if len(fresh.Members()) != 2 {
		t.Fatalf("after the refresh the group has members %v, want the new list", fresh.Members())
	}
	// The pin is not just a label: the router has to end at the same node.
	resolution, err := reloaded.registry.Resolve("airport")
	if err != nil {
		t.Fatalf("resolve the group: %v", err)
	}
	if resolution.Leaf != "airport/NodeB" {
		t.Fatalf("the group resolves to %q, want the pinned node", resolution.Leaf)
	}

	// A pin whose node the provider dropped cannot be honoured, and the reload
	// says so instead of quietly picking another member.
	body.Store(links("NodeC"))
	clock.Store(time.Now().Add(14 * time.Hour).UnixNano())
	view, err := state.reload(context.Background())
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(view.SelectionDropped) != 1 {
		t.Fatalf("selection_dropped = %v, want the lost pin", view.SelectionDropped)
	}
	last, ok := state.snapshot().registry.Group("airport")
	if !ok {
		t.Fatal("the group is missing after the last reload")
	}
	if got := last.Active(); got != "airport/NodeC" {
		t.Fatalf("with the pinned node gone the group routes to %q, want the remaining member", got)
	}
}

// TestAssembledCoreServesTheSkipDetail drives the two read-only subscription
// endpoints through a real daemon: the summary carries counts only, the detail
// is a page of the last completed refresh with the item numbers the log used,
// and a name the file does not declare is refused with its own code.
func TestAssembledCoreServesTheSkipDetail(t *testing.T) {
	// Two good nodes and two entries the importer refuses. The refused ones
	// carry a method it does not implement and a type it has never heard of,
	// and neither carries a credential: the reasons must not quote a link, and
	// a fixture without one keeps that property visible in the answer.
	body := strings.Join([]string{
		"ss://YWVzLTI1Ni1nY206c2VjcmV0@node-a.example.com:8388#NodeA",
		"ss://aes-999@bad.example.com:8388#Bad",
		"wireguard://key@host:1",
		"ss://YWVzLTI1Ni1nY206c2VjcmV0@node-b.example.com:8388#NodeB",
	}, "\n") + "\n"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, body)
	}))
	defer server.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "melonarc.ini")
	if err := os.WriteFile(cfgPath, []byte(subscriptionConfig(freePort(t), server.URL)), 0o600); err != nil {
		t.Fatalf("write configuration: %v", err)
	}
	core := assembleCore(t, cfgPath)

	listRec := apiGet[json.RawMessage](t, core.api, "/v1/subscriptions")
	if strings.Contains(string(listRec), `"reason"`) {
		t.Fatalf("the summary carries skip details: %s", listRec)
	}
	var list api.SubscriptionListView
	if err := json.Unmarshal(listRec, &list); err != nil {
		t.Fatalf("decode the summary: %v", err)
	}
	if len(list.Subscriptions) != 1 {
		t.Fatalf("subscriptions = %+v, want the one the file declares", list.Subscriptions)
	}
	summary := list.Subscriptions[0]
	if summary.Name != "airport" || summary.Nodes != 2 || summary.Skipped != 2 {
		t.Fatalf("summary = %+v, want two nodes and two skipped entries", summary)
	}
	if summary.FetchedAt == "" || summary.NextAt == "" || summary.Error != "" {
		t.Fatalf("summary = %+v, want a completed refresh with its next attempt", summary)
	}

	first := apiGet[api.SkippedListView](t, core.api, "/v1/subscriptions/airport/skipped?offset=0&limit=1")
	if !first.Refreshed || first.Total != 2 || first.Offset != 0 || first.Limit != 1 {
		t.Fatalf("first page = %+v", first)
	}
	if len(first.Skipped) != 1 || first.Skipped[0].Item != 2 {
		t.Fatalf("first page holds %+v, want item 2", first.Skipped)
	}
	if first.Skipped[0].Reason == "" || strings.Contains(first.Skipped[0].Reason, "bad.example.com") {
		t.Fatalf("reason = %q, want a reason that does not quote the link", first.Skipped[0].Reason)
	}

	second := apiGet[api.SkippedListView](t, core.api, "/v1/subscriptions/airport/skipped?offset=1&limit=1")
	if second.Total != 2 || second.Offset != 1 || len(second.Skipped) != 1 || second.Skipped[0].Item != 3 {
		t.Fatalf("second page = %+v, want item 3", second)
	}

	if code, _ := apiStatus(t, core.api, "/v1/subscriptions/typo/skipped"); code != http.StatusNotFound {
		t.Fatalf("an unknown name answered %d, want 404", code)
	}
	if code, body := apiStatus(t, core.api, "/v1/subscriptions/airport/skipped?limit=999"); code != http.StatusBadRequest {
		t.Fatalf("a page above the cap answered %d (%s), want 400", code, body)
	}
}
