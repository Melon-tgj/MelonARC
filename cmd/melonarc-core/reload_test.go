package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/melon-tgj/melonarc/internal/api"
	"github.com/melon-tgj/melonarc/internal/cli"
	"github.com/melon-tgj/melonarc/internal/config"
	"github.com/melon-tgj/melonarc/internal/datadir"
	"github.com/melon-tgj/melonarc/internal/inbound"
)

// testCore is a daemon assembled the way main assembles it, with a configuration
// file the test can rewrite and reload.
type testCore struct {
	cfgPath   string
	dataDir   string
	tokenPath string
	api       *api.Server
	// proxyAddr is the HTTP inbound the test sends connections through.
	proxyAddr string
	state     *daemonState
}

// assembleCore loads the configuration file, builds every routing artefact in the
// order main does and starts the HTTP inbound and the API. The daemon context,
// the listeners and the groups are stopped by the test cleanup.
func assembleCore(t *testing.T, cfgPath string) *testCore {
	t.Helper()
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load %s: %v", cfgPath, err)
	}
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
	dataDir, err := datadir.Resolve(cfg.BaseDir, cfg.General.DataDir)
	if err != nil {
		t.Fatalf("resolve the data directory: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	metrics := inbound.NewMetrics(0)
	handler, err := buildHandler(program, registry, dialers, resolver, metrics, testLogger())
	if err != nil {
		t.Fatalf("buildHandler: %v", err)
	}
	services, err := startInbounds(cfg.General, handler, metrics, testLogger())
	if err != nil {
		t.Fatalf("startInbounds: %v", err)
	}

	state := &daemonState{
		cfg:       cfg,
		program:   program,
		registry:  registry,
		handler:   handler,
		metrics:   metrics,
		resolver:  resolver,
		version:   "test",
		startedAt: time.Now(),
	}
	level := new(slog.LevelVar)
	level.Set(logLevel("error"))
	state.reload = (&reloader{
		path:    cfg.Path,
		handler: handler,
		state:   state,
		metrics: metrics,
		level:   level,
		logger:  testLogger(),
		ctx:     ctx,
	}).reload
	startGroups(ctx, registry, testLogger())

	srv, err := api.New(api.Options{Addr: "127.0.0.1:0", Provider: state, Version: "test", Logger: testLogger()})
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}
	srv.Start()
	tokenPath, err := datadir.WriteToken(dataDir, srv.Token())
	if err != nil {
		t.Fatalf("WriteToken: %v", err)
	}

	t.Cleanup(cancel)
	t.Cleanup(func() { state.snapshot().registry.Close() })
	t.Cleanup(func() { closeInbounds(services, testLogger()) })
	t.Cleanup(func() {
		shutdown, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelShutdown()
		if err := srv.Close(shutdown); err != nil {
			t.Errorf("api close: %v", err)
		}
	})

	core := &testCore{
		cfgPath:   cfg.Path,
		dataDir:   dataDir,
		tokenPath: tokenPath,
		api:       srv,
		state:     state,
	}
	if len(services) > 0 {
		core.proxyAddr = services[0].Addr()
	}
	return core
}

// runCLI runs the command line client against this core, reading the token from
// the data directory the daemon wrote it to.
func (c *testCore) runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	full := append([]string{"-api", c.api.URL(), "-data-dir", c.dataDir}, args...)
	var stdout, stderr strings.Builder
	code := cli.Run(full, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// writeConfig replaces the configuration file of the core.
func (c *testCore) writeConfig(t *testing.T, text string) {
	t.Helper()
	if err := os.WriteFile(c.cfgPath, []byte(text), 0o600); err != nil {
		t.Fatalf("write %s: %v", c.cfgPath, err)
	}
}

// tunnelThrough performs an HTTP CONNECT through the inbound and returns what
// the selected outbound wrote into the tunnel.
func tunnelThrough(t *testing.T, proxyAddr, target string) string {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial %s: %v", proxyAddr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	reader := bufio.NewReader(conn)
	status, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read status line: %v", err)
	}
	if !strings.Contains(status, "200") {
		t.Fatalf("CONNECT answered %q", strings.TrimSpace(status))
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read response headers: %v", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read the tunnel: %v", err)
	}
	return string(body)
}

// startLabelledProxy serves SOCKS5 CONNECT requests by answering the handshake
// and then writing its label into the tunnel. It is the smallest possible outbound
// that can be told apart from another one.
func startLabelledProxy(t *testing.T, label string) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				if !answerSOCKS5Connect(c) {
					return
				}
				_, _ = io.WriteString(c, label)
			}(conn)
		}
	}()
	return listener.Addr().String()
}

// answerSOCKS5Connect completes the method negotiation and a CONNECT request,
// leaving the stream ready for the body.
func answerSOCKS5Connect(c net.Conn) bool {
	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil || head[0] != 5 {
		return false
	}
	if _, err := io.ReadFull(c, make([]byte, int(head[1]))); err != nil {
		return false
	}
	if _, err := c.Write([]byte{5, 0}); err != nil {
		return false
	}
	request := make([]byte, 4)
	if _, err := io.ReadFull(c, request); err != nil || request[0] != 5 || request[1] != 1 {
		return false
	}
	var addrLen int
	switch request[3] {
	case 1:
		addrLen = 4
	case 4:
		addrLen = 16
	case 3:
		length := make([]byte, 1)
		if _, err := io.ReadFull(c, length); err != nil {
			return false
		}
		addrLen = int(length[0])
	default:
		return false
	}
	if _, err := io.ReadFull(c, make([]byte, addrLen+2)); err != nil {
		return false
	}
	_, err := c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
	return err == nil
}

// coreConfig renders a configuration with one manual group over two proxies.
func coreConfig(httpPort int, proxies [][2]string) string {
	lines := []string{
		"[General]",
		"log-level = error",
		fmt.Sprintf("http-listen = 127.0.0.1:%d", httpPort),
		"socks5-listen = off",
		"data-dir = ./data",
		"",
		"[Proxy]",
	}
	for _, p := range proxies {
		lines = append(lines, fmt.Sprintf("%s = socks5, %s", p[0], p[1]))
	}
	lines = append(lines,
		"",
		"[Proxy Group]",
		"manual = select, alpha, beta",
		"",
		"[Rule]",
		"FINAL,manual",
		"",
	)
	return strings.Join(lines, "\n")
}

// proxyEntry splits a host:port address into the two fields a [Proxy] line takes.
func proxyEntry(name, address string) [2]string {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return [2]string{name, address}
	}
	return [2]string{name, host + ", " + port}
}

// TestCLISwitchesTheGroupAndReloadsTheConfiguration walks the whole stage: a
// daemon assembled from a file, a switch through the CLI that changes which
// outbound carries the next connection, a broken file that is refused without
// disturbing the running daemon, and a fixed one that takes effect.
func TestCLISwitchesTheGroupAndReloadsTheConfiguration(t *testing.T) {
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

	// The manual group starts on its first member.
	if got := tunnelThrough(t, core.proxyAddr, "example.test:443"); got != "alpha" {
		t.Fatalf("the first connection was carried by %q, want alpha", got)
	}

	// A switch through the CLI applies to the next connection.
	code, stdout, stderr := core.runCLI(t, "select", "manual", "beta")
	if code != 0 {
		t.Fatalf("select exited %d: %s%s", code, stdout, stderr)
	}
	if strings.TrimSpace(stdout) != "manual: alpha -> beta" {
		t.Errorf("select printed %q", stdout)
	}
	if got := tunnelThrough(t, core.proxyAddr, "example.test:443"); got != "beta" {
		t.Fatalf("after the switch the connection was carried by %q, want beta", got)
	}

	// A configuration that does not validate is refused, and the running one
	// keeps serving: the rules, the groups and the selection are untouched.
	broken := strings.Replace(good, "FINAL,manual", "DOMAIN,broken.test,ghost\nFINAL,missing", 1)
	core.writeConfig(t, broken)
	code, _, stderr = core.runCLI(t, "reload")
	if code == 0 {
		t.Fatalf("reloading a broken configuration exited 0: %s", stderr)
	}
	for _, want := range []string{"configuration problem", "ghost", "missing", "still in force"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("the refusal does not mention %q:\n%s", want, stderr)
		}
	}
	if got := tunnelThrough(t, core.proxyAddr, "example.test:443"); got != "beta" {
		t.Fatalf("after a refused reload the connection was carried by %q, want beta", got)
	}
	if policies := apiGet[struct {
		Policies []api.PolicyView `json:"policies"`
	}](t, core.api, "/v1/policies"); len(policies.Policies) != 1 || policies.Policies[0].Active != "beta" {
		t.Errorf("after a refused reload the groups are %+v", policies.Policies)
	}

	// A fixed configuration takes effect: the group is rebuilt, so it starts on
	// its first member again.
	core.writeConfig(t, good)
	code, stdout, stderr = core.runCLI(t, "reload")
	if code != 0 {
		t.Fatalf("reload exited %d: %s%s", code, stdout, stderr)
	}
	for _, want := range []string{"reloaded " + cfgPath, "rules 1", "groups 1"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("reload printed %q, want it to mention %q", stdout, want)
		}
	}
	if strings.Contains(stdout, "restart required") {
		t.Errorf("reload asked for a restart without a reason:\n%s", stdout)
	}
	if got := tunnelThrough(t, core.proxyAddr, "example.test:443"); got != "alpha" {
		t.Fatalf("after the reload the connection was carried by %q, want alpha", got)
	}

	// A listener address cannot change in a running process; the answer says so
	// and the listener keeps serving on the old address.
	moved := strings.Replace(good, fmt.Sprintf("http-listen = 127.0.0.1:%d", httpPort),
		fmt.Sprintf("http-listen = 127.0.0.1:%d", freePort(t)), 1)
	core.writeConfig(t, moved)
	code, stdout, stderr = core.runCLI(t, "reload")
	if code != 0 {
		t.Fatalf("reload exited %d: %s%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "restart required for: http-listen") {
		t.Errorf("reload printed %q, want it to name the setting that needs a restart", stdout)
	}
	if got := tunnelThrough(t, core.proxyAddr, "example.test:443"); got != "alpha" {
		t.Fatalf("the listener stopped serving its original address: %q", got)
	}

	// Every attempt is in the audit record, in order.
	audit := apiGet[api.AuditListView](t, core.api, "/v1/audit")
	if audit.Count != 4 || len(audit.Entries) != 4 {
		t.Fatalf("audit holds %d entries, want 4: %+v", audit.Count, audit.Entries)
	}
	wantResults := []string{api.ResultOK, api.ResultFailed, api.ResultOK, api.ResultOK}
	wantActions := []string{api.ActionPolicySelect, api.ActionConfigReload, api.ActionConfigReload, api.ActionConfigReload}
	for i, entry := range audit.Entries {
		if entry.Action != wantActions[i] || entry.Result != wantResults[i] {
			t.Errorf("entry %d = %+v, want %s/%s", i, entry, wantActions[i], wantResults[i])
		}
	}
	if !strings.Contains(audit.Entries[0].Detail, "manual: alpha -> beta") {
		t.Errorf("the switch was recorded as %q", audit.Entries[0].Detail)
	}
	if !strings.Contains(audit.Entries[1].Detail, "still in force") {
		t.Errorf("the refused reload was recorded as %q", audit.Entries[1].Detail)
	}
}

// TestDaemonDistributesTheTokenThroughTheDataDirectory checks the contract the CLI
// relies on: the daemon writes its token to the data directory with 0600, and the
// client reads it from there without being told the token.
func TestDaemonDistributesTheTokenThroughTheDataDirectory(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "melonarc.ini")
	raw := `[General]
log-level = error
http-listen = off
socks5-listen = off
data-dir = ./state

[Rule]
FINAL,DIRECT
`
	if err := os.WriteFile(cfgPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write configuration: %v", err)
	}
	core := assembleCore(t, cfgPath)

	if want := filepath.Join(dir, "state"); core.dataDir != want {
		t.Errorf("data directory = %q, want %q (relative to the configuration file)", core.dataDir, want)
	}
	info, err := os.Stat(core.tokenPath)
	if err != nil {
		t.Fatalf("stat %s: %v", core.tokenPath, err)
	}
	if runtime.GOOS != "windows" {
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Errorf("token file mode = %o, want 600", mode)
		}
	}
	token, err := datadir.ReadTokenFile(core.tokenPath)
	if err != nil {
		t.Fatalf("ReadTokenFile: %v", err)
	}
	if token != core.api.Token() {
		t.Errorf("the token file holds %q, want the token the API accepts", token)
	}

	// The CLI needs nothing but the data directory.
	code, stdout, stderr := core.runCLI(t, "status")
	if code != 0 {
		t.Fatalf("status exited %d: %s%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "rules") {
		t.Errorf("status printed %q", stdout)
	}
}
