package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/melon-tgj/melonarc/internal/api"
	"github.com/melon-tgj/melonarc/internal/inbound"
	"github.com/melon-tgj/melonarc/internal/outbound"
	"github.com/melon-tgj/melonarc/internal/store"
)

// historyCore assembles a daemon with one manual group over two outbounds and a
// history file in its data directory. The first member echoes what it receives,
// so a test can put bytes in both directions of a tunnel; the second writes a
// label and closes, which is what the selection tests compare.
func historyCore(t *testing.T) *testCore {
	t.Helper()
	alpha := startEchoProxy(t)
	beta := startLabelledProxy(t, "beta")
	httpPort := freePort(t)

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "melonarc.ini")
	cfg := coreConfig(httpPort, [][2]string{proxyEntry("alpha", alpha), proxyEntry("beta", beta)})
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write configuration: %v", err)
	}
	return assembleCore(t, cfgPath)
}

// pollUntil repeats check until it reports true or the deadline passes. It is
// how these tests wait for a background loop: a fixed sleep would make them
// depend on how busy the machine is.
func pollUntil(t *testing.T, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if check() || time.Now().After(deadline) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// apiStatus reads one endpoint for its status code only, for the requests that
// are expected to be refused.
func apiStatus(t *testing.T, srv *api.Server, path string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, srv.URL()+path, nil)
	if err != nil {
		t.Fatalf("build %s: %v", path, err)
	}
	req.Header.Set("Authorization", "Bearer "+srv.Token())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body := make([]byte, 4096)
	n, _ := resp.Body.Read(body)
	return resp.StatusCode, string(body[:n])
}

// startEchoProxy serves SOCKS5 CONNECT requests by answering the handshake and
// then echoing everything it receives. Unlike the labelled proxy it keeps the
// connection open, which is what makes a tunnel carry bytes in both directions.
func startEchoProxy(t *testing.T) string {
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
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	return listener.Addr().String()
}

// echoThrough opens a CONNECT tunnel, sends payload and returns what came back,
// so the record can be checked in both directions.
func echoThrough(t *testing.T, proxyAddr, target, payload string) string {
	t.Helper()
	conn, reader := connectTunnel(t, proxyAddr, target)
	defer conn.Close()
	if _, err := io.WriteString(conn, payload); err != nil {
		t.Fatalf("write into the tunnel: %v", err)
	}
	answer := make([]byte, len(payload))
	if _, err := io.ReadFull(reader, answer); err != nil {
		t.Fatalf("read the echo: %v", err)
	}
	return string(answer)
}

// TestHistoryKeepsTheCarriedConnection checks the record a connection leaves
// behind: where it went, what carried it, and how much it moved.
func TestHistoryKeepsTheCarriedConnection(t *testing.T) {
	core := historyCore(t)

	// The echo outbound keeps the connection open, so the tunnel carries bytes
	// in both directions and the record has something to count in each.
	if got := echoThrough(t, core.proxyAddr, "example.test:443", "hello tunnel"); got != "hello tunnel" {
		t.Fatalf("the tunnel echoed %q", got)
	}

	// The record is written when the connection ends, which the tunnel's EOF
	// guarantees; polling keeps the assertion from depending on the order the
	// two goroutines finish in.
	var list api.ConnectionListView
	pollUntil(t, func() bool {
		list = apiGet[api.ConnectionListView](t, core.api, "/v1/history/connections")
		return list.Count > 0
	})
	if list.Count != 1 || len(list.Connections) != 1 {
		t.Fatalf("%d connections recorded, want 1: %+v", list.Count, list.Connections)
	}
	conn := list.Connections[0]
	if conn.Target != "example.test:443" || conn.Network != "tcp" || conn.Protocol != "http" {
		t.Errorf("record = %+v, want the http tunnel to example.test:443", conn)
	}
	if conn.Policy != "manual" || conn.Outbound != "alpha" {
		t.Errorf("record = %+v, want the policy and the leaf that carried it", conn)
	}
	if conn.Rule != "FINAL,manual" {
		t.Errorf("rule = %q, want the FINAL rule that chose the group", conn.Rule)
	}
	if conn.Up == 0 || conn.Down == 0 {
		t.Errorf("record carried up=%d down=%d, want both directions counted", conn.Up, conn.Down)
	}
	if conn.Up != int64(len("hello tunnel")) || conn.Down != int64(len("hello tunnel")) {
		t.Errorf("record carried up=%d down=%d, want the %d bytes of the echo in each direction",
			conn.Up, conn.Down, len("hello tunnel"))
	}

	summary := apiGet[api.HistoryView](t, core.api, "/v1/history")
	if !summary.Enabled || summary.Path != filepath.Join(core.dataDir, store.FileName) {
		t.Errorf("summary = %+v, want the history file of the data directory", summary)
	}
	if summary.Connections != 1 || summary.Capacity.Connections != store.DefaultRetention.Connections {
		t.Errorf("summary holds %d of %d connections", summary.Connections, summary.Capacity.Connections)
	}
	// The live counters and the record agree: a connection is counted once, in
	// both places, and the totals are what a traffic sample is taken from.
	if summary.Up != conn.Up || summary.Down != conn.Down {
		t.Errorf("summary reports %d/%d bytes, the record %d/%d", summary.Up, summary.Down, conn.Up, conn.Down)
	}
}

// TestHistoryKeepsWhatHappenedToTheDaemon checks the events: a selection, a
// reload that was refused and one that was applied.
func TestHistoryKeepsWhatHappenedToTheDaemon(t *testing.T) {
	core := historyCore(t)

	if code, _, stderr := core.runCLI(t, "select", "manual", "beta"); code != 0 {
		t.Fatalf("select exited %d: %s", code, stderr)
	}
	// A configuration that does not validate is refused, and the refusal is
	// part of the history: the file changed and the daemon did not agree.
	good, err := os.ReadFile(core.cfgPath)
	if err != nil {
		t.Fatalf("read the configuration: %v", err)
	}
	broken := strings.Replace(string(good), "FINAL,manual", "FINAL,missing", 1)
	core.writeConfig(t, broken)
	if code, _, _ := core.runCLI(t, "reload"); code == 0 {
		t.Fatal("reloading a broken configuration exited 0")
	}
	core.writeConfig(t, string(good))
	if code, _, stderr := core.runCLI(t, "reload"); code != 0 {
		t.Fatalf("reload exited %d: %s", code, stderr)
	}

	events := apiGet[api.EventListView](t, core.api, "/v1/history/events")
	if events.Count != 3 || len(events.Events) != 3 {
		t.Fatalf("%d events recorded, want 3: %+v", events.Count, events.Events)
	}
	if e := events.Events[0]; e.Kind != store.KindPolicy || !e.OK || e.Name != "manual" {
		t.Errorf("first event = %+v, want the successful selection", e)
	}
	if e := events.Events[1]; e.Kind != store.KindReload || e.OK {
		t.Errorf("second event = %+v, want the refused reload", e)
	} else if e.Detail == "" {
		t.Error("the refused reload was recorded without a reason")
	}
	if e := events.Events[2]; e.Kind != store.KindReload || !e.OK || e.Name != core.cfgPath {
		t.Errorf("third event = %+v, want the applied reload", e)
	}

	// A kind filter narrows the same set, which is what the CLI uses.
	reloads := apiGet[api.EventListView](t, core.api, "/v1/history/events?kind=reload")
	if reloads.Count != 2 {
		t.Errorf("%d reload events, want 2: %+v", reloads.Count, reloads.Events)
	}
}

// TestHistorySamplesTheTraffic checks that the series is the difference of the
// counters: what the connections carried, in the interval it was carried in.
func TestHistorySamplesTheTraffic(t *testing.T) {
	core := historyCore(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go sampleTraffic(ctx, core.state.metrics, core.state.history, 10*time.Millisecond, testLogger())

	var view api.TrafficListView
	// The sampler reads the counters before its first tick, so the connection
	// is opened after it started: that is the order a daemon runs in.
	if got := echoThrough(t, core.proxyAddr, "example.test:443", "sampled"); got != "sampled" {
		t.Fatalf("the tunnel echoed %q", got)
	}
	pollUntil(t, func() bool {
		view = apiGet[api.TrafficListView](t, core.api, "/v1/history/traffic")
		return view.Down > 0
	})
	if view.Up <= 0 || view.Down <= 0 {
		t.Fatalf("the sampled traffic is %d up and %d down, want both directions: %+v", view.Up, view.Down, view)
	}

	// A few intervals pass with nothing to carry, which is the case the series
	// has to keep: an idle interval is written as a zero rather than skipped, so
	// the samples add up to the traffic and a gap never looks like a measurement.
	pollUntil(t, func() bool {
		view = apiGet[api.TrafficListView](t, core.api, "/v1/history/traffic")
		for _, sample := range view.Samples {
			if sample.Up == 0 && sample.Down == 0 {
				return true
			}
		}
		return false
	})
	cancel()
	view = apiGet[api.TrafficListView](t, core.api, "/v1/history/traffic")

	if view.Count < 2 {
		t.Errorf("%d samples, want one per interval including the idle ones", view.Count)
	}
	for _, sample := range view.Samples {
		if sample.Time == "" {
			t.Error("a sample has no timestamp")
		}
	}
	up, down := core.state.metrics.Traffic()
	if view.Up > up || view.Down > down {
		t.Errorf("the series reports %d/%d bytes, more than the %d/%d carried", view.Up, view.Down, up, down)
	}
}

// TestHistoryServesAnEmptyRecord checks the shape of an empty answer: a daemon
// that has carried nothing yet reports empty lists, not nulls, so a client does
// not have to special case the first run.
func TestHistoryServesAnEmptyRecord(t *testing.T) {
	core := historyCore(t)

	if conns := apiGet[api.ConnectionListView](t, core.api, "/v1/history/connections"); conns.Connections == nil || conns.Count != 0 {
		t.Errorf("connections = %+v, want an empty list", conns)
	}
	if events := apiGet[api.EventListView](t, core.api, "/v1/history/events"); events.Events == nil || events.Count != 0 {
		t.Errorf("events = %+v, want an empty list", events)
	}
	if traffic := apiGet[api.TrafficListView](t, core.api, "/v1/history/traffic"); traffic.Samples == nil || traffic.Count != 0 {
		t.Errorf("traffic = %+v, want an empty list", traffic)
	}

	// A window a client cannot have meant is refused rather than ignored.
	if code, body := apiStatus(t, core.api, "/v1/history/connections?since=yesterday"); code != http.StatusBadRequest {
		t.Errorf("since=yesterday answered %d, want 400: %s", code, body)
	}
	if code, body := apiStatus(t, core.api, "/v1/history/events?kind="+strings.Repeat("x", 40)); code != http.StatusBadRequest {
		t.Errorf("a 40 byte kind answered %d, want 400: %s", code, body)
	}
}

// TestHistoryObserverRecordsWhatItIsGiven checks the translation the observer
// does, on its own: the inbound layer reports a record, the store keeps a row.
func TestHistoryObserverRecordsWhatItIsGiven(t *testing.T) {
	st, err := store.Open(store.Options{Path: filepath.Join(t.TempDir(), store.FileName)})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() {
		if err := st.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	}()
	observer := historyObserver{store: st}

	observer.Connection(inbound.ConnectionRecord{
		Protocol: "socks5",
		Target:   outbound.Target{Host: "example.test", Port: 8443},
		Network:  "tcp",
		Rule:     "DOMAIN-SUFFIX,example.test,manual",
		Policy:   "manual",
		Outbound: "beta",
		Started:  time.Unix(1_700_000_000, 0).UTC(),
		Duration: 1500 * time.Millisecond,
		Up:       120,
		Down:     340,
	})
	observer.Failure(inbound.Failure{
		Time:     time.Unix(1_700_000_001, 0).UTC(),
		Target:   "blocked.test:443",
		Network:  "tcp",
		Stage:    inbound.StageRoute,
		Category: inbound.CategoryRejected,
		Policy:   "REJECT",
	})

	conns := st.Connections(0, time.Time{})
	if len(conns) != 1 {
		t.Fatalf("%d connections kept, want 1", len(conns))
	}
	conn := conns[0]
	if conn.Host != "example.test" || conn.Port != 8443 || conn.Protocol != "socks5" {
		t.Errorf("connection = %+v", conn)
	}
	if conn.Up != 120 || conn.Down != 340 || conn.Duration != 1500*time.Millisecond {
		t.Errorf("connection carried %d/%d over %v", conn.Up, conn.Down, conn.Duration)
	}

	events := st.Events(0, store.KindFailure, time.Time{})
	if len(events) != 1 {
		t.Fatalf("%d failure events kept, want 1", len(events))
	}
	event := events[0]
	if event.Name != "blocked.test:443" || event.OK {
		t.Errorf("event = %+v, want an unsuccessful record of the target", event)
	}
	// The category stays in the detail: a rule that blocked a destination on
	// purpose and a proxy that refused one have the same shape here and the
	// opposite meaning to a reader.
	for _, want := range []string{inbound.StageRoute, inbound.CategoryRejected, "REJECT"} {
		if !strings.Contains(event.Detail, want) {
			t.Errorf("detail %q does not mention %q", event.Detail, want)
		}
	}
}

// TestSampleTrafficWithoutMetricsIsSilent checks that a daemon built without the
// observation object records an idle series instead of panicking in the sampler.
func TestSampleTrafficWithoutMetricsIsSilent(t *testing.T) {
	st, err := store.Open(store.Options{Path: filepath.Join(t.TempDir(), store.FileName)})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() {
		if err := st.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	sampleTraffic(ctx, nil, st, 10*time.Millisecond, testLogger())

	samples := st.Samples(0, time.Time{})
	if len(samples) == 0 {
		t.Error("an idle daemon recorded no sample at all")
	}
	for _, sample := range samples {
		if sample.Up != 0 || sample.Down != 0 {
			t.Errorf("an idle sample carried %d/%d bytes", sample.Up, sample.Down)
		}
	}
}

// captureStdout runs fn with the process stdout redirected, which is what the
// summary of a validation run is printed to.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	saved := os.Stdout
	os.Stdout = write
	defer func() { os.Stdout = saved }()

	done := make(chan string, 1)
	go func() {
		var out strings.Builder
		buf := make([]byte, 4096)
		for {
			n, err := read.Read(buf)
			out.Write(buf[:n])
			if err != nil {
				break
			}
		}
		done <- out.String()
	}()

	fn()
	write.Close()
	os.Stdout = saved
	return <-done
}

// TestCheckLeavesTheHistoryAlone keeps the validation run read-only: -check must
// report where the history would live without creating anything.
func TestCheckLeavesTheHistoryAlone(t *testing.T) {
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

	var runErr error
	out := captureStdout(t, func() { runErr = run([]string{"-config", cfgPath, "-check"}) })
	if runErr != nil {
		t.Fatalf("-check: %v", runErr)
	}

	want := filepath.Join(dir, "state", store.FileName)
	if !strings.Contains(out, "history: "+want) {
		t.Errorf("the summary does not report %q:\n%s", want, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "state")); !os.IsNotExist(err) {
		t.Errorf("-check created the data directory (%v)", err)
	}
}
