package store

// The tests at the file-format boundary: the history this build writes is an
// ordinary SQLite database, and the history a previous build left behind is
// read and then appended to by this one.
//
// The first property is checked by handing the file to the SQLite command line
// tool rather than to this package's own reader: a self-consistent mistake in
// the writer would satisfy the second reader only. The second property is
// checked against a real file from the previous build, kept in testdata as
// base64 because it is a binary artefact and the only copy of that layout.

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestHistoryFileIsReadBySQLiteTool is the check that matters: a file written
// here is a database any SQLite reader opens, with the schema, the version and
// the rows that went in.
//
// The 500 rows do not fit one page, so this also exercises the interior pages
// the engine builds — the case a single row would never reach.
func TestHistoryFileIsReadBySQLiteTool(t *testing.T) {
	tool, err := exec.LookPath("sqlite3")
	if err != nil {
		t.Skip("no sqlite3 command line tool on this machine")
	}
	path := filepath.Join(t.TempDir(), FileName)
	s, err := Open(Options{Path: path, FlushInterval: time.Hour})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	base := time.Date(2026, 11, 14, 8, 0, 0, 0, time.UTC)
	for i := 0; i < 500; i++ {
		s.RecordConnection(Connection{
			At:       base.Add(time.Duration(i) * time.Millisecond),
			Protocol: "http",
			Host:     fmt.Sprintf("host-%03d.example", i),
			Port:     i,
			Network:  "tcp",
			Rule:     strings.Repeat("z", i%120),
			Policy:   "manual",
			Outbound: "alpha",
			Up:       int64(i),
			Down:     int64(2 * i),
			Duration: time.Duration(i) * time.Millisecond,
		})
	}
	s.RecordEvent(Event{At: base, Kind: KindReload, Name: "/etc/melonarc.ini", Detail: "3 rules", OK: true})
	if err := s.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if out := runSQLite(t, tool, path, "SELECT count(*), min(at), max(at) FROM connections;"); out != "500|1794643200000|1794643200499" {
		t.Errorf("count/min/max = %q", out)
	}
	if out := runSQLite(t, tool, path, "SELECT rule FROM connections WHERE port = 499;"); out != strings.Repeat("z", 499%120) {
		t.Errorf("row 499 came back as %q", out)
	}
	if out := runSQLite(t, tool, path, "SELECT name FROM sqlite_schema ORDER BY name;"); out != "connections\nevents\nsamples" {
		t.Errorf("schema = %q", out)
	}
	if out := runSQLite(t, tool, path, "SELECT count(*) FROM events;"); out != "1" {
		t.Errorf("events answered %q", out)
	}
	if out := runSQLite(t, tool, path, "SELECT count(*) FROM samples;"); out != "0" {
		t.Errorf("an empty table answered %q", out)
	}
	if out := runSQLite(t, tool, path, "PRAGMA integrity_check;"); out != "ok" {
		t.Errorf("integrity_check = %q", out)
	}
	if out := runSQLite(t, tool, path, "PRAGMA user_version;"); out != fmt.Sprint(userVersion) {
		t.Errorf("user_version = %q", out)
	}
}

// TestLegacyHistoryFileIsReadByThisBuild loads the file the previous build
// wrote and checks every column of every row of all three tables. The fixture
// was chosen to be uncomfortable on purpose: a 252 byte host name, byte counts
// beyond 32 bits, an empty string column and a punycode name, so a decoder that
// only handles the easy row is caught here.
func TestLegacyHistoryFileIsReadByThisBuild(t *testing.T) {
	path := legacyHistoryFile(t)
	s, err := Open(Options{Path: path, FlushInterval: time.Hour})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() {
		if err := s.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}()

	if status := s.Status(); status.Notice != "" {
		t.Fatalf("the file a previous build wrote was not adopted: %s", status.Notice)
	}

	at := func(ms int64) time.Time { return time.UnixMilli(ms).UTC() }
	conns := s.Connections(0, time.Time{})
	if len(conns) != 4 {
		t.Fatalf("read %d connections, want 4: %+v", len(conns), conns)
	}
	want := Connection{
		At:       at(1794643200000),
		Protocol: "http",
		Host:     "example.com",
		Port:     443,
		Network:  "tcp",
		Rule:     "DOMAIN-SUFFIX,example.com",
		Policy:   "manual",
		Outbound: "alpha",
		Up:       1200,
		Down:     34000,
		Duration: 1500 * time.Millisecond,
	}
	if conns[0] != want {
		t.Errorf("first connection = %+v, want %+v", conns[0], want)
	}
	// An empty string column stays empty rather than coming back as NULL would
	// be a difference no caller could see, but a NULL would have made the row
	// unreadable, so this pins that the previous build really wrote ''.
	if conns[1].Rule != "" || conns[1].Policy != "auto" || conns[1].Network != "udp" {
		t.Errorf("second connection = %+v", conns[1])
	}
	if len(conns[2].Host) != 252 {
		t.Errorf("the long host came back with %d bytes, want 252", len(conns[2].Host))
	}
	if conns[2].Up != 1<<40 || conns[2].Down != 1<<41 {
		t.Errorf("the 40 bit counters came back as %d/%d", conns[2].Up, conns[2].Down)
	}
	if conns[2].Duration != 90*time.Second || conns[2].Outbound != "node-b" {
		t.Errorf("third connection = %+v", conns[2])
	}
	if conns[3].Host != "xn--fsqu00a.example" || conns[3].Up != 7 || conns[3].Down != 8 {
		t.Errorf("fourth connection = %+v", conns[3])
	}

	events := s.Events(0, "", time.Time{})
	if len(events) != 3 {
		t.Fatalf("read %d events, want 3: %+v", len(events), events)
	}
	wantEvents := []Event{
		{At: at(1794643200000), Kind: KindReload, Name: "/etc/melonarc.ini", Detail: "3 rules", OK: true},
		{At: at(1794643260000), Kind: KindFailure, Name: "alpha", Detail: "dial_timeout", OK: false},
		{At: at(1794643320000), Kind: KindPolicy, Name: "airport", Detail: "airport: node-a -> node-b", OK: true},
	}
	for i := range wantEvents {
		if events[i] != wantEvents[i] {
			t.Errorf("event %d = %+v, want %+v", i, events[i], wantEvents[i])
		}
	}

	samples := s.Samples(0, time.Time{})
	if len(samples) != 3 {
		t.Fatalf("read %d samples, want 3: %+v", len(samples), samples)
	}
	wantSamples := []Sample{
		{At: at(1794643200000), Up: 4000, Down: 90000},
		{At: at(1794643260000)},
		{At: at(1794643320000), Up: 1024, Down: 2048},
	}
	for i := range wantSamples {
		if samples[i] != wantSamples[i] {
			t.Errorf("sample %d = %+v, want %+v", i, samples[i], wantSamples[i])
		}
	}

	// Loading must not be a rewrite: the file has to be the one that was there.
	if status := s.Status(); status.Bytes != fileSize(t, path) {
		t.Errorf("status reports %d bytes, the file is %d", status.Bytes, fileSize(t, path))
	}
}

// TestLegacyHistoryFileTakesNewWrites is the takeover path: a file from the
// previous build is opened, appended to, flushed and read back by a third run.
// Both the rows that came from the old file and the ones written by this build
// have to survive, in order.
func TestLegacyHistoryFileTakesNewWrites(t *testing.T) {
	path := legacyHistoryFile(t)
	s, err := Open(Options{Path: path, FlushInterval: time.Hour})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	newAt := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	s.RecordConnection(Connection{
		At: newAt, Protocol: "tun", Host: "new.example", Port: 8443, Network: "tcp",
		Rule: "MATCH", Policy: "DIRECT", Outbound: "DIRECT", Up: 5, Down: 6,
		Duration: 7 * time.Millisecond,
	})
	s.RecordEvent(Event{At: newAt, Kind: KindSubscription, Name: "airport", Detail: "12 nodes", OK: true})
	s.RecordSample(Sample{At: newAt, Up: 11, Down: 22})
	if err := s.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := Open(Options{Path: path, FlushInterval: time.Hour})
	if err != nil {
		t.Fatalf("Open again: %v", err)
	}
	defer reopened.Close()
	if status := reopened.Status(); status.Notice != "" {
		t.Fatalf("the rewritten file is not usable: %s", status.Notice)
	}

	conns := reopened.Connections(0, time.Time{})
	if len(conns) != 5 {
		t.Fatalf("read %d connections, want 5: %+v", len(conns), conns)
	}
	if conns[0].Host != "example.com" || conns[0].Up != 1200 {
		t.Errorf("the oldest row from the previous build was lost: %+v", conns[0])
	}
	if conns[2].Up != 1<<40 || len(conns[2].Host) != 252 {
		t.Errorf("a wide row from the previous build was mangled: %+v", conns[2])
	}
	if conns[4].Host != "new.example" || conns[4].At != newAt || conns[4].Up != 5 {
		t.Errorf("the row written by this build = %+v", conns[4])
	}
	if events := reopened.Events(0, "", time.Time{}); len(events) != 4 || events[3].Kind != KindSubscription {
		t.Errorf("events = %+v", events)
	}
	if samples := reopened.Samples(0, time.Time{}); len(samples) != 4 || samples[3].Up != 11 {
		t.Errorf("samples = %+v", samples)
	}
}

// legacyHistoryFile decodes the fixture a previous build left behind into a
// temporary file. The text is base64 rather than the database itself because a
// binary blob in a diff cannot be reviewed; the layout it represents is the one
// the tests above have to keep reading.
func legacyHistoryFile(t *testing.T) string {
	t.Helper()
	encoded, err := os.ReadFile(filepath.Join("testdata", "legacy-history.sqlite3.base64"))
	if err != nil {
		t.Fatalf("read the fixture: %v", err)
	}
	clean := strings.NewReplacer("\n", "", "\r", "", " ", "", "\t", "").Replace(string(encoded))
	raw, err := base64.StdEncoding.DecodeString(clean)
	if err != nil {
		t.Fatalf("decode the fixture: %v", err)
	}
	path := filepath.Join(t.TempDir(), FileName)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write the fixture: %v", err)
	}
	return path
}

// fileSize is the on-disk size, which Status reports after a load.
func fileSize(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return info.Size()
}

// runSQLite runs one statement through the command line tool and returns its
// output without the trailing newline.
func runSQLite(t *testing.T, tool, path, statement string) string {
	t.Helper()
	cmd := exec.Command(tool, path, statement)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s: %v\n%s", statement, err, stderr.String())
	}
	return strings.TrimRight(stdout.String(), "\n")
}
