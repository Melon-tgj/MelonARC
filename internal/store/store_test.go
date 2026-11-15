package store

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// testStore opens a store in a temporary directory with a fixed clock.
func testStore(t *testing.T, opts Options) (*Store, string) {
	t.Helper()
	if opts.Path == "" {
		opts.Path = filepath.Join(t.TempDir(), FileName)
	}
	if opts.FlushInterval == 0 {
		// Long enough that only an explicit Flush writes: a background write
		// would make the assertions depend on timing.
		opts.FlushInterval = time.Hour
	}
	if opts.Now == nil {
		base := time.Date(2026, 11, 14, 9, 0, 0, 0, time.UTC)
		var calls int
		opts.Now = func() time.Time {
			calls++
			return base.Add(time.Duration(calls) * time.Second)
		}
	}
	s, err := Open(opts)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return s, opts.Path
}

// TestStoreWritesAndReloadsHistory is the round trip: what one run recorded, the
// next run reads back, from a file only its owner can read.
func TestStoreWritesAndReloadsHistory(t *testing.T) {
	s, path := testStore(t, Options{})
	at := time.Date(2026, 11, 14, 8, 0, 0, 0, time.UTC)
	s.RecordConnection(Connection{
		At: at, Protocol: "http", Host: "example.com", Port: 443, Network: "tcp",
		Rule: "DOMAIN-SUFFIX,example.com", Policy: "manual", Outbound: "alpha",
		Up: 1200, Down: 34000, Duration: 1500 * time.Millisecond,
	})
	s.RecordConnection(Connection{
		At: at.Add(time.Second), Protocol: "socks5", Host: "198.51.100.7", Port: 53,
		Network: "udp", Policy: "auto", Outbound: "DIRECT", Down: 90,
	})
	s.RecordEvent(Event{At: at, Kind: KindReload, Name: "/etc/melonarc.ini", Detail: "3 rules", OK: true})
	s.RecordEvent(Event{At: at, Kind: KindFailure, Name: "alpha", Detail: "dial_timeout", OK: false})
	s.RecordSample(Sample{At: at, Up: 4000, Down: 90000})
	if err := s.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if runtime.GOOS != "windows" {
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Errorf("history file mode = %o, want 600", mode)
		}
	}
	if info.Size() == 0 {
		t.Fatal("the history file is empty")
	}

	// A second run, as a restart would.
	reopened, err := Open(Options{Path: path, FlushInterval: time.Hour})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer reopened.Close()
	conns := reopened.Connections(0, time.Time{})
	if len(conns) != 2 {
		t.Fatalf("reloaded %d connections, want 2: %+v", len(conns), conns)
	}
	want := Connection{
		At: at, Protocol: "http", Host: "example.com", Port: 443, Network: "tcp",
		Rule: "DOMAIN-SUFFIX,example.com", Policy: "manual", Outbound: "alpha",
		Up: 1200, Down: 34000, Duration: 1500 * time.Millisecond,
	}
	if conns[0] != want {
		t.Errorf("first connection = %+v, want %+v", conns[0], want)
	}
	if conns[1].Host != "198.51.100.7" || conns[1].Down != 90 {
		t.Errorf("second connection = %+v", conns[1])
	}
	events := reopened.Events(0, "", time.Time{})
	if len(events) != 2 || events[0].Kind != KindReload || !events[0].OK {
		t.Fatalf("reloaded events = %+v", events)
	}
	if events[1].Kind != KindFailure || events[1].OK {
		t.Errorf("the failed event lost its outcome: %+v", events[1])
	}
	samples := reopened.Samples(0, time.Time{})
	if len(samples) != 1 || samples[0].Up != 4000 || samples[0].Down != 90000 {
		t.Fatalf("reloaded samples = %+v", samples)
	}
	if status := reopened.Status(); status.Bytes == 0 || status.Connections != 2 || status.Notice != "" {
		t.Errorf("status = %+v", status)
	}
}

// TestStoreBoundsWhatItKeeps checks the retention rule: the oldest record is the
// one that goes, and the count never exceeds the bound.
func TestStoreBoundsWhatItKeeps(t *testing.T) {
	s, _ := testStore(t, Options{Retention: Retention{Connections: 2, Events: 1, Samples: 2}})
	base := time.Date(2026, 11, 14, 8, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		s.RecordConnection(Connection{At: base.Add(time.Duration(i) * time.Second), Host: string(rune('a' + i))})
		s.RecordEvent(Event{At: base, Kind: KindReload, Name: string(rune('a' + i))})
		s.RecordSample(Sample{At: base.Add(time.Duration(i) * time.Minute), Up: int64(i)})
	}
	conns := s.Connections(0, time.Time{})
	if len(conns) != 2 {
		t.Fatalf("kept %d connections, want 2", len(conns))
	}
	if conns[0].Host != "d" || conns[1].Host != "e" {
		t.Errorf("kept %q and %q, want the two newest", conns[0].Host, conns[1].Host)
	}
	if events := s.Events(0, "", time.Time{}); len(events) != 1 || events[0].Name != "e" {
		t.Errorf("events = %+v, want only the newest", events)
	}
	if samples := s.Samples(0, time.Time{}); len(samples) != 2 || samples[1].Up != 4 {
		t.Errorf("samples = %+v", samples)
	}
	// A limit narrower than the retention window still selects the newest.
	if conns := s.Connections(1, time.Time{}); len(conns) != 1 || conns[0].Host != "e" {
		t.Errorf("Connections(1) = %+v", conns)
	}
}

// TestStoreDefaultsBoundTheTables pins the capacities a daemon gets when it
// configures none, and the eviction rule at those capacities rather than at a
// convenient small one: the oldest record of each table is the one that goes.
func TestStoreDefaultsBoundTheTables(t *testing.T) {
	s, _ := testStore(t, Options{})
	base := time.Date(2026, 11, 14, 8, 0, 0, 0, time.UTC)
	connTotal := DefaultRetention.Connections + 5
	for i := 0; i < connTotal; i++ {
		s.RecordConnection(Connection{At: base.Add(time.Duration(i) * time.Second), Host: fmt.Sprintf("h%04d", i)})
	}
	eventTotal := DefaultRetention.Events + 5
	for i := 0; i < eventTotal; i++ {
		s.RecordEvent(Event{At: base, Kind: KindReload, Name: fmt.Sprintf("e%04d", i)})
	}
	sampleTotal := DefaultRetention.Samples + 5
	for i := 0; i < sampleTotal; i++ {
		s.RecordSample(Sample{At: base.Add(time.Duration(i) * time.Minute), Up: int64(i)})
	}

	conns := s.Connections(0, time.Time{})
	if len(conns) != DefaultRetention.Connections {
		t.Fatalf("kept %d connections, want %d", len(conns), DefaultRetention.Connections)
	}
	if conns[0].Host != "h0005" || conns[len(conns)-1].Host != fmt.Sprintf("h%04d", connTotal-1) {
		t.Errorf("kept %q..%q, want the newest %d", conns[0].Host, conns[len(conns)-1].Host, len(conns))
	}
	events := s.Events(0, "", time.Time{})
	if len(events) != DefaultRetention.Events {
		t.Fatalf("kept %d events, want %d", len(events), DefaultRetention.Events)
	}
	if events[0].Name != "e0005" || events[len(events)-1].Name != fmt.Sprintf("e%04d", eventTotal-1) {
		t.Errorf("kept %q..%q", events[0].Name, events[len(events)-1].Name)
	}
	samples := s.Samples(0, time.Time{})
	if len(samples) != DefaultRetention.Samples {
		t.Fatalf("kept %d samples, want %d", len(samples), DefaultRetention.Samples)
	}
	if samples[0].Up != 5 || samples[len(samples)-1].Up != int64(sampleTotal-1) {
		t.Errorf("kept samples %d..%d", samples[0].Up, samples[len(samples)-1].Up)
	}
	// The capacities are part of the file's documented shape, not an internal
	// choice: a reader is told how much history to expect.
	if DefaultRetention != (Retention{Connections: 2000, Events: 500, Samples: 1440}) {
		t.Errorf("DefaultRetention = %+v", DefaultRetention)
	}
	if DefaultFlushInterval != 30*time.Second || SampleInterval != time.Minute {
		t.Errorf("flush interval = %v, sample interval = %v", DefaultFlushInterval, SampleInterval)
	}
}

// TestStoreFlushesWithoutBeingTold covers the background beat: the records
// reach the file on the interval alone, with no explicit Flush anywhere. The
// daemon relies on this for everything it never gets to write at shutdown.
func TestStoreFlushesWithoutBeingTold(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	s, err := Open(Options{Path: path, FlushInterval: 5 * time.Millisecond})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	s.RecordEvent(Event{At: time.Date(2026, 11, 14, 8, 0, 0, 0, time.UTC), Kind: KindReload, OK: true})

	deadline := time.Now().Add(10 * time.Second)
	for s.Status().Flushes == 0 {
		if time.Now().After(deadline) {
			s.Close()
			t.Fatal("the background beat never wrote the file")
		}
		time.Sleep(time.Millisecond)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := Open(Options{Path: path, FlushInterval: time.Hour})
	if err != nil {
		t.Fatalf("Open again: %v", err)
	}
	defer reopened.Close()
	if events := reopened.Events(0, "", time.Time{}); len(events) != 1 {
		t.Fatalf("the beat wrote %d events, want 1", len(events))
	}
}

// TestStoreFiltersConnections covers the query filters the API exposes: a kind,
// a lower bound and a limit, on all three tables.
func TestStoreFiltersConnections(t *testing.T) {
	s, _ := testStore(t, Options{})
	base := time.Date(2026, 11, 14, 8, 0, 0, 0, time.UTC)
	for i := 0; i < 4; i++ {
		s.RecordConnection(Connection{At: base.Add(time.Duration(i) * time.Minute), Host: "h"})
	}
	since := base.Add(2 * time.Minute)
	got := s.Connections(0, since)
	if len(got) != 2 {
		t.Fatalf("since filtered to %d connections, want 2", len(got))
	}
	if got[0].At.Before(since) {
		t.Errorf("a connection older than the cutoff was returned: %v", got[0].At)
	}

	s.RecordEvent(Event{At: base, Kind: KindFailure})
	s.RecordEvent(Event{At: base, Kind: KindReload})
	s.RecordEvent(Event{At: base, Kind: KindFailure})
	if events := s.Events(0, KindFailure, time.Time{}); len(events) != 2 {
		t.Errorf("kind filter returned %d events, want 2", len(events))
	}
	if events := s.Events(0, "nonsense", time.Time{}); len(events) != 0 {
		t.Errorf("an unknown kind returned %d events", len(events))
	}

	// The lower bound applies to the events the same way: a record exactly at
	// the cutoff is kept, and one minute later nothing is.
	if events := s.Events(0, "", base); len(events) != 3 {
		t.Errorf("since at the oldest event returned %d, want all 3", len(events))
	}
	if events := s.Events(0, "", base.Add(time.Minute)); len(events) != 0 {
		t.Errorf("since one minute in returned %d events, want none", len(events))
	}
	// The samples carry their own times, so the bound splits them.
	for i := 0; i < 3; i++ {
		s.RecordSample(Sample{At: base.Add(time.Duration(i) * time.Minute), Up: int64(i + 1)})
	}
	samples := s.Samples(0, base.Add(time.Minute))
	if len(samples) != 2 {
		t.Fatalf("since one minute in returned %d samples, want 2", len(samples))
	}
	if samples[0].Up != 2 || samples[1].Up != 3 {
		t.Errorf("samples = %+v, want the ones at or after the cutoff", samples)
	}
	// A limit keeps the newest of the window, which is what "the last few"
	// means to a reader of a series.
	if tail := s.Samples(1, time.Time{}); len(tail) != 1 || tail[0].Up != 3 {
		t.Errorf("limit 1 returned %+v, want the newest sample", tail)
	}
}

// TestStoreSurvivesAWriteFailure is the property the daemon depends on: a history
// that cannot be written leaves the records readable and reports the problem, and
// the caller never sees an error on the recording path.
func TestStoreSurvivesAWriteFailure(t *testing.T) {
	// The parent of the database is a regular file, so creating the directory
	// fails for any user — including a test run as root.
	blocked := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocked, []byte("x"), 0o600); err != nil {
		t.Fatalf("write the blocking file: %v", err)
	}
	s, err := Open(Options{Path: filepath.Join(blocked, FileName), FlushInterval: time.Hour})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	base := time.Date(2026, 11, 14, 8, 0, 0, 0, time.UTC)
	s.RecordConnection(Connection{At: base, Host: "example.com"})
	if err := s.Flush(); err == nil {
		t.Fatal("Flush succeeded although the path cannot be created")
	}
	status := s.Status()
	if status.LastError == "" {
		t.Error("a failed write left no error in the status")
	}
	if status.Connections != 1 {
		t.Errorf("the record was lost with the failed write: %+v", status)
	}
	if conns := s.Connections(0, time.Time{}); len(conns) != 1 {
		t.Errorf("the record is not queryable after a failed write")
	}
}

// TestStoreRetriesAFailedWrite is the other half of "the records stay in
// memory": a write that failed is attempted again by the next flush, and the
// retry puts the records the failed one could not. The failure is made by
// closing the handle underneath the store, because a full disk and a revoked
// permission are not failures a test can provoke deterministically.
func TestStoreRetriesAFailedWrite(t *testing.T) {
	s, path := testStore(t, Options{})
	at := time.Date(2026, 11, 14, 8, 0, 0, 0, time.UTC)
	s.RecordConnection(Connection{At: at, Host: "example.com", Up: 1})

	s.flushMu.Lock()
	broken := s.db
	s.flushMu.Unlock()
	if err := broken.Close(); err != nil {
		t.Fatalf("close the handle: %v", err)
	}
	// The handle is still installed and no longer usable, which is what a write
	// failure looks like from inside Flush.
	if err := s.Flush(); err == nil {
		t.Fatal("a flush through a closed handle succeeded")
	}
	if status := s.Status(); status.LastError == "" || status.Connections != 1 {
		t.Fatalf("status after a failed write = %+v", status)
	}
	if conns := s.Connections(0, time.Time{}); len(conns) != 1 {
		t.Fatalf("the record did not survive the failed write")
	}

	db, err := openWritable(path)
	if err != nil {
		t.Fatalf("open the file again: %v", err)
	}
	s.flushMu.Lock()
	s.db = db
	s.flushMu.Unlock()
	if err := s.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if status := s.Status(); status.Flushes != 1 || status.LastError != "" {
		t.Errorf("status after a successful retry = %+v", status)
	}

	reopened, err := Open(Options{Path: path, FlushInterval: time.Hour})
	if err != nil {
		t.Fatalf("Open again: %v", err)
	}
	defer reopened.Close()
	if conns := reopened.Connections(0, time.Time{}); len(conns) != 1 || conns[0].Host != "example.com" {
		t.Fatalf("the retried write left %+v", conns)
	}
}

// TestStorePreservesACorruptFile is the review regression: a file this build
// cannot decode must survive byte for byte. The old behaviour continued with
// empty tables and overwrote the original on the next flush, losing history
// that another reader might still have been able to recover.
func TestStorePreservesACorruptFile(t *testing.T) {
	original := []byte("this is not a database, but it is long enough")
	path := filepath.Join(t.TempDir(), FileName)
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatalf("write the corrupt file: %v", err)
	}
	s, err := Open(Options{Path: path, FlushInterval: time.Hour})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if status := s.Status(); !strings.Contains(status.Notice, "not usable") || !strings.Contains(status.Notice, "preserved") {
		t.Fatalf("a corrupt file was accepted silently: %+v", status)
	}
	if conns := s.Connections(0, time.Time{}); len(conns) != 0 {
		t.Errorf("a corrupt file produced %d connections", len(conns))
	}

	// Records are still served from memory, but no write may replace the file.
	s.RecordConnection(Connection{At: time.Now(), Host: "example.com"})
	if err := s.Flush(); !errors.Is(err, ErrHistoryPreserved) {
		t.Fatalf("Flush = %v, want ErrHistoryPreserved", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close reported a preservation refusal as a shutdown failure: %v", err)
	}
	assertUnchanged(t, path, original)

	// A restart reaches the same decision; it must not quietly adopt the file.
	reopened, err := Open(Options{Path: path, FlushInterval: time.Hour})
	if err != nil {
		t.Fatalf("Open again: %v", err)
	}
	if err := reopened.Flush(); !errors.Is(err, ErrHistoryPreserved) {
		t.Errorf("the second run tried to write: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Errorf("Close again: %v", err)
	}
	assertUnchanged(t, path, original)
	assertNoSidecars(t, path)
}

// TestStorePreservesAFileFromAnotherVersion builds a real history file with
// this build, then moves only the user_version field in the header one schema
// ahead. The layout is the one this build writes, so this is the "known layout,
// unknown schema" case rather than a corrupt file.
func TestStorePreservesAFileFromAnotherVersion(t *testing.T) {
	path, original := historyFileFromAFutureSchema(t)

	s, err := Open(Options{Path: path, FlushInterval: time.Hour})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	status := s.Status()
	if !strings.Contains(status.Notice, "another version") || !strings.Contains(status.Notice, "preserved") {
		t.Fatalf("a foreign schema was accepted silently: %+v", status)
	}
	s.RecordEvent(Event{At: time.Now(), Kind: KindReload, OK: true})
	if err := s.Flush(); !errors.Is(err, ErrHistoryPreserved) {
		t.Fatalf("Flush = %v, want ErrHistoryPreserved", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	assertUnchanged(t, path, original)
	assertNoSidecars(t, path)
}

// TestStorePreservesATruncatedFile is the other half of "a file this build
// cannot read": a file whose 100 byte header is genuine and whose body stops in
// the middle of a page. It has to be refused the same way as a file that is not
// a database at all — refused, not repaired.
func TestStorePreservesATruncatedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	seed, err := Open(Options{Path: path, FlushInterval: time.Hour})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	base := time.Date(2026, 11, 14, 8, 0, 0, 0, time.UTC)
	for i := 0; i < 500; i++ {
		seed.RecordConnection(Connection{At: base.Add(time.Duration(i) * time.Second), Host: "example.com"})
	}
	if err := seed.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if err := seed.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Half a page: the header still says 4096 byte pages, so every read past it
	// runs off the end of the file.
	if err := os.Truncate(path, 2048); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the truncated file: %v", err)
	}

	s, err := Open(Options{Path: path, FlushInterval: time.Hour})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if status := s.Status(); !strings.Contains(status.Notice, "preserved") {
		t.Fatalf("a truncated file was accepted: %+v", status)
	}
	if conns := s.Connections(0, time.Time{}); len(conns) != 0 {
		t.Errorf("a truncated file produced %d connections", len(conns))
	}
	s.RecordConnection(Connection{At: time.Now(), Host: "example.com"})
	if err := s.Flush(); !errors.Is(err, ErrHistoryPreserved) {
		t.Fatalf("Flush = %v, want ErrHistoryPreserved", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	assertUnchanged(t, path, original)
	assertNoSidecars(t, path)
}

// TestStorePreservesAFileWithAColumnItCannotRead is the boundary case between
// "corrupt" and "another version": a file whose header, schema and row count
// are all fine and whose values are not the types this build reads. SQLite
// stores such a value happily, so the check has to happen in the reader, and
// the answer has to be the same as everywhere else on this path — refuse, do
// not rewrite, do not drop the row the flush would have skipped.
func TestStorePreservesAFileWithAColumnItCannotRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	seed, err := Open(Options{Path: path, FlushInterval: time.Hour})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	seed.RecordConnection(Connection{At: time.Date(2026, 11, 14, 8, 0, 0, 0, time.UTC), Host: "example.com", Up: 1})
	if err := seed.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if err := seed.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Only a writer older than this one, or a tool outside this package, can
	// put a text value in an integer column; that is the case being covered.
	db, err := openWritable(path)
	if err != nil {
		t.Fatalf("open for the edit: %v", err)
	}
	if _, err := db.Exec("UPDATE connections SET up = 'not a number' WHERE rowid = 1"); err != nil {
		t.Fatalf("confuse the column: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close after the edit: %v", err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the edited file: %v", err)
	}

	s, err := Open(Options{Path: path, FlushInterval: time.Hour})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	status := s.Status()
	if !strings.Contains(status.Notice, "cannot be read") || !strings.Contains(status.Notice, "preserved") {
		t.Fatalf("a file with an unreadable column was accepted: %+v", status)
	}
	if err := s.Flush(); !errors.Is(err, ErrHistoryPreserved) {
		t.Fatalf("Flush = %v, want ErrHistoryPreserved", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	assertUnchanged(t, path, original)
	assertNoSidecars(t, path)
}

// historyFileFromAFutureSchema writes a history file this build made, one
// connection deep, and then edits the schema version in its header.
func historyFileFromAFutureSchema(t *testing.T) (path string, original []byte) {
	t.Helper()
	path = filepath.Join(t.TempDir(), FileName)
	seed, err := Open(Options{Path: path, FlushInterval: time.Hour})
	if err != nil {
		t.Fatalf("Open the seed: %v", err)
	}
	seed.RecordConnection(Connection{At: time.Date(2026, 11, 14, 8, 0, 0, 0, time.UTC), Host: "example.com"})
	if err := seed.Flush(); err != nil {
		t.Fatalf("Flush the seed: %v", err)
	}
	if err := seed.Close(); err != nil {
		t.Fatalf("Close the seed: %v", err)
	}

	original, err = os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the seed: %v", err)
	}
	// The schema version lives at offset 60 of the header, four bytes big
	// endian; every other byte stays as the engine wrote it.
	if got := binary.BigEndian.Uint32(original[60:64]); got != userVersion {
		t.Fatalf("the seed does not start at schema %d but at %d", userVersion, got)
	}
	binary.BigEndian.PutUint32(original[60:64], userVersion+1)
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatalf("write the future-version file: %v", err)
	}
	return path, original
}

// assertUnchanged is the assertion the whole fix exists for: the bytes on disk
// are exactly the bytes the operator's previous build left behind.
func assertUnchanged(t *testing.T, path string, original []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("the history file changed: %d bytes on disk, %d originally", len(got), len(original))
	}
}

// assertNoSidecars checks that the inspection of a file this build cannot read
// left nothing beside it. A rollback journal, a write-ahead log or its index
// next to a preserved file would be a write to that file's directory, and a
// write is the one thing the preservation path must not do.
func assertNoSidecars(t *testing.T, path string) {
	t.Helper()
	for _, suffix := range []string{"-journal", "-wal", "-shm"} {
		switch _, err := os.Stat(path + suffix); {
		case err == nil:
			t.Errorf("the preservation path left a %s file behind", suffix)
		case !errors.Is(err, fs.ErrNotExist):
			t.Errorf("stat %s: %v", path+suffix, err)
		}
	}
}

// TestStoreTrimsWhatItCannotStore keeps a remote peer from deciding how large a
// record is, and keeps every stored string valid UTF-8 so a reader can print it.
func TestStoreTrimsWhatItCannotStore(t *testing.T) {
	s, _ := testStore(t, Options{})
	long := strings.Repeat("a", 400) + strings.Repeat("é", 200)
	s.RecordConnection(Connection{Host: long, Protocol: strings.Repeat("p", 40), Rule: long, Policy: long})
	s.RecordEvent(Event{Kind: strings.Repeat("k", 40), Detail: long})
	conn := s.Connections(0, time.Time{})[0]
	if len(conn.Host) > maxHostLen {
		t.Errorf("host is %d bytes, want at most %d", len(conn.Host), maxHostLen)
	}
	if !utf8.ValidString(conn.Host) {
		t.Error("a trimmed value is not valid UTF-8")
	}
	if len(conn.Protocol) > maxProtocolLen {
		t.Errorf("protocol is %d bytes", len(conn.Protocol))
	}
	event := s.Events(0, "", time.Time{})[0]
	if len(event.Detail) > maxDetailLen || !utf8.ValidString(event.Detail) {
		t.Errorf("detail is %d bytes", len(event.Detail))
	}
}

// TestStoreCloseWritesWhatIsLeft checks the shutdown contract: the last records of
// a run reach the file without an explicit Flush.
func TestStoreCloseWritesWhatIsLeft(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	s, err := Open(Options{Path: path, FlushInterval: time.Hour})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	s.RecordEvent(Event{At: time.Now(), Kind: KindReload, OK: true})
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Closing twice is safe and keeps the first result.
	if err := s.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	reopened, err := Open(Options{Path: path, FlushInterval: time.Hour})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer reopened.Close()
	if events := reopened.Events(0, "", time.Time{}); len(events) != 1 {
		t.Fatalf("the last event was not written on close: %d events", len(events))
	}
}

// TestNilStoreIsUsable guards the call sites that hold an optional store: a nil one
// records nothing and answers empty, so the daemon needs no nil checks.
func TestNilStoreIsUsable(t *testing.T) {
	var s *Store
	s.RecordConnection(Connection{Host: "example.com"})
	s.RecordEvent(Event{Kind: KindReload})
	s.RecordSample(Sample{Up: 1})
	if err := s.Flush(); err != nil {
		t.Errorf("nil Flush: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("nil Close: %v", err)
	}
	if got := s.Connections(0, time.Time{}); got != nil {
		t.Errorf("nil Connections = %v", got)
	}
	if got := s.Status(); got != (Status{}) {
		t.Errorf("nil Status = %+v", got)
	}
}
