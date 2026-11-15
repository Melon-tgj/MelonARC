package store

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Defaults.
const (
	// DefaultFlushInterval is how often the retained records are written. It is
	// a compromise: often enough that a crash costs a recent window rather than
	// a day, rare enough that the file rewrite is not a background load.
	DefaultFlushInterval = 30 * time.Second
	// FileName is the database file inside the data directory.
	FileName = "history.sqlite3"
)

// The kinds an event can carry. They are part of the API contract, so they are
// spelled out here rather than at the call sites.
const (
	// KindFailure is a request that could not be carried out: a routing
	// failure or a dial failure, with the category the inbound layer assigned.
	KindFailure = "failure"
	// KindReload is a configuration reload, accepted or refused.
	KindReload = "reload"
	// KindSubscription is a subscription refresh that changed the node list.
	KindSubscription = "subscription"
	// KindPolicy is a manual selection of a policy group.
	KindPolicy = "policy"
)

// Column bounds. Every one of them keeps a row inside a single leaf page; they
// also keep a remote peer from deciding how large a record is.
const (
	maxProtocolLen = 16
	maxNetworkLen  = 8
	maxHostLen     = 255
	maxPolicyLen   = 128
	maxDetailLen   = 240
	maxKindLen     = 32
)

// Retention is how many records each table keeps. The oldest record is dropped
// when a table is full.
//
// The bounds are what make a whole-file rewrite affordable: the cost of a flush
// is proportional to these numbers and to nothing else.
type Retention struct {
	Connections int
	Events      int
	Samples     int
}

// DefaultRetention is the retention a daemon uses when none is configured.
//
// Two thousand connections is roughly a busy hour, five hundred events a couple
// of days of failures and reloads, and a daily set of traffic samples at one a
// minute. They are deliberately small: this is an observation window, not an
// archive, and a file that stays under a megabyte is one a UI can read whole.
var DefaultRetention = Retention{Connections: 2000, Events: 500, Samples: 1440}

// SampleInterval is the spacing the daemon should use between traffic samples.
const SampleInterval = time.Minute

// Connection is one carried connection.
type Connection struct {
	// At is when the connection was accepted.
	At time.Time
	// Protocol is the listener that accepted it: "http", "socks5" or "tun".
	Protocol string
	// Host and Port are the destination the client asked for, as it asked for
	// it: a name stays a name, because that is what a rule matched.
	Host string
	Port int
	// Network is "tcp" or "udp".
	Network string
	// Rule is the rule that classified the destination, empty when none did.
	Rule string
	// Policy is the target the rule named.
	Policy string
	// Outbound is the leaf that finally carried the connection.
	Outbound string
	// Up and Down are the bytes the connection carried.
	Up, Down int64
	// Duration is how long the connection was served.
	Duration time.Duration
}

// Event is one thing that happened to the daemon rather than to a connection.
type Event struct {
	At     time.Time
	Kind   string
	Name   string
	Detail string
	// OK reports whether the event succeeded. A refused reload and a failed
	// subscription refresh are recorded with false, because "it happened" and
	// "it worked" are different questions.
	OK bool
}

// Sample is the traffic one interval carried.
type Sample struct {
	At time.Time
	// Up and Down are the bytes carried during this interval. They are
	// deltas rather than totals, so a reader can draw them as they are and a
	// restart does not look like a negative spike.
	Up, Down int64
}

// Status describes the store for the local API. It carries no record content.
type Status struct {
	Path        string    `json:"path,omitempty"`
	Bytes       int64     `json:"bytes"`
	Connections int       `json:"connections"`
	Events      int       `json:"events"`
	Samples     int       `json:"samples"`
	Capacity    Retention `json:"capacity"`
	Flushes     uint64    `json:"flushes"`
	LastFlush   time.Time `json:"last_flush,omitempty"`
	// LastError is the most recent write failure, empty while writes succeed.
	// The records are still in memory when it is set, so the next flush can
	// still put them on disk.
	LastError string `json:"last_error,omitempty"`
	// Notice explains a history that could not be loaded at startup. A foreign
	// or unreadable file is preserved, so the notice stays for the whole run:
	// a daemon that started on such a file must not report an empty history as
	// normal or quietly adopt it as its own.
	Notice string `json:"notice,omitempty"`
}

// Options configures a Store.
type Options struct {
	// Path is the database file. It is the only required option.
	Path string
	// Logger receives one line per write failure that is new. Nil discards
	// them.
	Logger *slog.Logger
	// Retention bounds the three tables. Zero fields fall back to
	// DefaultRetention.
	Retention Retention
	// FlushInterval is how often the records are written. Zero means
	// DefaultFlushInterval.
	FlushInterval time.Duration
	// Now is the clock, replaced by tests.
	Now func() time.Time
}

// Store is the observation history. Every method is safe for concurrent use.
type Store struct {
	path      string
	logger    *slog.Logger
	retention Retention
	interval  time.Duration
	now       func() time.Time

	mu      sync.Mutex
	conns   []Connection
	events  []Event
	samples []Sample
	status  Status

	// preserved names a history file this build cannot read. It is set once by
	// load, before the flush loop starts, and never cleared: every Flush must
	// refuse to overwrite it. An operator who wants a fresh history moves or
	// deletes that file explicitly; losing an old one silently is not an option.
	preserved error

	// flushMu serialises the file writes. Two flushes must not interleave: the
	// older image would win the rename.
	flushMu sync.Mutex

	stop     chan struct{}
	done     chan struct{}
	closeOne sync.Once
	closeErr error
}

// ErrHistoryPreserved marks a run in which an existing history file this build
// cannot read was left untouched. The store still serves in-memory records, but
// Flush and Close report this error instead of writing over that file.
var ErrHistoryPreserved = errors.New("store: the previous history is preserved and writes are suspended")

// Open creates or loads the database at opts.Path and starts the background
// flush.
//
// A file that does not exist is not an error: the store starts empty and writes
// its first image when it has something to keep. A file that exists but cannot
// be read is not a startup error either — an observation history must not stop
// a daemon — but the original is preserved byte for byte and writes are
// suspended for the whole run. Status.Notice explains why; Flush reports
// ErrHistoryPreserved. An operator starts a fresh history by moving the file.
func Open(opts Options) (*Store, error) {
	if opts.Path == "" {
		return nil, errors.New("store: a database path is required")
	}
	retention := opts.Retention
	if retention.Connections <= 0 {
		retention.Connections = DefaultRetention.Connections
	}
	if retention.Events <= 0 {
		retention.Events = DefaultRetention.Events
	}
	if retention.Samples <= 0 {
		retention.Samples = DefaultRetention.Samples
	}
	interval := opts.FlushInterval
	if interval <= 0 {
		interval = DefaultFlushInterval
	}
	s := &Store{
		path:      opts.Path,
		logger:    loggerOrDiscard(opts.Logger),
		retention: retention,
		interval:  interval,
		now:       opts.Now,
		status:    Status{Path: opts.Path, Capacity: retention},
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
	}
	if s.now == nil {
		s.now = time.Now
	}
	s.load()
	go s.loop()
	return s, nil
}

// loggerOrDiscard returns a logger that swallows everything when l is nil.
func loggerOrDiscard(l *slog.Logger) *slog.Logger {
	if l != nil {
		return l
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// load reads the records a previous run left behind. Any file this build cannot
// decode is preserved: preserving the bytes of an unknown schema or a partly
// written file is the only way a later build, or an operator with the right
// reader, can still recover that history.
func (s *Store) load() {
	image, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		s.preserve(fmt.Errorf("the history file cannot be read: %w", err))
		return
	}
	s.status.Bytes = int64(len(image))
	s.attach(image)
}

// preserve latches the store into a read-only run. It is called from load,
// before the flush loop starts; the lock keeps the write ordered with the reads
// in Flush and Status.
func (s *Store) preserve(reason error) {
	s.mu.Lock()
	s.preserved = reason
	s.status.Notice = fmt.Sprintf(
		"%v; the original file is preserved unchanged and writes are suspended for this run, "+
			"move it aside explicitly to start a fresh history", reason)
	s.mu.Unlock()
	s.logger.Warn("history is preserved, writes are suspended", "path", s.path, "error", reason)
}

// attach decodes an image into the in-memory tables. A file this build does not
// understand is preserved; the tables stay empty but are never written back
// over the original.
func (s *Store) attach(image []byte) {
	db, err := openImage(image)
	if err != nil {
		s.preserve(fmt.Errorf("the history file is not usable: %w", err))
		return
	}
	if db.userVersion != userVersion {
		s.preserve(fmt.Errorf(
			"the history file was written by another version (schema %d, this build writes %d)",
			db.userVersion, userVersion))
		return
	}
	conns, err := readConnections(db)
	if err != nil {
		s.preserve(fmt.Errorf("the connection history cannot be read: %w", err))
		return
	}
	events, err := readEvents(db)
	if err != nil {
		s.preserve(fmt.Errorf("the event history cannot be read: %w", err))
		return
	}
	samples, err := readSamples(db)
	if err != nil {
		s.preserve(fmt.Errorf("the traffic history cannot be read: %w", err))
		return
	}
	s.mu.Lock()
	s.conns, s.events, s.samples = conns, events, samples
	s.mu.Unlock()
}

// Path is the database file.
func (s *Store) Path() string { return s.path }

// RecordConnection keeps one carried connection. It never blocks for longer than
// an append and never reports an error: the connection has already been served.
func (s *Store) RecordConnection(c Connection) {
	if s == nil {
		return
	}
	if c.At.IsZero() {
		c.At = s.now()
	}
	c.Protocol = trim(c.Protocol, maxProtocolLen)
	c.Network = trim(c.Network, maxNetworkLen)
	c.Host = trim(c.Host, maxHostLen)
	c.Rule = trim(c.Rule, maxPolicyLen)
	c.Policy = trim(c.Policy, maxPolicyLen)
	c.Outbound = trim(c.Outbound, maxPolicyLen)
	s.mu.Lock()
	s.conns = appendBounded(s.conns, c, s.retention.Connections)
	s.mu.Unlock()
}

// RecordEvent keeps one event.
func (s *Store) RecordEvent(e Event) {
	if s == nil {
		return
	}
	if e.At.IsZero() {
		e.At = s.now()
	}
	e.Kind = trim(e.Kind, maxKindLen)
	e.Name = trim(e.Name, maxPolicyLen)
	e.Detail = trim(e.Detail, maxDetailLen)
	s.mu.Lock()
	s.events = appendBounded(s.events, e, s.retention.Events)
	s.mu.Unlock()
}

// RecordSample keeps the traffic of one interval.
func (s *Store) RecordSample(sample Sample) {
	if s == nil {
		return
	}
	if sample.At.IsZero() {
		sample.At = s.now()
	}
	s.mu.Lock()
	s.samples = appendBounded(s.samples, sample, s.retention.Samples)
	s.mu.Unlock()
}

// appendBounded appends v and drops the oldest record when the bound is reached.
func appendBounded[T any](list []T, v T, limit int) []T {
	list = append(list, v)
	if over := len(list) - limit; over > 0 {
		list = list[over:]
	}
	return list
}

// Flush writes the retained records to disk.
//
// The whole file is rewritten from the in-memory tables: the tables are bounded,
// so this is a copy of at most a few hundred kilobytes, and it makes the file
// self-consistent without a free list, an incremental b-tree or a journal. A
// failure leaves the previous file untouched and the records in memory.
func (s *Store) Flush() error {
	if s == nil {
		return nil
	}
	s.flushMu.Lock()
	defer s.flushMu.Unlock()

	// A preserved file must never become the empty image of this run. Refuse
	// the write explicitly rather than replacing history that belongs to a
	// build or a format we cannot read.
	if reason := s.preservationReason(); reason != nil {
		err := fmt.Errorf("%w: %v", ErrHistoryPreserved, reason)
		s.fail(err)
		return err
	}

	tables := s.tables()
	image, err := buildImage(tables)
	if err != nil {
		s.fail(err)
		return err
	}
	if err := writeAtomic(s.path, image); err != nil {
		s.fail(err)
		return err
	}
	s.mu.Lock()
	s.status.Bytes = int64(len(image))
	s.status.Flushes++
	s.status.LastFlush = s.now()
	s.status.LastError = ""
	s.status.Notice = ""
	s.mu.Unlock()
	return nil
}

// preservationReason reports why writes are suspended, or nil for a normal run.
// The flag is written once by load, before any goroutine can call Flush.
func (s *Store) preservationReason() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.preserved
}

// fail records a write failure and reports it once.
func (s *Store) fail(err error) {
	s.mu.Lock()
	first := s.status.LastError != err.Error()
	s.status.LastError = err.Error()
	s.mu.Unlock()
	if first {
		// One line per distinct failure: a full disk would otherwise fill the
		// log at the flush interval forever.
		s.logger.Warn("history cannot be written; the records stay in memory",
			"path", s.path, "error", err)
	}
}

// tables renders the in-memory records as the tables of an image.
func (s *Store) tables() []table {
	s.mu.Lock()
	conns := append([]Connection(nil), s.conns...)
	events := append([]Event(nil), s.events...)
	samples := append([]Sample(nil), s.samples...)
	s.mu.Unlock()

	connectionRows := make([][]recordValue, 0, len(conns))
	for _, c := range conns {
		connectionRows = append(connectionRows, []recordValue{
			intValue(c.At.UnixMilli()),
			textValue(c.Protocol),
			textValue(c.Host),
			intValue(int64(c.Port)),
			textValue(c.Network),
			textValue(c.Rule),
			textValue(c.Policy),
			textValue(c.Outbound),
			intValue(c.Up),
			intValue(c.Down),
			intValue(c.Duration.Milliseconds()),
		})
	}
	eventRows := make([][]recordValue, 0, len(events))
	for _, e := range events {
		ok := int64(0)
		if e.OK {
			ok = 1
		}
		eventRows = append(eventRows, []recordValue{
			intValue(e.At.UnixMilli()),
			textValue(e.Kind),
			textValue(e.Name),
			textValue(e.Detail),
			intValue(ok),
		})
	}
	sampleRows := make([][]recordValue, 0, len(samples))
	for _, sample := range samples {
		sampleRows = append(sampleRows, []recordValue{
			intValue(sample.At.UnixMilli()),
			intValue(sample.Up),
			intValue(sample.Down),
		})
	}
	return []table{
		{name: tableConnections, sql: schemaConnections, rows: connectionRows},
		{name: tableEvents, sql: schemaEvents, rows: eventRows},
		{name: tableSamples, sql: schemaSamples, rows: sampleRows},
	}
}

// The table names and schema statements. They are written into sqlite_schema, so
// another reader sees the same column names this package uses.
const (
	tableConnections = "connections"
	tableEvents      = "events"
	tableSamples     = "samples"

	schemaConnections = "CREATE TABLE connections(" +
		"at INTEGER NOT NULL, protocol TEXT NOT NULL, host TEXT NOT NULL, " +
		"port INTEGER NOT NULL, network TEXT NOT NULL, rule TEXT NOT NULL, " +
		"policy TEXT NOT NULL, outbound TEXT NOT NULL, up INTEGER NOT NULL, " +
		"down INTEGER NOT NULL, duration_ms INTEGER NOT NULL)"
	schemaEvents = "CREATE TABLE events(" +
		"at INTEGER NOT NULL, kind TEXT NOT NULL, name TEXT NOT NULL, " +
		"detail TEXT NOT NULL, ok INTEGER NOT NULL)"
	schemaSamples = "CREATE TABLE samples(" +
		"at INTEGER NOT NULL, up INTEGER NOT NULL, down INTEGER NOT NULL)"
)

// readConnections decodes the connections table.
func readConnections(db *database) ([]Connection, error) {
	payloads, err := db.table(tableConnections)
	if err != nil {
		return nil, err
	}
	out := make([]Connection, 0, len(payloads))
	for _, payload := range payloads {
		values, err := decodeRecord(payload)
		if err != nil || len(values) != 11 {
			continue
		}
		out = append(out, Connection{
			At:       time.UnixMilli(values[0].i).UTC(),
			Protocol: values[1].s,
			Host:     values[2].s,
			Port:     int(values[3].i),
			Network:  values[4].s,
			Rule:     values[5].s,
			Policy:   values[6].s,
			Outbound: values[7].s,
			Up:       values[8].i,
			Down:     values[9].i,
			Duration: time.Duration(values[10].i) * time.Millisecond,
		})
	}
	return out, nil
}

// readEvents decodes the events table.
func readEvents(db *database) ([]Event, error) {
	payloads, err := db.table(tableEvents)
	if err != nil {
		return nil, err
	}
	out := make([]Event, 0, len(payloads))
	for _, payload := range payloads {
		values, err := decodeRecord(payload)
		if err != nil || len(values) != 5 {
			continue
		}
		out = append(out, Event{
			At:     time.UnixMilli(values[0].i).UTC(),
			Kind:   values[1].s,
			Name:   values[2].s,
			Detail: values[3].s,
			OK:     values[4].i != 0,
		})
	}
	return out, nil
}

// readSamples decodes the traffic table.
func readSamples(db *database) ([]Sample, error) {
	payloads, err := db.table(tableSamples)
	if err != nil {
		return nil, err
	}
	out := make([]Sample, 0, len(payloads))
	for _, payload := range payloads {
		values, err := decodeRecord(payload)
		if err != nil || len(values) != 3 {
			continue
		}
		out = append(out, Sample{
			At:   time.UnixMilli(values[0].i).UTC(),
			Up:   values[1].i,
			Down: values[2].i,
		})
	}
	return out, nil
}

// Connections returns at most limit connections, oldest first, keeping only the
// ones at or after since when since is not zero.
//
// The limit selects the newest records and the result stays in chronological
// order, which is the same rule the failure endpoint follows: a caller that wants
// a list to show reverses it, and a caller that wants to append to a table does
// not have to.
func (s *Store) Connections(limit int, since time.Time) []Connection {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	out := make([]Connection, 0, len(s.conns))
	for _, c := range s.conns {
		if !since.IsZero() && c.At.Before(since) {
			continue
		}
		out = append(out, c)
	}
	s.mu.Unlock()
	return tail(out, limit)
}

// Events returns at most limit events, oldest first. A non-empty kind keeps only
// that kind, and a non-zero since keeps only the ones at or after it.
func (s *Store) Events(limit int, kind string, since time.Time) []Event {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	out := make([]Event, 0, len(s.events))
	for _, e := range s.events {
		if kind != "" && e.Kind != kind {
			continue
		}
		if !since.IsZero() && e.At.Before(since) {
			continue
		}
		out = append(out, e)
	}
	s.mu.Unlock()
	return tail(out, limit)
}

// Samples returns at most limit traffic samples, oldest first, keeping only the
// ones at or after since when since is not zero.
func (s *Store) Samples(limit int, since time.Time) []Sample {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	out := make([]Sample, 0, len(s.samples))
	for _, sample := range s.samples {
		if !since.IsZero() && sample.At.Before(since) {
			continue
		}
		out = append(out, sample)
	}
	s.mu.Unlock()
	return tail(out, limit)
}

// tail keeps at most limit of the newest records of a chronological list.
func tail[T any](list []T, limit int) []T {
	if limit > 0 && len(list) > limit {
		return list[len(list)-limit:]
	}
	return list
}

// Status returns the store description.
func (s *Store) Status() Status {
	if s == nil {
		return Status{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.status
	out.Connections = len(s.conns)
	out.Events = len(s.events)
	out.Samples = len(s.samples)
	return out
}

// Close stops the background flush and writes what is left.
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	s.closeOne.Do(func() {
		close(s.stop)
		<-s.done
		if err := s.Flush(); err != nil && !errors.Is(err, ErrHistoryPreserved) {
			s.closeErr = fmt.Errorf("store: the last flush failed: %w", err)
		}
	})
	return s.closeErr
}

// loop writes the records on the configured interval until Close.
func (s *Store) loop() {
	defer close(s.done)
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
			// The error is in Status and was logged once by fail; a periodic
			// retry must not produce a line per tick.
			_ = s.Flush()
		}
	}
}

// writeAtomic replaces path with data in one step: a reader sees the previous
// file or the new one, never a half written database. The temporary file lives in
// the same directory so the rename stays on one file system, and it is removed
// when anything fails.
func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("store: create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*")
	if err != nil {
		return fmt.Errorf("store: create a temporary file in %s: %w", dir, err)
	}
	name := tmp.Name()
	cleanup := func(err error) error {
		tmp.Close()
		os.Remove(name)
		return err
	}
	// CreateTemp already uses 0600; the explicit chmod keeps the guarantee from
	// depending on it, and covers a umask applied to the creating process.
	if err := tmp.Chmod(0o600); err != nil {
		return cleanup(fmt.Errorf("store: set the history file permissions: %w", err))
	}
	if _, err := tmp.Write(data); err != nil {
		return cleanup(fmt.Errorf("store: write the history file: %w", err))
	}
	if err := tmp.Sync(); err != nil {
		return cleanup(fmt.Errorf("store: flush the history file: %w", err))
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return fmt.Errorf("store: close the history file: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return fmt.Errorf("store: install %s: %w", path, err)
	}
	return nil
}

// trim shortens a value to at most limit bytes, cutting at a rune boundary so the
// result stays valid UTF-8.
func trim(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	cut := limit
	for cut > 0 && (s[cut]&0xc0) == 0x80 {
		cut--
	}
	return s[:cut]
}
