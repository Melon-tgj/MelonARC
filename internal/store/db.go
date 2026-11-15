package store

// The database layer: one ordinary SQLite file, read and written through
// database/sql and the pure-Go driver modernc.org/sqlite.
//
// Why a driver now: the previous build rendered and parsed the SQLite file
// format itself, because the module proxy was unreachable and a cgo binding
// would have ended the single static binary. Both constraints are gone — the
// driver is pure Go and cross-builds for Windows — and a hand-written b-tree
// writer is not something to keep maintaining when the observation layer is
// the only user.
//
// What does not change is the contract:
//   - the file stays an ordinary SQLite database with the same three tables,
//     the same columns and the schema version 1 the previous build wrote, so a
//     file written before this change is read and then written by this build;
//   - a file this build cannot read is never written: it is inspected through
//     a read-only connection and, if anything is off, left byte for byte alone
//     (see Store.preserve);
//   - the in-memory tables stay the source of truth, so a failed write leaves
//     the records readable and the next flush retries them.

import (
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// userVersion identifies the schema this package writes. It is stored in the
// database header, so a build can notice a file it does not understand instead
// of decoding the rows of another layout.
const userVersion = 1

// driverName is the name modernc.org/sqlite registers with database/sql.
const driverName = "sqlite"

// The table names. They are part of the contract: another reader sees them.
const (
	tableConnections = "connections"
	tableEvents      = "events"
	tableSamples     = "samples"
)

// columnDef is one column this build writes. Every column is NOT NULL: an
// empty value is stored as an empty string or a zero, never as NULL, so a
// reader never needs a null branch.
type columnDef struct {
	name    string
	typ     string
	notNull bool
}

// tableDef is one table: its name, its columns in order, and nothing else — no
// indexes, no primary key, no constraints. The previous build wrote exactly
// this layout, so the definitions below also describe the files it left behind.
type tableDef struct {
	name    string
	columns []columnDef
}

func cols(pairs ...string) []columnDef {
	out := make([]columnDef, 0, len(pairs)/2)
	for i := 0; i+1 < len(pairs); i += 2 {
		out = append(out, columnDef{name: pairs[i], typ: pairs[i+1], notNull: true})
	}
	return out
}

var tableDefs = []tableDef{
	{tableConnections, cols(
		"at", "INTEGER", "protocol", "TEXT", "host", "TEXT", "port", "INTEGER",
		"network", "TEXT", "rule", "TEXT", "policy", "TEXT", "outbound", "TEXT",
		"up", "INTEGER", "down", "INTEGER", "duration_ms", "INTEGER",
	)},
	{tableEvents, cols(
		"at", "INTEGER", "kind", "TEXT", "name", "TEXT", "detail", "TEXT", "ok", "INTEGER",
	)},
	{tableSamples, cols(
		"at", "INTEGER", "up", "INTEGER", "down", "INTEGER",
	)},
}

// createSQL renders the statement that creates the table. It is the same text
// the previous build wrote into sqlite_schema, so an old file and a new one
// differ only in what the engine put around it.
func (t tableDef) createSQL() string {
	parts := make([]string, len(t.columns))
	for i, c := range t.columns {
		parts[i] = c.name + " " + c.typ
		if c.notNull {
			parts[i] += " NOT NULL"
		}
	}
	return "CREATE TABLE " + t.name + "(" + strings.Join(parts, ", ") + ")"
}

// fileURI builds the DSN. The "file:" form is required for the parameters
// SQLite itself interprets (mode=ro); the driver's own parameters are the
// underscore-prefixed ones. Percent-encoding matters: a path may contain a '?'
// or a '#'.
func fileURI(path string, params url.Values) string {
	p := filepath.ToSlash(path)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	u := url.URL{Scheme: "file", Path: p, RawQuery: params.Encode()}
	return u.String()
}

// openReadOnly opens path for inspection. mode=ro makes SQLite fail instead of
// creating a missing file and makes every write fail with SQLITE_READONLY, so
// no statement in the validation path can touch the bytes on disk.
func openReadOnly(path string) (*sql.DB, error) {
	params := url.Values{}
	params.Set("mode", "ro")
	params.Set("_query_only", "1")
	params.Set("_busy_timeout", "5000")
	db, err := sql.Open(driverName, fileURI(path, params))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// openWritable opens path for the flush path. It is only ever called on a file
// that validated: it creates the file when it is missing and it writes the
// header (journal mode), which is exactly what must not happen to a file this
// build cannot read.
func openWritable(path string) (*sql.DB, error) {
	params := url.Values{}
	params.Set("_busy_timeout", "5000")
	// Keep one self-contained file rather than a WAL pair: the history is a
	// side channel, and a single file is what an operator copies or deletes.
	params.Set("_journal_mode", "delete")
	// A committed flush must survive a power cut, the same promise the old
	// temp-file-and-rename made.
	params.Set("_synchronous", "full")
	// Take the write lock when the transaction begins, not on the first
	// statement, so two writers queue instead of one failing on upgrade.
	params.Set("_txlock", "immediate")
	db, err := sql.Open(driverName, fileURI(path, params))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// create makes a new history file: the file itself first, with the mode this
// package promises, then the schema and the version in one transaction.
func (s *Store) create() error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("store: create %s: %w", dir, err)
	}
	// Create the file here rather than letting the driver do it: the driver
	// applies the process umask (0644 with the usual one), and a history file
	// must not be readable by anyone else even for the moment before the first
	// flush. O_EXCL also keeps two starts from both initialising the schema.
	f, err := os.OpenFile(s.path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	switch {
	case err == nil:
		if cerr := f.Close(); cerr != nil {
			return fmt.Errorf("store: create %s: %w", s.path, cerr)
		}
	case errors.Is(err, fs.ErrExist):
		// Someone created it between the stat and now; treat it as existing.
	default:
		return fmt.Errorf("store: create %s: %w", s.path, err)
	}

	db, err := openWritable(s.path)
	if err != nil {
		return fmt.Errorf("store: open %s: %w", s.path, err)
	}
	if err := initSchema(db); err != nil {
		db.Close()
		s.removeHalfMadeFile()
		return err
	}
	s.db = db
	return nil
}

// initSchema writes the three tables and the schema version. Both happen in one
// transaction: a crash leaves either an empty file (which the next start
// initialises) or a complete schema, never half of it.
func initSchema(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("store: begin the schema: %w", err)
	}
	defer tx.Rollback()
	for _, t := range tableDefs {
		if _, err := tx.Exec(t.createSQL()); err != nil {
			return fmt.Errorf("store: create the table %s: %w", t.name, err)
		}
	}
	if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", userVersion)); err != nil {
		return fmt.Errorf("store: set the schema version: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit the schema: %w", err)
	}
	return nil
}

// removeHalfMadeFile drops a file this run created but could not initialise.
// It is the one file the store is allowed to delete: it did not exist before
// this run, so there is no history in it to preserve.
func (s *Store) removeHalfMadeFile() {
	if err := os.Remove(s.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		s.logger.Warn("a half initialised history file was left in place", "path", s.path, "error", err)
	}
}

// adopt validates an existing file through a read-only connection, reads it,
// and only then opens it for writing.
func (s *Store) adopt() error {
	ro, err := openReadOnly(s.path)
	if err != nil {
		return fmt.Errorf("the history file is not usable: %w", err)
	}
	defer ro.Close()

	version, err := userVersionOf(ro)
	if err != nil {
		return fmt.Errorf("the history file is not usable: %w", err)
	}
	if version != userVersion {
		return fmt.Errorf(
			"the history file was written by another version (schema %d, this build writes %d)",
			version, userVersion)
	}
	if err := checkSchema(ro); err != nil {
		return fmt.Errorf("the history file is not usable: %w", err)
	}
	conns, err := readConnections(ro)
	if err != nil {
		return fmt.Errorf("the connection history cannot be read: %w", err)
	}
	events, err := readEvents(ro)
	if err != nil {
		return fmt.Errorf("the event history cannot be read: %w", err)
	}
	samples, err := readSamples(ro)
	if err != nil {
		return fmt.Errorf("the traffic history cannot be read: %w", err)
	}
	if err := ro.Close(); err != nil {
		return fmt.Errorf("the history file cannot be read: %w", err)
	}

	db, err := openWritable(s.path)
	if err != nil {
		return fmt.Errorf("the history file cannot be opened for writing: %w", err)
	}
	// The file is ours from here on; make sure only its owner can read it. A
	// wider mode is reported rather than fatal: refusing to record anything
	// because a chmod failed would be worse than the log line.
	if info, err := os.Stat(s.path); err == nil && info.Mode().Perm() != 0o600 {
		if err := os.Chmod(s.path, 0o600); err != nil {
			s.logger.Warn("the history file is readable by others and cannot be tightened",
				"path", s.path, "mode", info.Mode().Perm(), "error", err)
		}
	}
	s.db = db
	s.mu.Lock()
	s.conns, s.events, s.samples = conns, events, samples
	s.mu.Unlock()
	return nil
}

// userVersionOf reads PRAGMA user_version.
func userVersionOf(db *sql.DB) (int, error) {
	var v int
	if err := db.QueryRow("PRAGMA user_version").Scan(&v); err != nil {
		return 0, err
	}
	return v, nil
}

// checkSchema compares the tables on disk with the ones this build writes. A
// table that is missing, or whose columns differ in name, type, order or
// nullability, is not something this build can append to without guessing.
func checkSchema(db *sql.DB) error {
	for _, t := range tableDefs {
		got, err := columnsOf(db, t.name)
		if err != nil {
			return err
		}
		if len(got) == 0 {
			return fmt.Errorf("the table %s is missing", t.name)
		}
		if len(got) != len(t.columns) {
			return fmt.Errorf("the table %s has %d columns, this build writes %d",
				t.name, len(got), len(t.columns))
		}
		for i := range got {
			want := t.columns[i]
			if got[i].name != want.name || got[i].typ != want.typ || got[i].notNull != want.notNull {
				return fmt.Errorf("the table %s column %d is %s %s, this build writes %s %s",
					t.name, i+1, got[i].name, got[i].typ, want.name, want.typ)
			}
		}
	}
	return nil
}

// columnsOf reads PRAGMA table_info for one table. The table name is a
// constant of this package, never user input.
func columnsOf(db *sql.DB, table string) ([]columnDef, error) {
	rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%q)", table))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []columnDef
	for rows.Next() {
		var (
			cid     int
			name    string
			typ     string
			notNull int
			dflt    sql.NullString
			pk      int
		)
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk); err != nil {
			return nil, err
		}
		out = append(out, columnDef{name: name, typ: strings.ToUpper(typ), notNull: notNull != 0})
	}
	return out, rows.Err()
}

// writeTables replaces the contents of the three tables in one transaction. The
// in-memory tables are bounded, so this is a copy of at most a few thousand
// rows; doing it in one transaction means a reader sees the previous flush or
// the new one, never a half-written history.
func writeTables(db *sql.DB, conns []Connection, events []Event, samples []Sample) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("store: begin a flush: %w", err)
	}
	defer tx.Rollback()

	for _, t := range tableDefs {
		if _, err := tx.Exec("DELETE FROM " + t.name); err != nil {
			return fmt.Errorf("store: clear the table %s: %w", t.name, err)
		}
	}
	insertConnection, err := tx.Prepare(
		"INSERT INTO connections(at, protocol, host, port, network, rule, policy, outbound, up, down, duration_ms) " +
			"VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		return fmt.Errorf("store: prepare the connection insert: %w", err)
	}
	defer insertConnection.Close()
	for _, c := range conns {
		if _, err := insertConnection.Exec(
			c.At.UnixMilli(), c.Protocol, c.Host, c.Port, c.Network, c.Rule, c.Policy,
			c.Outbound, c.Up, c.Down, c.Duration.Milliseconds(),
		); err != nil {
			return fmt.Errorf("store: write a connection: %w", err)
		}
	}
	insertEvent, err := tx.Prepare(
		"INSERT INTO events(at, kind, name, detail, ok) VALUES(?, ?, ?, ?, ?)")
	if err != nil {
		return fmt.Errorf("store: prepare the event insert: %w", err)
	}
	defer insertEvent.Close()
	for _, e := range events {
		ok := int64(0)
		if e.OK {
			ok = 1
		}
		if _, err := insertEvent.Exec(e.At.UnixMilli(), e.Kind, e.Name, e.Detail, ok); err != nil {
			return fmt.Errorf("store: write an event: %w", err)
		}
	}
	insertSample, err := tx.Prepare(
		"INSERT INTO samples(at, up, down) VALUES(?, ?, ?)")
	if err != nil {
		return fmt.Errorf("store: prepare the sample insert: %w", err)
	}
	defer insertSample.Close()
	for _, sample := range samples {
		if _, err := insertSample.Exec(sample.At.UnixMilli(), sample.Up, sample.Down); err != nil {
			return fmt.Errorf("store: write a sample: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit a flush: %w", err)
	}
	return nil
}

// readConnections reads the connections table in insertion order. A row whose
// columns are not the types this build writes is skipped rather than trusted.
func readConnections(db *sql.DB) ([]Connection, error) {
	rows, err := db.Query("SELECT at, protocol, host, port, network, rule, policy, outbound, " +
		"up, down, duration_ms FROM connections ORDER BY rowid")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Connection
	for rows.Next() {
		var (
			at, port, up, down, duration                    sql.NullInt64
			protocol, host, network, rule, policy, outbound sql.NullString
		)
		if err := rows.Scan(&at, &protocol, &host, &port, &network, &rule, &policy,
			&outbound, &up, &down, &duration); err != nil {
			return nil, err
		}
		if !at.Valid || !protocol.Valid || !host.Valid || !port.Valid || !network.Valid ||
			!rule.Valid || !policy.Valid || !outbound.Valid || !up.Valid || !down.Valid ||
			!duration.Valid {
			continue
		}
		out = append(out, Connection{
			At:       time.UnixMilli(at.Int64).UTC(),
			Protocol: protocol.String,
			Host:     host.String,
			Port:     int(port.Int64),
			Network:  network.String,
			Rule:     rule.String,
			Policy:   policy.String,
			Outbound: outbound.String,
			Up:       up.Int64,
			Down:     down.Int64,
			Duration: time.Duration(duration.Int64) * time.Millisecond,
		})
	}
	return out, rows.Err()
}

// readEvents reads the events table in insertion order.
func readEvents(db *sql.DB) ([]Event, error) {
	rows, err := db.Query("SELECT at, kind, name, detail, ok FROM events ORDER BY rowid")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var (
			at, ok             sql.NullInt64
			kind, name, detail sql.NullString
		)
		if err := rows.Scan(&at, &kind, &name, &detail, &ok); err != nil {
			return nil, err
		}
		if !at.Valid || !kind.Valid || !name.Valid || !detail.Valid || !ok.Valid {
			continue
		}
		out = append(out, Event{
			At:     time.UnixMilli(at.Int64).UTC(),
			Kind:   kind.String,
			Name:   name.String,
			Detail: detail.String,
			OK:     ok.Int64 != 0,
		})
	}
	return out, rows.Err()
}

// readSamples reads the traffic table in insertion order.
func readSamples(db *sql.DB) ([]Sample, error) {
	rows, err := db.Query("SELECT at, up, down FROM samples ORDER BY rowid")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Sample
	for rows.Next() {
		var at, up, down sql.NullInt64
		if err := rows.Scan(&at, &up, &down); err != nil {
			return nil, err
		}
		if !at.Valid || !up.Valid || !down.Valid {
			continue
		}
		out = append(out, Sample{
			At:   time.UnixMilli(at.Int64).UTC(),
			Up:   up.Int64,
			Down: down.Int64,
		})
	}
	return out, rows.Err()
}
