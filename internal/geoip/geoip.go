// Package geoip loads MaxMind DB (.mmdb) files and answers the two lookups the
// rule engine needs: the country of an address and the autonomous system it
// belongs to.
//
// The rule engine only knows the GeoIPLookup and ASNLookup interfaces, so this
// package can be swapped for the in-memory datasets the tests use without the
// matcher noticing. A database is immutable and safe for concurrent use.
//
// A database file is not part of the repository: the formats are large and carry
// their own licence terms. Tests build small fixtures of their own instead, and
// the fixtures are written by the same code the loader is tested against.
package geoip

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/oschwald/maxminddb-golang"
)

// Kind says which records a database is expected to carry.
type Kind int

// The two kinds this build uses.
const (
	// KindCountry answers "which country is this address in", from a database
	// with country records such as a country or city database.
	KindCountry Kind = iota
	// KindASN answers "which autonomous system announces this address", from a
	// database with autonomous system records.
	KindASN
)

// String implements fmt.Stringer.
func (k Kind) String() string {
	if k == KindASN {
		return "asn"
	}
	return "country"
}

// Errors reported by the loader.
var (
	// ErrMissing reports a configured database file that is not there.
	ErrMissing = errors.New("geoip: database file does not exist")
	// ErrCorrupt reports a file that is not a usable MaxMind DB.
	ErrCorrupt = errors.New("geoip: database file is not usable")
	// ErrWrongKind reports a database of the wrong sort, which is the mistake of
	// pointing geoip-db at an ASN file or the other way round.
	ErrWrongKind = errors.New("geoip: database is of the wrong kind")
)

// Database is an open MaxMind DB file.
type Database struct {
	path   string
	kind   Kind
	reader *maxminddb.Reader
}

// countryRecord is the part of a country record this project reads. A city
// database nests the same structure, and a country database repeats it under
// registered_country for addresses announced by a different country than the one
// they are located in.
type countryRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	RegisteredCountry struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"registered_country"`
}

// asnRecord is the part of an autonomous system record this project reads.
type asnRecord struct {
	Number uint32 `maxminddb:"autonomous_system_number"`
}

// Open loads a database file. The kind decides which records are expected: the
// common mistake of pointing the country setting at an ASN file is reported
// here, where the file is still identifiable, instead of showing up later as a
// rule set that matches nothing.
func Open(path string, kind Kind) (*Database, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("%w: %s path is empty", ErrMissing, kind)
	}
	info, err := os.Stat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, fmt.Errorf("%w: %s", ErrMissing, path)
	case err != nil:
		return nil, fmt.Errorf("%w: %s: %v", ErrMissing, path, err)
	case info.IsDir():
		return nil, fmt.Errorf("%w: %s is a directory", ErrMissing, path)
	}
	reader, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrCorrupt, path, err)
	}
	db := &Database{path: path, kind: kind, reader: reader}
	if err := db.checkKind(); err != nil {
		_ = reader.Close()
		return nil, err
	}
	return db, nil
}

// checkKind compares the database type the file declares with the records the
// caller is going to read. The comparison is a heuristic on purpose: the type
// string is free form — a publisher's own naming, a country set, an autonomous
// system set — so only the one distinction that matters is enforced: an
// autonomous system database and a country database are not interchangeable.
func (d *Database) checkKind() error {
	declared := strings.ToLower(d.reader.Metadata.DatabaseType)
	looksLikeASN := strings.Contains(declared, "asn") || strings.Contains(declared, "autonomous")
	switch {
	case d.kind == KindASN && !looksLikeASN:
		return fmt.Errorf("%w: %s declares type %q, which carries no autonomous system records", ErrWrongKind, d.path, d.reader.Metadata.DatabaseType)
	case d.kind == KindCountry && looksLikeASN:
		return fmt.Errorf("%w: %s declares type %q, which carries no country records", ErrWrongKind, d.path, d.reader.Metadata.DatabaseType)
	}
	return nil
}

// Path is the file the database was loaded from.
func (d *Database) Path() string {
	if d == nil {
		return ""
	}
	return d.path
}

// Type is the database type the file declares, which is what a startup log line
// should report so an operator can tell which dataset is in force.
func (d *Database) Type() string {
	if d == nil || d.reader == nil {
		return ""
	}
	return d.reader.Metadata.DatabaseType
}

// IPVersion is 4 or 6, the address family the file's search tree covers.
func (d *Database) IPVersion() int {
	if d == nil || d.reader == nil {
		return 0
	}
	return int(d.reader.Metadata.IPVersion)
}

// Close releases the file. A database must not be closed while a lookup is in
// flight: the reader either maps the file or holds its bytes, and unmapping them
// under a reader is undefined behaviour. The daemon therefore keeps its
// databases open for the lifetime of the process.
func (d *Database) Close() error {
	if d == nil || d.reader == nil {
		return nil
	}
	err := d.reader.Close()
	d.reader = nil
	return err
}

// Country implements the rule engine's GeoIPLookup: the ISO code of the country
// an address is located in, falling back to the country that announces it. It
// returns false for an address the database does not cover.
func (d *Database) Country(ip net.IP) (string, bool) {
	if d == nil || d.reader == nil || d.kind != KindCountry || ip == nil {
		return "", false
	}
	var record countryRecord
	// A lookup error means the record cannot be decoded, which is a property of
	// the file rather than of the address: report "no answer" and let the rule
	// engine treat it as a miss. The rule engine's interface has no error
	// channel, and a miss is the safe direction for a routing decision that must
	// stay deterministic.
	if err := d.reader.Lookup(ip, &record); err != nil {
		return "", false
	}
	if record.Country.ISOCode != "" {
		return record.Country.ISOCode, true
	}
	if record.RegisteredCountry.ISOCode != "" {
		return record.RegisteredCountry.ISOCode, true
	}
	return "", false
}

// ASN implements the rule engine's ASNLookup: the autonomous system number that
// announces an address.
func (d *Database) ASN(ip net.IP) (uint32, bool) {
	if d == nil || d.reader == nil || d.kind != KindASN || ip == nil {
		return 0, false
	}
	var record asnRecord
	if err := d.reader.Lookup(ip, &record); err != nil {
		return 0, false
	}
	if record.Number == 0 {
		return 0, false
	}
	return record.Number, true
}

// Cache keeps the databases a running daemon has opened, so a reload of the
// configuration reuses a handle instead of mapping the same multi megabyte file
// again.
//
// The file's size and modification time are part of the key: replacing the file
// on disk opens a new handle, and the old one is kept until Close. Old handles
// are deliberately not closed on reload, because a request that started before
// the reload may still be reading through the previous rule program.
type Cache struct {
	mu    sync.Mutex
	open  map[cacheKey]*Database
	owned []*Database
}

// cacheKey identifies one load of one file.
type cacheKey struct {
	path    string
	kind    Kind
	size    int64
	modTime int64
}

// NewCache builds an empty cache.
func NewCache() *Cache {
	return &Cache{open: make(map[cacheKey]*Database)}
}

// Country returns the country database for path, opening it when this is the
// first time the file is seen or when it changed on disk.
func (c *Cache) Country(path string) (*Database, error) { return c.load(path, KindCountry) }

// ASN returns the autonomous system database for path.
func (c *Cache) ASN(path string) (*Database, error) { return c.load(path, KindASN) }

// load is the one place a database is opened, so the cache key and the handle
// list cannot drift apart.
func (c *Cache) load(path string, kind Kind) (*Database, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrMissing, path, err)
	}
	key := cacheKey{path: path, kind: kind, size: info.Size(), modTime: info.ModTime().UnixNano()}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.open == nil {
		c.open = make(map[cacheKey]*Database)
	}
	if db, ok := c.open[key]; ok {
		return db, nil
	}
	db, err := Open(path, kind)
	if err != nil {
		return nil, err
	}
	c.open[key] = db
	c.owned = append(c.owned, db)
	return db, nil
}

// Close releases every database the cache has opened. It is called once, when
// the process stops, for the reason given on Database.Close.
func (c *Cache) Close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, db := range c.owned {
		_ = db.Close()
	}
	c.owned = nil
	c.open = make(map[cacheKey]*Database)
}
