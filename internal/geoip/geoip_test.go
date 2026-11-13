package geoip

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/melon-tgj/melonarc/internal/geoip/geoiptest"
	"github.com/melon-tgj/melonarc/internal/rules"
)

// countryTable is the mapping both the fixture and the in-memory dataset are
// built from, so their answers can be compared address by address.
func countryTable() map[string][]string {
	return map[string][]string{
		"ZZ": {"203.0.113.0/24", "198.51.100.0/24"},
		"YY": {"192.0.2.0/24"},
	}
}

// writeFixture builds a database and writes it to a temporary file.
func writeFixture(tb testing.TB, name string, build func() ([]byte, error)) string {
	tb.Helper()
	data, err := build()
	if err != nil {
		tb.Fatalf("build fixture: %v", err)
	}
	path := filepath.Join(tb.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		tb.Fatalf("write fixture: %v", err)
	}
	return path
}

// TestCountryMatchesTheInMemoryDataset is the equivalence check the memory
// implementation exists for: the same mapping must answer the same way through
// either implementation.
func TestCountryMatchesTheInMemoryDataset(t *testing.T) {
	table := countryTable()
	path := writeFixture(t, "country.mmdb", func() ([]byte, error) { return geoiptest.Country(table) })
	db, err := Open(path, KindCountry)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if db.Type() != "Test-Country" {
		t.Fatalf("type = %q, want Test-Country", db.Type())
	}
	if db.IPVersion() != 6 {
		t.Fatalf("ip version = %d, want 6", db.IPVersion())
	}

	mem, err := rules.NewMemGeoIP(table)
	if err != nil {
		t.Fatalf("memory dataset: %v", err)
	}

	addresses := []string{
		"203.0.113.0", "203.0.113.1", "203.0.113.255", "203.0.114.0",
		"198.51.100.7", "198.51.100.255", "192.0.2.1", "192.0.2.254",
		"198.51.101.1", "10.0.0.1", "0.0.0.0", "255.255.255.255",
		"2001:db8::1", // outside a database that only carries IPv4 networks
	}
	for _, addr := range addresses {
		ip := net.ParseIP(addr)
		wantCode, wantOK := mem.Country(ip)
		gotCode, gotOK := db.Country(ip)
		if gotOK != wantOK || gotCode != wantCode {
			t.Fatalf("Country(%s) = %q, %v; want %q, %v", addr, gotCode, gotOK, wantCode, wantOK)
		}
	}
}

// TestCountryCoversBothFamilies checks a database that carries IPv4 and IPv6
// records, which is how a real one is laid out: the IPv4 subtree lives ninety
// six zero bits into the IPv6 tree.
func TestCountryCoversBothFamilies(t *testing.T) {
	table := map[string][]string{
		"ZZ": {"203.0.113.0/24", "2001:db8::/32"},
		"YY": {"2001:dba::/32"},
	}
	path := writeFixture(t, "dual.mmdb", func() ([]byte, error) { return geoiptest.Country(table) })
	db, err := Open(path, KindCountry)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	tests := []struct {
		addr string
		want string
		ok   bool
	}{
		{addr: "203.0.113.9", want: "ZZ", ok: true},
		{addr: "203.0.114.9"},
		{addr: "2001:db8::1", want: "ZZ", ok: true},
		{addr: "2001:db8:1::1", want: "ZZ", ok: true},
		{addr: "2001:dba::1", want: "YY", ok: true},
		{addr: "2001:dbb::1"},
	}
	for _, tc := range tests {
		code, ok := db.Country(net.ParseIP(tc.addr))
		if ok != tc.ok || code != tc.want {
			t.Fatalf("Country(%s) = %q, %v; want %q, %v", tc.addr, code, ok, tc.want, tc.ok)
		}
	}
}

// TestCountryFallsBackToTheRegisteredCountry covers the records a real database
// uses for an address announced by a different country than the one it sits in.
func TestCountryFallsBackToTheRegisteredCountry(t *testing.T) {
	build := func() ([]byte, error) {
		return geoiptest.Build("Test-Country", 4, []geoiptest.Entry{{
			Prefix: mustPrefix(t, "203.0.113.0/24"),
			Record: map[string]any{
				"registered_country": map[string]any{"iso_code": "XX"},
			},
		}})
	}
	path := writeFixture(t, "registered.mmdb", build)
	db, err := Open(path, KindCountry)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if code, ok := db.Country(net.ParseIP("203.0.113.1")); !ok || code != "XX" {
		t.Fatalf("Country = %q, %v; want XX, true", code, ok)
	}
}

// TestASNMatchesTheInMemoryDataset is the same equivalence check for the other
// interface.
func TestASNMatchesTheInMemoryDataset(t *testing.T) {
	table := map[uint32][]string{
		64512: {"203.0.113.0/24", "2001:db8::/32"},
		64513: {"198.51.100.0/24"},
	}
	path := writeFixture(t, "asn.mmdb", func() ([]byte, error) { return geoiptest.ASN(table) })
	db, err := Open(path, KindASN)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	mem, err := rules.NewMemASN(table)
	if err != nil {
		t.Fatalf("memory dataset: %v", err)
	}
	addresses := []string{
		"203.0.113.1", "203.0.113.255", "198.51.100.9", "2001:db8::5",
		"203.0.114.1", "2001:db9::1",
	}
	for _, addr := range addresses {
		ip := net.ParseIP(addr)
		wantNumber, wantOK := mem.ASN(ip)
		gotNumber, gotOK := db.ASN(ip)
		if gotOK != wantOK || gotNumber != wantNumber {
			t.Fatalf("ASN(%s) = %d, %v; want %d, %v", addr, gotNumber, gotOK, wantNumber, wantOK)
		}
	}
}

// TestOpenReportsAMissingFile keeps the error a user sees actionable.
func TestOpenReportsAMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.mmdb")
	_, err := Open(path, KindCountry)
	if !errors.Is(err, ErrMissing) {
		t.Fatalf("error = %v, want %v", err, ErrMissing)
	}
	if !strings.Contains(err.Error(), path) {
		t.Fatalf("error = %v, want the path in it", err)
	}
}

// TestOpenReportsADirectory covers a path that exists but is not a file.
func TestOpenReportsADirectory(t *testing.T) {
	dir := t.TempDir()
	if _, err := Open(dir, KindCountry); !errors.Is(err, ErrMissing) {
		t.Fatalf("error = %v, want %v", err, ErrMissing)
	}
}

// TestOpenReportsACorruptFile covers a file that exists and cannot be read as a
// database, including a truncated one.
func TestOpenReportsACorruptFile(t *testing.T) {
	good, err := geoiptest.Country(countryTable())
	if err != nil {
		t.Fatalf("build fixture: %v", err)
	}
	tests := []struct {
		name string
		data []byte
	}{
		{name: "not a database", data: []byte("this is not a database at all")},
		{name: "empty", data: nil},
		{name: "truncated", data: good[:len(good)/2]},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "corrupt.mmdb")
			if err := os.WriteFile(path, tc.data, 0o600); err != nil {
				t.Fatalf("write fixture: %v", err)
			}
			_, err := Open(path, KindCountry)
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("error = %v, want %v", err, ErrCorrupt)
			}
		})
	}
}

// TestOpenRejectsTheWrongKind keeps a swapped setting from turning into a rule
// set that matches nothing.
func TestOpenRejectsTheWrongKind(t *testing.T) {
	countryPath := writeFixture(t, "country.mmdb", func() ([]byte, error) { return geoiptest.Country(countryTable()) })
	asnPath := writeFixture(t, "asn.mmdb", func() ([]byte, error) {
		return geoiptest.ASN(map[uint32][]string{64512: {"203.0.113.0/24"}})
	})

	if _, err := Open(countryPath, KindASN); !errors.Is(err, ErrWrongKind) {
		t.Fatalf("opening a country database as asn: error = %v, want %v", err, ErrWrongKind)
	}
	if _, err := Open(asnPath, KindCountry); !errors.Is(err, ErrWrongKind) {
		t.Fatalf("opening an asn database as country: error = %v, want %v", err, ErrWrongKind)
	}
}

// TestNilDatabaseAnswersNothing keeps a missing database from panicking a rule
// evaluation.
func TestNilDatabaseAnswersNothing(t *testing.T) {
	var db *Database
	if _, ok := db.Country(net.ParseIP("203.0.113.1")); ok {
		t.Fatal("a nil database answered a country lookup")
	}
	if _, ok := db.ASN(net.ParseIP("203.0.113.1")); ok {
		t.Fatal("a nil database answered an asn lookup")
	}
	if db.Path() != "" || db.Type() != "" || db.IPVersion() != 0 {
		t.Fatal("a nil database reports metadata")
	}
	if err := db.Close(); err != nil {
		t.Fatalf("closing a nil database: %v", err)
	}
}

// TestCacheReusesAHandle keeps a reload from mapping the same file again.
func TestCacheReusesAHandle(t *testing.T) {
	path := writeFixture(t, "country.mmdb", func() ([]byte, error) { return geoiptest.Country(countryTable()) })
	cache := NewCache()
	defer cache.Close()

	first, err := cache.Country(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	second, err := cache.Country(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if first != second {
		t.Fatal("the cache opened the same file twice")
	}

	// A different file at the same path has to be picked up. It is written to a
	// temporary file and renamed into place, which is how an operator replaces a
	// dataset: rewriting the file in place would change the bytes under the
	// mapping the old handle still holds.
	replacement, err := geoiptest.Country(map[string][]string{"WW": {"203.0.113.0/24"}})
	if err != nil {
		t.Fatalf("build replacement: %v", err)
	}
	next := filepath.Join(t.TempDir(), "country.mmdb")
	if err := os.WriteFile(next, replacement, 0o600); err != nil {
		t.Fatalf("write replacement: %v", err)
	}
	if err := os.Rename(next, path); err != nil {
		t.Fatalf("replace fixture: %v", err)
	}
	third, err := cache.Country(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if third == first {
		t.Fatal("the cache kept the handle of a replaced file")
	}
	if code, ok := third.Country(net.ParseIP("203.0.113.1")); !ok || code != "WW" {
		t.Fatalf("Country = %q, %v; want WW, true", code, ok)
	}
	// The old handle stays readable: a request that started before the reload
	// may still be using it.
	if code, ok := first.Country(net.ParseIP("203.0.113.1")); !ok || code != "ZZ" {
		t.Fatalf("old handle Country = %q, %v; want ZZ, true", code, ok)
	}
}

// TestCacheCloseReleasesEveryHandle checks the shutdown path.
func TestCacheCloseReleasesEveryHandle(t *testing.T) {
	path := writeFixture(t, "country.mmdb", func() ([]byte, error) { return geoiptest.Country(countryTable()) })
	cache := NewCache()
	db, err := cache.Country(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	cache.Close()
	if _, ok := db.Country(net.ParseIP("203.0.113.1")); ok {
		t.Fatal("a closed database still answered")
	}
	// Opening again after a close works, which is what a test that reuses a
	// cache expects.
	if _, err := cache.Country(path); err != nil {
		t.Fatalf("open after close: %v", err)
	}
	cache.Close()
}

// TestCacheReportsAMissingFile checks that a configured path that does not exist
// fails where it is used.
func TestCacheReportsAMissingFile(t *testing.T) {
	cache := NewCache()
	defer cache.Close()
	if _, err := cache.Country(filepath.Join(t.TempDir(), "absent.mmdb")); !errors.Is(err, ErrMissing) {
		t.Fatalf("error = %v, want %v", err, ErrMissing)
	}
}

// mustPrefix parses a prefix or fails the test.
func mustPrefix(t *testing.T, cidr string) netip.Prefix {
	t.Helper()
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		t.Fatalf("prefix %q: %v", cidr, err)
	}
	return prefix
}
