package geoip

import (
	"net"
	"testing"

	"github.com/melon-tgj/melonarc/internal/geoip/geoiptest"
	"github.com/melon-tgj/melonarc/internal/rules"
)

// BenchmarkCountryLookup compares the file backed lookup with the in-memory
// dataset the rule engine was built against. The file lookup walks a search tree
// and decodes a record through reflection, so it is the more expensive of the
// two; the numbers say how much of a match's budget one GEOIP rule costs.
func BenchmarkCountryLookup(b *testing.B) {
	table := map[string][]string{
		"ZZ": {"203.0.113.0/24", "198.51.100.0/24", "2001:db8::/32"},
		"YY": {"192.0.2.0/24"},
	}
	path := writeFixture(b, "country.mmdb", func() ([]byte, error) { return geoiptest.Country(table) })
	db, err := Open(path, KindCountry)
	if err != nil {
		b.Fatalf("open: %v", err)
	}
	b.Cleanup(func() { _ = db.Close() })
	mem, err := rules.NewMemGeoIP(table)
	if err != nil {
		b.Fatalf("memory dataset: %v", err)
	}
	ip := net.ParseIP("203.0.113.5")

	b.Run("mmdb", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, ok := db.Country(ip); !ok {
				b.Fatal("no answer")
			}
		}
	})
	b.Run("memory", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, ok := mem.Country(ip); !ok {
				b.Fatal("no answer")
			}
		}
	})
}
