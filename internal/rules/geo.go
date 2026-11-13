package rules

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"sort"
)

// GeoIPLookup answers which country or region an address belongs to.
//
// The MVP ships the in-memory implementation below; an mmdb backed one can be
// added later without touching the rule engine, which only sees this interface.
type GeoIPLookup interface {
	Country(ip net.IP) (string, bool)
}

// ASNLookup answers which autonomous system an address belongs to.
type ASNLookup interface {
	ASN(ip net.IP) (uint32, bool)
}

// MemGeoIP is a GeoIP dataset held in memory, built from country code to
// prefix list. It is immutable and safe for concurrent use.
type MemGeoIP struct {
	codes []string
	v4    *rangeTable[uint32]
	v6    *rangeTable[u128]
}

// NewMemGeoIP builds a dataset. Blocks that overlap are resolved in favour of
// the alphabetically first country code, which keeps the choice deterministic;
// real datasets do not overlap in practice.
func NewMemGeoIP(entries map[string][]string) (*MemGeoIP, error) {
	codes := make([]string, 0, len(entries))
	for code := range entries {
		codes = append(codes, code)
	}
	sort.Strings(codes)

	var v4Blocks, v6Blocks []block
	for i, code := range codes {
		for _, cidr := range entries[code] {
			b, isV4, err := cidrBlock(cidr, int32(i))
			if err != nil {
				return nil, fmt.Errorf("geoip %s: %w", code, err)
			}
			if isV4 {
				v4Blocks = append(v4Blocks, b)
			} else {
				v6Blocks = append(v6Blocks, b)
			}
		}
	}
	return &MemGeoIP{
		codes: codes,
		v4:    newRangeTable4(buildRanges(v4Blocks)),
		v6:    newRangeTable6(buildRanges(v6Blocks)),
	}, nil
}

// Country implements GeoIPLookup.
func (m *MemGeoIP) Country(ip net.IP) (string, bool) {
	if m == nil || ip == nil {
		return "", false
	}
	if v4 := ip.To4(); v4 != nil {
		idx, ok := m.v4.lookup(binary.BigEndian.Uint32(v4))
		if !ok {
			return "", false
		}
		return m.codes[idx], true
	}
	v6 := ip.To16()
	if v6 == nil {
		return "", false
	}
	idx, ok := m.v6.lookup(ipToU128(v6))
	if !ok {
		return "", false
	}
	return m.codes[idx], true
}

// MemASN is an ASN dataset held in memory, built from AS number to prefix
// list. It is immutable and safe for concurrent use.
type MemASN struct {
	numbers []uint32
	v4      *rangeTable[uint32]
	v6      *rangeTable[u128]
}

// NewMemASN builds an ASN dataset. Overlapping blocks resolve to the lowest AS
// number for determinism.
func NewMemASN(entries map[uint32][]string) (*MemASN, error) {
	numbers := make([]uint32, 0, len(entries))
	for n := range entries {
		numbers = append(numbers, n)
	}
	sort.Slice(numbers, func(i, j int) bool { return numbers[i] < numbers[j] })

	var v4Blocks, v6Blocks []block
	for i, n := range numbers {
		for _, cidr := range entries[n] {
			b, isV4, err := cidrBlock(cidr, int32(i))
			if err != nil {
				return nil, fmt.Errorf("ip-asn %d: %w", n, err)
			}
			if isV4 {
				v4Blocks = append(v4Blocks, b)
			} else {
				v6Blocks = append(v6Blocks, b)
			}
		}
	}
	return &MemASN{
		numbers: numbers,
		v4:      newRangeTable4(buildRanges(v4Blocks)),
		v6:      newRangeTable6(buildRanges(v6Blocks)),
	}, nil
}

// ASN implements ASNLookup.
func (m *MemASN) ASN(ip net.IP) (uint32, bool) {
	if m == nil || ip == nil {
		return 0, false
	}
	if v4 := ip.To4(); v4 != nil {
		idx, ok := m.v4.lookup(binary.BigEndian.Uint32(v4))
		if !ok {
			return 0, false
		}
		return m.numbers[idx], true
	}
	v6 := ip.To16()
	if v6 == nil {
		return 0, false
	}
	idx, ok := m.v6.lookup(ipToU128(v6))
	if !ok {
		return 0, false
	}
	return m.numbers[idx], true
}

// cidrBlock turns a prefix into an address range.
func cidrBlock(cidr string, idx int32) (block, bool, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return block{}, false, fmt.Errorf("invalid prefix %q", cidr)
	}
	ones, bits := network.Mask.Size()
	if bits == 32 {
		v4 := network.IP.To4()
		if v4 == nil {
			return block{}, false, fmt.Errorf("invalid prefix %q", cidr)
		}
		start := uint64(binary.BigEndian.Uint32(v4))
		return block{
			start: boundOf(u128{lo: start}),
			end:   boundOf(u128{lo: start + uint64(1)<<uint(32-ones)}),
			idx:   idx,
		}, true, nil
	}
	start := ipToU128(network.IP.To16())
	return block{start: boundOf(start), end: endBound(start, 128-ones), idx: idx}, false, nil
}

// endBound returns the exclusive end of a prefix that starts at start and has
// hostBits host bits.
func endBound(start u128, hostBits int) bound {
	if hostBits >= 128 {
		return boundPast()
	}
	var add u128
	switch {
	case hostBits == 0:
		add = u128{lo: 1}
	case hostBits < 64:
		add = u128{lo: 1 << uint(hostBits)}
	default:
		add = u128{hi: 1 << uint(hostBits-64)}
	}
	lo := start.lo + add.lo
	carry := lo < start.lo
	hi := start.hi + add.hi
	if hi < start.hi || hi < add.hi {
		return boundPast()
	}
	if carry {
		if hi == math.MaxUint64 {
			return boundPast()
		}
		hi++
	}
	return boundOf(u128{hi: hi, lo: lo})
}

// ipToU128 reads a 16-byte address as a 128-bit integer.
func ipToU128(ip net.IP) u128 {
	return u128{
		hi: binary.BigEndian.Uint64(ip[0:8]),
		lo: binary.BigEndian.Uint64(ip[8:16]),
	}
}
