// Package geoiptest builds MaxMind DB files for tests.
//
// A real country database is several megabytes and carries its own licence
// terms, so it is not part of the repository. Tests that need one build a tiny
// database with the same layout instead: a binary search tree, the sixteen byte
// separator, a data section, the metadata marker and a metadata record. The
// loader under test then reads it through the same code path a real file takes,
// so the fixture is checked by the reader rather than trusted.
//
// The writer covers what tests need and refuses the rest: no overlapping
// prefixes, no data section compression, one data record per leaf. A prefix that
// overlaps another is reported instead of being silently dropped, because a
// fixture that loses a network would make a test pass for the wrong reason.
package geoiptest

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sort"
)

// Format constants of the file layout.
const (
	// RecordSize is the width of one search tree record, in bits. Twenty four is
	// the narrowest the format allows and keeps a fixture readable.
	RecordSize = 24
	// SeparatorSize is the zero run between the search tree and the data
	// section. A data pointer is encoded relative to its end.
	SeparatorSize = 16
)

// Type codes of the data section.
const (
	typeString  = 2
	typeUint    = 6
	typeMap     = 7
	typeArray   = 11
	typeBoolean = 14
)

// MetadataMarker introduces the metadata section.
var MetadataMarker = []byte("\xab\xcd\xefMaxMind.com")

// Errors the writer reports.
var (
	// ErrPrefixFamily reports a prefix that does not fit the address family of
	// the database being written.
	ErrPrefixFamily = errors.New("geoiptest: the prefix family does not fit the database")
	// ErrPrefixOverlap reports a prefix that overlaps another.
	ErrPrefixOverlap = errors.New("geoiptest: overlapping prefixes are not supported")
	// ErrValue reports a record value the writer cannot encode.
	ErrValue = errors.New("geoiptest: unsupported record value")
)

// Entry is one network and the record it carries.
type Entry struct {
	Prefix netip.Prefix
	// Record is the decoded data of the network, as the reader would produce it:
	// nested maps, strings, unsigned integers, booleans and slices.
	Record map[string]any
}

// Country builds a country database from a country code to prefixes table, the
// shape the in-memory dataset uses. The file carries both address families.
func Country(entries map[string][]string) ([]byte, error) {
	codes := make([]string, 0, len(entries))
	for code := range entries {
		codes = append(codes, code)
	}
	sort.Strings(codes)
	out := make([]Entry, 0, len(codes))
	for _, code := range codes {
		for _, cidr := range entries[code] {
			prefix, err := netip.ParsePrefix(cidr)
			if err != nil {
				return nil, fmt.Errorf("geoiptest: prefix %q: %w", cidr, err)
			}
			out = append(out, Entry{
				Prefix: prefix,
				Record: map[string]any{"country": map[string]any{"iso_code": code}},
			})
		}
	}
	return Build("Test-Country", 6, out)
}

// ASN builds an autonomous system database from a number to prefixes table.
func ASN(entries map[uint32][]string) ([]byte, error) {
	numbers := make([]uint32, 0, len(entries))
	for number := range entries {
		numbers = append(numbers, number)
	}
	sort.Slice(numbers, func(i, j int) bool { return numbers[i] < numbers[j] })
	var out []Entry
	for _, number := range numbers {
		for _, cidr := range entries[number] {
			prefix, err := netip.ParsePrefix(cidr)
			if err != nil {
				return nil, fmt.Errorf("geoiptest: prefix %q: %w", cidr, err)
			}
			out = append(out, Entry{
				Prefix: prefix,
				Record: map[string]any{"autonomous_system_number": uint64(number)},
			})
		}
	}
	return Build("Test-ASN", 6, out)
}

// Build encodes a database. The IP version is 4 or 6; a database that covers
// both families uses 6, which is where a real one puts the IPv4 subtree: ninety
// six zero bits into the tree.
func Build(databaseType string, ipVersion int, entries []Entry) ([]byte, error) {
	if ipVersion != 4 && ipVersion != 6 {
		return nil, fmt.Errorf("geoiptest: ip version %d is not 4 or 6", ipVersion)
	}
	root := &node{}
	for _, entry := range entries {
		bits, length, err := prefixBits(entry.Prefix, ipVersion)
		if err != nil {
			return nil, fmt.Errorf("geoiptest: prefix %v: %w", entry.Prefix, err)
		}
		if err := insert(root, bits, length, entry.Record); err != nil {
			return nil, fmt.Errorf("geoiptest: prefix %v: %w", entry.Prefix, err)
		}
	}

	// Lay the tree out depth first, so a node index is stable and the data
	// section is written in the order the records are referenced.
	var (
		nodes  []*node
		index  = map[*node]int{}
		leaves []*node
	)
	var walk func(n *node)
	walk = func(n *node) {
		if n.child[0] == nil && n.child[1] == nil {
			leaves = append(leaves, n)
			return
		}
		index[n] = len(nodes)
		nodes = append(nodes, n)
		for _, child := range n.child {
			if child != nil {
				walk(child)
			}
		}
	}
	walk(root)
	if len(nodes) == 0 {
		return nil, errors.New("geoiptest: the tree has no node")
	}
	nodeCount := len(nodes)

	// The data section: one record per leaf, in tree order.
	data := make([]byte, 0, 64*len(leaves))
	offsets := map[*node]int{}
	for _, leaf := range leaves {
		offsets[leaf] = len(data)
		encoded, err := encodeValue(leaf.value)
		if err != nil {
			return nil, err
		}
		data = append(data, encoded...)
	}

	// A record below the node count continues the walk, one equal to it ends the
	// walk with no answer, and one above it points into the data section counted
	// from the end of the separator.
	record := func(child *node) uint32 {
		switch {
		case child == nil:
			return uint32(nodeCount)
		case child.child[0] != nil || child.child[1] != nil:
			return uint32(index[child])
		default:
			return uint32(nodeCount) + SeparatorSize + uint32(offsets[child])
		}
	}
	tree := make([]byte, 0, nodeCount*RecordSize/4)
	for _, n := range nodes {
		tree = appendRecord(tree, record(n.child[0]))
		tree = appendRecord(tree, record(n.child[1]))
	}

	metadata, err := encodeValue(map[string]any{
		"binary_format_major_version": uint64(2),
		"binary_format_minor_version": uint64(0),
		"build_epoch":                 uint64(1_700_000_000),
		"database_type":               databaseType,
		"description":                 map[string]any{"en": "test fixture"},
		"ip_version":                  uint64(ipVersion),
		"languages":                   []any{"en"},
		"node_count":                  uint64(nodeCount),
		"record_size":                 uint64(RecordSize),
	})
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, len(tree)+SeparatorSize+len(data)+len(MetadataMarker)+len(metadata))
	out = append(out, tree...)
	out = append(out, make([]byte, SeparatorSize)...)
	out = append(out, data...)
	out = append(out, MetadataMarker...)
	return append(out, metadata...), nil
}

// node is one node of the tree the writer builds.
type node struct {
	child [2]*node
	value map[string]any
}

// appendRecord appends one record of RecordSize bits.
func appendRecord(buf []byte, value uint32) []byte {
	return append(buf, byte(value>>16), byte(value>>8), byte(value))
}

// prefixBits renders a prefix as the bits of the tree. An IPv4 prefix in a tree
// that carries both families is placed ninety six zero bits down, which is where
// the reader starts an IPv4 lookup.
func prefixBits(prefix netip.Prefix, ipVersion int) ([]byte, int, error) {
	if prefix.Addr().Is4() {
		addr := prefix.Addr().As4()
		if ipVersion == 4 {
			return addr[:], prefix.Bits(), nil
		}
		full := make([]byte, 16)
		copy(full[12:], addr[:])
		return full, prefix.Bits() + 96, nil
	}
	if ipVersion == 4 {
		return nil, 0, ErrPrefixFamily
	}
	addr := prefix.Addr().As16()
	return addr[:], prefix.Bits(), nil
}

// insert adds one prefix and its record to the tree.
func insert(root *node, bits []byte, length int, value map[string]any) error {
	if length == 0 {
		return ErrPrefixOverlap
	}
	current := root
	for i := 0; i < length; i++ {
		if current.value != nil {
			return ErrPrefixOverlap
		}
		bit := (bits[i/8] >> (7 - uint(i%8))) & 1
		if current.child[bit] == nil {
			current.child[bit] = &node{}
		}
		current = current.child[bit]
	}
	if current.value != nil || current.child[0] != nil || current.child[1] != nil {
		return ErrPrefixOverlap
	}
	current.value = value
	return nil
}

// encodeValue writes one data section value.
func encodeValue(value any) ([]byte, error) {
	switch typed := value.(type) {
	case string:
		return append(control(typeString, len(typed)), typed...), nil
	case uint64:
		return appendUint(typed), nil
	case uint32:
		return appendUint(uint64(typed)), nil
	case int:
		return appendUint(uint64(typed)), nil
	case bool:
		if typed {
			return control(typeBoolean, 1), nil
		}
		return control(typeBoolean, 0), nil
	case []any:
		out := control(typeArray, len(typed))
		for _, item := range typed {
			encoded, err := encodeValue(item)
			if err != nil {
				return nil, err
			}
			out = append(out, encoded...)
		}
		return out, nil
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		out := control(typeMap, len(keys))
		for _, key := range keys {
			encodedKey, err := encodeValue(key)
			if err != nil {
				return nil, err
			}
			encodedValue, err := encodeValue(typed[key])
			if err != nil {
				return nil, err
			}
			out = append(out, encodedKey...)
			out = append(out, encodedValue...)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%w: %T", ErrValue, value)
	}
}

// appendUint writes an unsigned integer using as many bytes as it needs.
func appendUint(value uint64) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], value)
	first := 0
	for first < 7 && buf[first] == 0 {
		first++
	}
	payload := buf[first:]
	return append(control(typeUint, len(payload)), payload...)
}

// control encodes the type and size field of a value. A type of eight or more
// needs a second byte, because the first three bits only hold seven.
func control(typ, size int) []byte {
	var (
		sizeField byte
		extra     []byte
	)
	switch {
	case size < 29:
		sizeField = byte(size)
	case size < 29+256:
		sizeField = 29
		extra = []byte{byte(size - 29)}
	case size < 285+65536:
		sizeField = 30
		extra = binary.BigEndian.AppendUint16(nil, uint16(size-285))
	default:
		sizeField = 31
		s := uint32(size - 65821)
		extra = []byte{byte(s >> 16), byte(s >> 8), byte(s)}
	}
	if typ < 8 {
		return append([]byte{byte(typ)<<5 | sizeField}, extra...)
	}
	return append([]byte{sizeField, byte(typ - 7)}, extra...)
}
