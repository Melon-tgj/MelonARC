package store

// The SQLite file format, limited to what this package writes and reads.
//
// Why the format is implemented here rather than taken from a library:
// every Go SQLite binding is either cgo (which would end the single static
// binary and the Windows cross build) or a pure-Go engine of several modules
// whose licence would have to be vetted. The observation store needs one table
// per record kind, an append and a scan — no SQL, no indexes, no triggers — so
// the file format itself is the smaller surface. What the package writes is a
// real database file: any SQLite reader opens it, and the tests prove that with
// an independent one.
//
// The subset: page size 4096, UTF-8, one table b-tree per table, depth at most
// two, no overflow pages, no freelist, no indexes, no WAL. A row is rejected
// before it could need any of those, which is why every column has a length
// bound.

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Layout constants.
const (
	// pageSize is the size of one page. 4096 keeps a row far below the
	// largest payload that still fits a leaf page, so no row ever needs an
	// overflow chain.
	pageSize = 4096
	// headerBytes is the database header, which occupies the start of page 1.
	headerBytes = 100
	// schemaCookie changes when the schema does. The schema here is fixed, so
	// the value never moves; a reader only compares it with itself.
	schemaCookie = 1
	// schemaFormat is 4 for every database SQLite has written since 3.3.
	schemaFormat = 4
	// encodingUTF8 is the text encoding every string in this file uses.
	encodingUTF8 = 1
	// userVersion identifies the schema this package writes. It lets a future
	// build notice a file it does not understand instead of decoding the rows
	// of another layout.
	userVersion = 1
	// writerLibrary is what the header reports as the writing library. It is
	// deliberately an old, plain number: the file uses no feature newer than
	// the format itself, and a high number would make an older reader refuse
	// it.
	writerLibrary = 3045000
	// maxDepth bounds the tree walk. The writer never builds more than two
	// levels, so this only stops a corrupted file from looping.
	maxDepth = 4
)

// Page types.
const (
	pageTypeInterior = 0x05
	pageTypeLeaf     = 0x0d
)

// Errors reported by the reader and the writer.
var (
	// ErrNotADatabase marks a file that does not start with the SQLite header,
	// is truncated, or declares a page size this package does not write.
	ErrNotADatabase = errors.New("store: not a SQLite database of this layout")
	// ErrTooLarge marks a table that would need a third tree level or an
	// overflow page. It is a bug in the retention limits, not a runtime
	// condition: the retention caps keep every table far below it.
	ErrTooLarge = errors.New("store: table does not fit the layout")
)

// maxLocalPayload is the largest payload a leaf cell can hold inline. It comes
// from the default payload fractions: (usable-12)*64/255 - 23 with usable equal
// to the page size, because the reserved area is zero.
const maxLocalPayload = ((pageSize-12)*64)/255 - 23

// recordValue is one column of one row. Only the two storage classes this
// package writes are represented: an integer and a text string. NULL is the
// zero kind, which is what an empty column looks like.
type recordValue struct {
	kind valueKind
	i    int64
	s    string
}

// valueKind is the storage class of a record value.
type valueKind int

const (
	kindNull valueKind = iota
	kindInt
	kindText
)

// intValue and textValue build the two kinds a caller writes.
func intValue(v int64) recordValue { return recordValue{kind: kindInt, i: v} }

func textValue(v string) recordValue { return recordValue{kind: kindText, s: v} }

// serialType returns the serial type and the body length of a value.
//
// The integer widths are the ones the format offers: a value that fits one byte
// takes one byte. The 0 and 1 shortcuts are used because they are what a
// boolean and an empty counter look like, and they cost nothing.
func serialType(v recordValue) (serial uint64, body uint64) {
	switch v.kind {
	case kindInt:
		switch {
		case v.i == 0:
			return 8, 0
		case v.i == 1:
			return 9, 0
		case v.i >= -128 && v.i <= 127:
			return 1, 1
		case v.i >= -32768 && v.i <= 32767:
			return 2, 2
		case v.i >= -2147483648 && v.i <= 2147483647:
			return 4, 4
		default:
			return 6, 8
		}
	case kindText:
		return 13 + 2*uint64(len(v.s)), uint64(len(v.s))
	default:
		return 0, 0
	}
}

// encodeValue writes the body of a value. Integers are big-endian two's
// complement, text is raw UTF-8.
func encodeValue(dst []byte, v recordValue) {
	switch v.kind {
	case kindInt:
		switch {
		case v.i == 0, v.i == 1:
		case v.i >= -128 && v.i <= 127:
			dst[0] = byte(v.i)
		case v.i >= -32768 && v.i <= 32767:
			binary.BigEndian.PutUint16(dst, uint16(v.i))
		case v.i >= -2147483648 && v.i <= 2147483647:
			binary.BigEndian.PutUint32(dst, uint32(v.i))
		default:
			binary.BigEndian.PutUint64(dst, uint64(v.i))
		}
	case kindText:
		copy(dst, v.s)
	}
}

// encodeRecord renders one row payload: a header of serial types followed by the
// values themselves.
func encodeRecord(values []recordValue) []byte {
	types := make([]byte, 0, len(values)*2)
	body := make([]byte, 0, len(values)*8)
	var scratch [9]byte
	for _, v := range values {
		serial, size := serialType(v)
		n := putVarint(scratch[:], serial)
		types = append(types, scratch[:n]...)
		if size == 0 {
			continue
		}
		start := len(body)
		body = append(body, make([]byte, size)...)
		encodeValue(body[start:], v)
	}
	// The header length counts its own varint, which makes the length depend
	// on the width of its encoding. It settles in one step for every row this
	// package writes; the loop is here so that it is correct rather than
	// lucky.
	headerLen := len(types) + 1
	for {
		need := varintLen(uint64(headerLen)) + len(types)
		if need == headerLen {
			break
		}
		headerLen = need
	}
	out := make([]byte, headerLen, headerLen+len(body))
	n := putVarint(out, uint64(headerLen))
	copy(out[n:], types)
	return append(out, body...)
}

// decodeRecord splits one row payload back into its values.
func decodeRecord(payload []byte) ([]recordValue, error) {
	headerLen, n, err := readVarint(payload)
	if err != nil {
		return nil, err
	}
	if headerLen > uint64(len(payload)) || headerLen < uint64(n) {
		return nil, fmt.Errorf("%w: record header runs past the payload", ErrNotADatabase)
	}
	var out []recordValue
	body := int(headerLen)
	offset := n
	for offset < int(headerLen) {
		serial, width, err := readVarint(payload[offset:])
		if err != nil {
			return nil, err
		}
		offset += width
		v, size, err := decodeValue(payload, body, serial)
		if err != nil {
			return nil, err
		}
		body += size
		out = append(out, v)
	}
	return out, nil
}

// decodeValue reads one value of the given serial type from the body.
func decodeValue(payload []byte, offset int, serial uint64) (recordValue, int, error) {
	var size int
	switch {
	case serial == 0:
		return recordValue{}, 0, nil
	case serial >= 1 && serial <= 6:
		size = [...]int{0, 1, 2, 3, 4, 6, 8}[serial]
	case serial == 7:
		size = 8
	case serial == 8:
		return intValue(0), 0, nil
	case serial == 9:
		return intValue(1), 0, nil
	case serial >= 12 && serial%2 == 0:
		size = int((serial - 12) / 2)
	case serial >= 13 && serial%2 == 1:
		size = int((serial - 13) / 2)
	default:
		return recordValue{}, 0, fmt.Errorf("%w: serial type %d is reserved", ErrNotADatabase, serial)
	}
	if offset+size > len(payload) {
		return recordValue{}, 0, fmt.Errorf("%w: value runs past the payload", ErrNotADatabase)
	}
	raw := payload[offset : offset+size]
	switch {
	case serial >= 13:
		return textValue(string(raw)), size, nil
	case serial == 7:
		// A float is not written by this package, but a file written by
		// another reader might carry one; it is decoded as its bit pattern so
		// the row stays aligned instead of being rejected.
		return recordValue{kind: kindNull}, size, nil
	default:
		var v int64
		switch len(raw) {
		case 1:
			v = int64(int8(raw[0]))
		case 2:
			v = int64(int16(binary.BigEndian.Uint16(raw)))
		case 3:
			v = int64(int32(raw[0])<<16 | int32(raw[1])<<8 | int32(raw[2]))
			if v >= 1<<23 {
				v -= 1 << 24
			}
		case 4:
			v = int64(int32(binary.BigEndian.Uint32(raw)))
		case 6:
			v = int64(raw[0])<<40 | int64(raw[1])<<32 | int64(raw[2])<<24 |
				int64(raw[3])<<16 | int64(raw[4])<<8 | int64(raw[5])
			if v >= 1<<47 {
				v -= 1 << 48
			}
		case 8:
			v = int64(binary.BigEndian.Uint64(raw))
		}
		return intValue(v), size, nil
	}
}

// putVarint writes a varint into dst and returns its width, one to nine bytes.
func putVarint(dst []byte, v uint64) int {
	if v <= 0x7f {
		dst[0] = byte(v)
		return 1
	}
	if v > 0x00ffffffffffffff {
		// Nine bytes: eight groups of seven bits, then a full byte.
		buf := [9]byte{}
		buf[8] = byte(v)
		v >>= 8
		for i := 7; i >= 0; i-- {
			buf[i] = byte(v&0x7f) | 0x80
			v >>= 7
		}
		copy(dst, buf[:])
		return 9
	}
	var buf [8]byte
	n := 0
	for {
		buf[n] = byte(v & 0x7f)
		n++
		v >>= 7
		if v == 0 {
			break
		}
	}
	for i := 0; i < n; i++ {
		b := buf[n-1-i]
		if i < n-1 {
			b |= 0x80
		}
		dst[i] = b
	}
	return n
}

// varintLen returns the width putVarint would use.
func varintLen(v uint64) int {
	switch {
	case v <= 0x7f:
		return 1
	case v > 0x00ffffffffffffff:
		return 9
	}
	n := 1
	for v >>= 7; v != 0; v >>= 7 {
		n++
	}
	return n
}

// readVarint reads a varint and returns its value and width.
func readVarint(src []byte) (uint64, int, error) {
	var v uint64
	for i := 0; i < 9; i++ {
		if i >= len(src) {
			return 0, 0, fmt.Errorf("%w: varint runs past the buffer", ErrNotADatabase)
		}
		b := src[i]
		if i == 8 {
			return (v << 8) | uint64(b), 9, nil
		}
		v = (v << 7) | uint64(b&0x7f)
		if b&0x80 == 0 {
			return v, i + 1, nil
		}
	}
	return 0, 0, fmt.Errorf("%w: varint is longer than nine bytes", ErrNotADatabase)
}

// getU16 and getU32 read the big-endian fields of the format.
func getU16(b []byte) uint16 { return binary.BigEndian.Uint16(b) }

func getU32(b []byte) uint32 { return binary.BigEndian.Uint32(b) }

// putU16 and putU32 write the big-endian fields of the format.
func putU16(b []byte, v uint16) { binary.BigEndian.PutUint16(b, v) }

func putU32(b []byte, v uint32) { binary.BigEndian.PutUint32(b, v) }

// table is one table of the database: its name, its schema statement and its
// rows in insertion order. Rowids are assigned from one when the image is
// built, so a table is always written in one go.
type table struct {
	name string
	sql  string
	rows [][]recordValue
}

// buildImage renders a complete database file from a set of tables.
//
// Pages are allocated in order as they are written, and page 1 is filled last
// because the schema rows name the root page of every table.
func buildImage(tables []table) ([]byte, error) {
	pages := [][]byte{make([]byte, pageSize)}
	alloc := func() (uint32, []byte) {
		page := make([]byte, pageSize)
		pages = append(pages, page)
		return uint32(len(pages)), page
	}

	type entry struct {
		name string
		root uint32
		sql  string
	}
	entries := make([]entry, 0, len(tables))
	for _, t := range tables {
		cells, err := encodeTableCells(t)
		if err != nil {
			return nil, err
		}
		var leaves []uint32
		var firstIDs []int64
		for i := 0; i < len(cells); {
			n, size := 0, 0
			for i+n < len(cells) {
				next := size + len(cells[i+n])
				// One pointer per cell plus the eight byte leaf header, and a
				// page that always holds at least one cell.
				if n > 0 && 8+2*(n+1)+next > pageSize {
					break
				}
				if n == 0 && 8+2+next > pageSize {
					return nil, fmt.Errorf("%w: a row of %s is %d bytes", ErrTooLarge, t.name, len(cells[i]))
				}
				size = next
				n++
			}
			number, page := alloc()
			if err := packLeafPage(page, 0, cells[i:i+n]); err != nil {
				return nil, err
			}
			leaves = append(leaves, number)
			firstIDs = append(firstIDs, int64(i+1))
			i += n
		}
		if len(leaves) == 0 {
			// A table with no rows still needs a root page: an empty leaf.
			number, page := alloc()
			if err := packLeafPage(page, 0, nil); err != nil {
				return nil, err
			}
			leaves = append(leaves, number)
			firstIDs = append(firstIDs, 0)
		}
		root := leaves[0]
		if len(leaves) > 1 {
			interior := make([][]byte, 0, len(leaves)-1)
			for i := 1; i < len(leaves); i++ {
				cell := make([]byte, 4, 4+9)
				putU32(cell, leaves[i-1])
				var buf [9]byte
				// The key of an interior cell is the largest rowid in the
				// subtree to its left, which is one below the first rowid of
				// the next leaf. Every other value satisfies "greater than the
				// left subtree" but not the format's own rule, and a reader
				// that trusts it would descend into the wrong child.
				n := putVarint(buf[:], uint64(firstIDs[i]-1))
				interior = append(interior, append(cell, buf[:n]...))
			}
			number, page := alloc()
			if err := packInteriorPage(page, interior, leaves[len(leaves)-1]); err != nil {
				return nil, fmt.Errorf("%w: %s needs more leaves than one page can address", ErrTooLarge, t.name)
			}
			root = number
		}
		entries = append(entries, entry{name: t.name, root: root, sql: t.sql})
	}

	// Page 1 holds the schema, in the space after the file header.
	schema := make([][]byte, 0, len(entries))
	for i, e := range entries {
		payload := encodeRecord([]recordValue{
			textValue("table"), textValue(e.name), textValue(e.name),
			intValue(int64(e.root)), textValue(e.sql),
		})
		cell, err := leafCell(payload, int64(i+1))
		if err != nil {
			return nil, err
		}
		schema = append(schema, cell)
	}
	if err := packLeafPage(pages[0], headerBytes, schema); err != nil {
		return nil, fmt.Errorf("%w: the schema does not fit page 1", ErrTooLarge)
	}

	image := make([]byte, 0, len(pages)*pageSize)
	for _, page := range pages {
		image = append(image, page...)
	}
	writeHeader(image, len(pages))
	if err := validateImage(image); err != nil {
		return nil, err
	}
	return image, nil
}

// leafCell renders one cell of a table leaf: the payload length, the rowid and
// the payload.
func leafCell(payload []byte, rowid int64) ([]byte, error) {
	if len(payload) > maxLocalPayload {
		return nil, fmt.Errorf("%w: a row of %d bytes needs an overflow page", ErrTooLarge, len(payload))
	}
	var buf [9]byte
	cell := make([]byte, 0, 10+len(payload))
	n := putVarint(buf[:], uint64(len(payload)))
	cell = append(cell, buf[:n]...)
	n = putVarint(buf[:], uint64(rowid))
	cell = append(cell, buf[:n]...)
	return append(cell, payload...), nil
}

// validateImage reads the file back before it is handed to the caller. A writer
// bug that produced an unreadable page would otherwise be found by the next
// start instead of here, and the previous file would already be gone.
func validateImage(image []byte) error {
	db, err := openImage(image)
	if err != nil {
		return err
	}
	roots, err := db.tableRoots()
	if err != nil {
		return err
	}
	for name, root := range roots {
		if _, err := db.scanTree(root); err != nil {
			return fmt.Errorf("%w: table %s: %v", ErrTooLarge, name, err)
		}
	}
	return nil
}

// encodeTableCells renders every row of a table as a leaf cell. Rowids run from
// one in insertion order.
func encodeTableCells(t table) ([][]byte, error) {
	cells := make([][]byte, 0, len(t.rows))
	for i, row := range t.rows {
		cell, err := leafCell(encodeRecord(row), int64(i+1))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", t.name, err)
		}
		cells = append(cells, cell)
	}
	return cells, nil
}

// packLeafPage writes a table leaf page: the header at base, the cell pointer
// array after it, and the cells at the end of the page growing downwards.
func packLeafPage(page []byte, base int, cells [][]byte) error {
	start := base + 8
	content := pageSize
	for _, cell := range cells {
		content -= len(cell)
	}
	if content < start+2*len(cells) {
		return ErrTooLarge
	}
	page[base] = pageTypeLeaf
	putU16(page[base+1:], 0)
	putU16(page[base+3:], uint16(len(cells)))
	putU16(page[base+5:], uint16(content))
	page[base+7] = 0
	offset := content
	for i, cell := range cells {
		copy(page[offset:], cell)
		putU16(page[start+2*i:], uint16(offset))
		offset += len(cell)
	}
	return nil
}

// packInteriorPage writes a table interior page: one cell per child except the
// last, which the page header points at, and the first rowid of the subtree each
// child leads to as the key.
func packInteriorPage(page []byte, cells [][]byte, right uint32) error {
	const start = 12
	content := pageSize
	for _, cell := range cells {
		content -= len(cell)
	}
	if content < start+2*len(cells) {
		return ErrTooLarge
	}
	page[0] = pageTypeInterior
	putU16(page[1:], 0)
	putU16(page[3:], uint16(len(cells)))
	putU16(page[5:], uint16(content))
	page[7] = 0
	putU32(page[8:], right)
	offset := content
	for i, cell := range cells {
		copy(page[offset:], cell)
		putU16(page[start+2*i:], uint16(offset))
		offset += len(cell)
	}
	return nil
}

// writeHeader fills the 100 bytes at the start of page 1.
func writeHeader(image []byte, pages int) {
	copy(image, "SQLite format 3\x00")
	putU16(image[16:], pageSize)
	image[18] = 1 // write format: legacy
	image[19] = 1 // read format: legacy
	image[20] = 0 // reserved bytes per page
	image[21] = 64
	image[22] = 32
	image[23] = 32
	putU32(image[24:], 1) // change counter
	putU32(image[28:], uint32(pages))
	putU32(image[32:], 0) // no freelist
	putU32(image[36:], 0)
	putU32(image[40:], schemaCookie)
	putU32(image[44:], schemaFormat)
	putU32(image[48:], 0) // default page cache size
	putU32(image[52:], 0) // no largest root page
	putU32(image[56:], encodingUTF8)
	putU32(image[60:], userVersion)
	putU32(image[64:], 0) // no incremental vacuum
	putU32(image[68:], 0) // no application id
	putU32(image[92:], 1) // version valid for, matching the change counter
	putU32(image[96:], writerLibrary)
}

// database is a parsed image. It is read-only: the store rewrites the whole file
// rather than patching it.
type database struct {
	image       []byte
	pageSize    int
	userVersion uint32
}

// openImage validates the header and returns a reader over the image.
func openImage(image []byte) (*database, error) {
	if len(image) < headerBytes+8 {
		return nil, ErrNotADatabase
	}
	if string(image[:16]) != "SQLite format 3\x00" {
		return nil, ErrNotADatabase
	}
	size := int(getU16(image[16:]))
	if size < 512 || size > 65536 || size&(size-1) != 0 {
		return nil, fmt.Errorf("%w: page size %d", ErrNotADatabase, size)
	}
	if len(image)%size != 0 {
		return nil, fmt.Errorf("%w: the file is not a whole number of pages", ErrNotADatabase)
	}
	declared := int(getU32(image[28:]))
	if declared != 0 && declared != len(image)/size {
		return nil, fmt.Errorf("%w: the header declares %d pages, the file holds %d",
			ErrNotADatabase, declared, len(image)/size)
	}
	if encoding := getU32(image[56:]); encoding != encodingUTF8 {
		return nil, fmt.Errorf("%w: text encoding %d", ErrNotADatabase, encoding)
	}
	return &database{image: image, pageSize: size, userVersion: getU32(image[60:])}, nil
}

// page returns the bytes of page number p, which is one based.
func (d *database) page(p uint32) ([]byte, error) {
	if p == 0 {
		return nil, fmt.Errorf("%w: page 0 does not exist", ErrNotADatabase)
	}
	start := int(p-1) * d.pageSize
	if start+d.pageSize > len(d.image) {
		return nil, fmt.Errorf("%w: page %d is past the end of the file", ErrNotADatabase, p)
	}
	return d.image[start : start+d.pageSize], nil
}

// pageBase is where the b-tree header of a page starts: after the file header
// for page 1, at the beginning of the page for every other page.
func pageBase(p uint32) int {
	if p == 1 {
		return headerBytes
	}
	return 0
}

// tableRoots reads the schema and returns the root page of every table.
func (d *database) tableRoots() (map[string]uint32, error) {
	rows, err := d.scanTree(1)
	if err != nil {
		return nil, err
	}
	out := make(map[string]uint32, len(rows))
	for _, payload := range rows {
		values, err := decodeRecord(payload)
		if err != nil {
			return nil, err
		}
		if len(values) < 5 || values[0].s != "table" {
			continue
		}
		out[values[1].s] = uint32(values[3].i)
	}
	return out, nil
}

// table returns the payloads of every row of a table, in rowid order.
func (d *database) table(name string) ([][]byte, error) {
	roots, err := d.tableRoots()
	if err != nil {
		return nil, err
	}
	root, ok := roots[name]
	if !ok {
		return nil, nil
	}
	return d.scanTree(root)
}

// scanTree walks the b-tree rooted at a page and returns the row payloads.
func (d *database) scanTree(root uint32) ([][]byte, error) {
	var out [][]byte
	var walk func(p uint32, depth int) error
	walk = func(p uint32, depth int) error {
		if depth > maxDepth {
			return fmt.Errorf("%w: the tree is deeper than %d levels", ErrNotADatabase, maxDepth)
		}
		page, err := d.page(p)
		if err != nil {
			return err
		}
		base := pageBase(p)
		if base+8 > len(page) {
			return fmt.Errorf("%w: page %d has no room for a header", ErrNotADatabase, p)
		}
		kind := page[base]
		count := int(getU16(page[base+3:]))
		if kind == pageTypeInterior {
			start := base + 12
			if start+2*count+4 > len(page) {
				return fmt.Errorf("%w: page %d has an impossible cell count", ErrNotADatabase, p)
			}
			for i := 0; i < count; i++ {
				offset := int(getU16(page[start+2*i:]))
				if offset+4 > len(page) {
					return fmt.Errorf("%w: page %d points outside itself", ErrNotADatabase, p)
				}
				if err := walk(getU32(page[offset:]), depth+1); err != nil {
					return err
				}
			}
			return walk(getU32(page[base+8:]), depth+1)
		}
		if kind != pageTypeLeaf {
			return fmt.Errorf("%w: page %d has type %d", ErrNotADatabase, p, kind)
		}
		start := base + 8
		if start+2*count > len(page) {
			return fmt.Errorf("%w: page %d has an impossible cell count", ErrNotADatabase, p)
		}
		for i := 0; i < count; i++ {
			offset := int(getU16(page[start+2*i:]))
			payload, err := d.payload(page, offset)
			if err != nil {
				return err
			}
			out = append(out, payload)
		}
		return nil
	}
	if err := walk(root, 0); err != nil {
		return nil, err
	}
	return out, nil
}

// payload reads the payload of one leaf cell.
func (d *database) payload(page []byte, offset int) ([]byte, error) {
	if offset <= 0 || offset >= len(page) {
		return nil, fmt.Errorf("%w: a cell offset points outside its page", ErrNotADatabase)
	}
	length, n, err := readVarint(page[offset:])
	if err != nil {
		return nil, err
	}
	_, m, err := readVarint(page[offset+n:])
	if err != nil {
		return nil, err
	}
	start := offset + n + m
	if length > uint64(len(page)-start) {
		return nil, fmt.Errorf("%w: a cell payload runs past its page (overflow pages are not written)",
			ErrNotADatabase)
	}
	return page[start : start+int(length)], nil
}
