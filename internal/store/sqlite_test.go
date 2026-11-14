package store

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The format tests. The writer is exercised end to end: an image is built,
// written to a file and then read twice — by this package's own reader, and by
// the SQLite command line tool when the machine has one. The second reader is
// the point: a self-consistent bug in the writer would satisfy the first one.

// TestVarintRoundTrip covers the widths the format uses, including the nine byte
// form that carries a full byte in its last position.
func TestVarintRoundTrip(t *testing.T) {
	values := []uint64{
		0, 1, 0x7f, 0x80, 0x3fff, 0x4000, 1 << 20, 1 << 35,
		0x00ffffffffffffff, 1 << 56, 1<<63 + 12345, ^uint64(0),
	}
	for _, want := range values {
		var buf [9]byte
		n := putVarint(buf[:], want)
		if n != varintLen(want) {
			t.Errorf("putVarint(%d) wrote %d bytes, varintLen says %d", want, n, varintLen(want))
		}
		got, width, err := readVarint(buf[:n])
		if err != nil {
			t.Fatalf("readVarint(%d): %v", want, err)
		}
		if got != want || width != n {
			t.Errorf("varint round trip of %d gave %d in %d bytes", want, got, width)
		}
	}
	// A varint that claims more bytes than are there is a corrupt file, not a
	// panic.
	if _, _, err := readVarint([]byte{0x80}); err == nil {
		t.Error("readVarint accepted a truncated varint")
	}
}

// TestRecordRoundTrip covers the storage classes and the integer widths the
// encoder chooses.
func TestRecordRoundTrip(t *testing.T) {
	want := []recordValue{
		intValue(0),
		intValue(1),
		intValue(-1),
		intValue(127),
		intValue(-128),
		intValue(4096),
		intValue(-70000),
		intValue(1 << 40),
		intValue(-1 << 62),
		textValue(""),
		textValue("example.com"),
		textValue(strings.Repeat("x", 200)),
	}
	payload := encodeRecord(want)
	got, err := decodeRecord(payload)
	if err != nil {
		t.Fatalf("decodeRecord: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("decoded %d values, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("value %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	// The header length is a varint that counts itself. A row wide enough to
	// need a two byte header is the case that catches an off-by-one.
	wide := make([]recordValue, 0, 70)
	for i := 0; i < 70; i++ {
		wide = append(wide, textValue("v"))
	}
	payload = encodeRecord(wide)
	back, err := decodeRecord(payload)
	if err != nil {
		t.Fatalf("decodeRecord of a wide row: %v", err)
	}
	if len(back) != len(wide) {
		t.Fatalf("wide row decoded to %d values, want %d", len(back), len(wide))
	}
}

// TestImageIsReadBySQLite is the check that matters: a file written here is a
// database any SQLite reader opens.
func TestImageIsReadBySQLite(t *testing.T) {
	rows := [][]recordValue{
		{intValue(1700000000000), textValue("http"), textValue("example.com"), intValue(443), intValue(17), intValue(-3), textValue(""), textValue("a long policy name")},
		{intValue(1700000001000), textValue("socks5"), textValue("other.test"), intValue(80), intValue(0), intValue(0), textValue("rule"), textValue("DIRECT")},
	}
	image, err := buildImage([]table{{
		name: "connections",
		sql: "CREATE TABLE connections(" +
			"at INTEGER NOT NULL, protocol TEXT NOT NULL, host TEXT NOT NULL, port INTEGER NOT NULL, " +
			"up INTEGER NOT NULL, down INTEGER NOT NULL, rule TEXT NOT NULL, policy TEXT NOT NULL)",
		rows: rows,
	}})
	if err != nil {
		t.Fatalf("buildImage: %v", err)
	}
	path := writeTestImage(t, image)

	// The package's own reader must agree with what went in, reading the bytes
	// that are on disk rather than the slice the writer kept in memory.
	if info, err := os.Stat(path); err != nil || info.Size() != int64(len(image)) {
		t.Fatalf("written file: %v, %d bytes", err, len(image))
	}
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	db, err := openImage(onDisk)
	if err != nil {
		t.Fatalf("openImage: %v", err)
	}
	if db.userVersion != userVersion {
		t.Errorf("user version = %d, want %d", db.userVersion, userVersion)
	}
	payloads, err := db.table("connections")
	if err != nil {
		t.Fatalf("table: %v", err)
	}
	if len(payloads) != len(rows) {
		t.Fatalf("read back %d rows, want %d", len(payloads), len(rows))
	}
	for i, payload := range payloads {
		values, err := decodeRecord(payload)
		if err != nil {
			t.Fatalf("decode row %d: %v", i, err)
		}
		if len(values) != len(rows[i]) {
			t.Fatalf("row %d has %d columns, want %d", i, len(values), len(rows[i]))
		}
		if values[2].s != rows[i][2].s || values[1].i != rows[i][1].i || values[5].i != rows[i][5].i {
			t.Errorf("row %d read back as %+v", i, values)
		}
	}
}

// TestImageIsReadBySQLiteTool hands the file to the real implementation. It is
// skipped when the machine has no SQLite command line tool, which is the same
// rule the reference interop tests follow: a check that needs an external party
// says so and skips instead of pretending.
func TestImageIsReadBySQLiteTool(t *testing.T) {
	tool, err := exec.LookPath("sqlite3")
	if err != nil {
		t.Skip("no sqlite3 command line tool on this machine")
	}
	var rows [][]recordValue
	for i := 0; i < 500; i++ {
		rows = append(rows, []recordValue{
			intValue(int64(1700000000000 + i)),
			textValue(fmt.Sprintf("host-%03d.example", i)),
			intValue(int64(i)),
			textValue(strings.Repeat("z", i%120)),
		})
	}
	image, err := buildImage([]table{
		{
			name: "connections",
			sql:  "CREATE TABLE connections(at INTEGER NOT NULL, host TEXT NOT NULL, port INTEGER NOT NULL, note TEXT NOT NULL)",
			rows: rows,
		},
		{
			name: "events",
			sql:  "CREATE TABLE events(at INTEGER NOT NULL, kind TEXT NOT NULL)",
			rows: [][]recordValue{{intValue(1), textValue("reload")}},
		},
		{
			name: "samples",
			sql:  "CREATE TABLE samples(at INTEGER NOT NULL)",
		},
	})
	if err != nil {
		t.Fatalf("buildImage: %v", err)
	}
	path := writeTestImage(t, image)

	// 500 rows of up to 120 bytes do not fit one page, so this also checks the
	// interior page the writer places above the leaves.
	out := runSQLite(t, tool, path, "SELECT count(*), min(at), max(at) FROM connections;")
	if out != "500|1700000000000|1700000000499" {
		t.Errorf("count/min/max = %q", out)
	}
	if out := runSQLite(t, tool, path, "SELECT note FROM connections WHERE port = 499;"); out != strings.Repeat("z", 499%120) {
		t.Errorf("row 499 came back as %q", out)
	}
	if out := runSQLite(t, tool, path, "SELECT name FROM sqlite_schema ORDER BY name;"); out != "connections\nevents\nsamples" {
		t.Errorf("schema = %q", out)
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

// TestImageRejectsWhatItCannotRead covers the reader's guards: a file that is
// not a database, one that is truncated and one whose page count is a lie are
// all refused instead of being decoded into nonsense.
func TestImageRejectsWhatItCannotRead(t *testing.T) {
	image, err := buildImage([]table{{
		name: "events",
		sql:  "CREATE TABLE events(at INTEGER NOT NULL)",
		rows: [][]recordValue{{intValue(7)}},
	}})
	if err != nil {
		t.Fatalf("buildImage: %v", err)
	}
	if _, err := openImage([]byte("not a database at all, but long enough to look like one")); err == nil {
		t.Error("a text file was accepted as a database")
	}
	if _, err := openImage(image[:len(image)-100]); err == nil {
		t.Error("a truncated image was accepted")
	}
	lie := append([]byte(nil), image...)
	putU32(lie[28:], 99)
	if _, err := openImage(lie); err == nil {
		t.Error("a header claiming 99 pages was accepted for a one page file")
	}
	// An empty file has nothing to read, which a caller reports as "no history
	// yet" rather than as a database.
	if _, err := openImage(nil); err == nil {
		t.Error("an empty image was accepted")
	}
}

// TestBuildImageRefusesAnOversizedRow keeps the writer honest about the layout it
// implements: a row that would need an overflow page is refused, not written as
// something no reader can follow.
func TestBuildImageRefusesAnOversizedRow(t *testing.T) {
	_, err := buildImage([]table{{
		name: "events",
		sql:  "CREATE TABLE events(note TEXT NOT NULL)",
		rows: [][]recordValue{{textValue(strings.Repeat("x", maxLocalPayload))}},
	}})
	if err == nil {
		t.Fatal("buildImage accepted a row that cannot fit a page")
	}
	if !strings.Contains(err.Error(), "overflow") {
		t.Errorf("error = %v, want it to name the overflow page", err)
	}
}

// TestVarintWidthsMatchTheFormat pins the widths the encoder picks, so a change
// to the body layout is noticed by a test rather than by a reader.
func TestVarintWidthsMatchTheFormat(t *testing.T) {
	cases := []struct {
		v    int64
		want uint64
	}{
		{0, 8}, {1, 9}, {-1, 1}, {127, 1}, {-128, 1}, {128, 2}, {4096, 2},
		{1 << 30, 4}, {1 << 40, 6}, {-1 << 40, 6},
	}
	for _, c := range cases {
		serial, body := serialType(intValue(c.v))
		if serial != c.want {
			t.Errorf("serialType(%d) = %d, want %d", c.v, serial, c.want)
		}
		encoded := encodeRecord([]recordValue{intValue(c.v)})
		values, err := decodeRecord(encoded)
		if err != nil {
			t.Fatalf("decodeRecord(%d): %v", c.v, err)
		}
		if values[0].i != c.v {
			t.Errorf("%d read back as %d in %d body bytes", c.v, values[0].i, body)
		}
	}
}

// writeTestImage writes an image to a file the tests can hand to another tool.
func writeTestImage(t *testing.T, image []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "history.sqlite3")
	if err := os.WriteFile(path, image, 0o600); err != nil {
		t.Fatalf("write image: %v", err)
	}
	return path
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
