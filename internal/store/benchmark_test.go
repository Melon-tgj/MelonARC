package store

// The cost of a flush, which is the only thing in this package that runs
// without a request waiting for it. It is here so that "is 30 seconds often
// enough" is answered with a number rather than an opinion.

import (
	"path/filepath"
	"testing"
	"time"
)

// benchStore is a store with all three tables at their default capacity, and
// the file already written once so the measurement is of the steady state.
//
// Measured on the reference machine (Linux/x86_64, Go 1.27, one flush of
// 2000 connections + 500 events + 1440 samples): about 39–42 ms with this
// build, against about 10–14 ms with the hand-written file writer it replaced
// (stage 19). One fsync is part of it — `_synchronous=full` buys the promise
// that a committed flush survives a power cut — and the rest is roughly 3900
// inserts through the translated engine.
func benchStore(tb testing.TB) *Store {
	tb.Helper()
	s, err := Open(Options{Path: filepath.Join(tb.TempDir(), FileName), FlushInterval: time.Hour})
	if err != nil {
		tb.Fatalf("Open: %v", err)
	}
	tb.Cleanup(func() {
		if err := s.Close(); err != nil {
			tb.Errorf("Close: %v", err)
		}
	})
	base := time.Date(2026, 11, 14, 8, 0, 0, 0, time.UTC)
	for i := 0; i < DefaultRetention.Connections; i++ {
		s.RecordConnection(Connection{
			At:       base.Add(time.Duration(i) * time.Second),
			Protocol: "http",
			Host:     "a-fairly-long-host-name.example.com",
			Port:     443,
			Network:  "tcp",
			Rule:     "DOMAIN-SUFFIX,example.com",
			Policy:   "manual",
			Outbound: "alpha",
			Up:       int64(i),
			Down:     int64(2 * i),
			Duration: time.Second,
		})
	}
	for i := 0; i < DefaultRetention.Events; i++ {
		s.RecordEvent(Event{At: base, Kind: KindReload, Name: "/etc/melonarc.ini", Detail: "3 rules", OK: true})
	}
	for i := 0; i < DefaultRetention.Samples; i++ {
		s.RecordSample(Sample{At: base.Add(time.Duration(i) * time.Minute), Up: int64(i), Down: int64(i)})
	}
	if err := s.Flush(); err != nil {
		tb.Fatalf("the first flush: %v", err)
	}
	return s
}

// BenchmarkFlushFullHistory measures one rewrite of a full history.
func BenchmarkFlushFullHistory(b *testing.B) {
	s := benchStore(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := s.Flush(); err != nil {
			b.Fatalf("Flush: %v", err)
		}
	}
}
