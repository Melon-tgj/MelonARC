// Package store persists the connection and traffic observations of the daemon
// in a SQLite database.
//
// It is a side channel, never a dependency of the data path: a record is kept in
// memory and written later, a write that fails is reported through Status and
// retried with the next flush, and nothing here blocks a request or returns an
// error to one. What it buys is the thing the live counters cannot give —
// history, readable after a restart and by an ordinary SQLite reader.
//
// The file is written through database/sql and modernc.org/sqlite. The tables
// are bounded (see Retention), and a flush replaces all three from memory in one
// transaction: a reader sees the previous flush or the new one, never half of
// one, and the cost is a copy of at most a few thousand rows. A file this build
// cannot read is never written at all — it is inspected read-only, preserved
// byte for byte, and the store runs on memory alone for the rest of the run.
package store
