// Package store persists the connection and traffic observations of the daemon
// in a SQLite database.
//
// It is a side channel, never a dependency of the data path: a record is kept in
// memory and written later, a write that fails is reported through Status and
// retried with the next flush, and nothing here blocks a request or returns an
// error to one. What it buys is the thing the live counters cannot give —
// history, readable after a restart and by an ordinary SQLite reader.
//
// The tables are bounded (see Retention). That bound is what makes the write
// strategy possible: the whole file is rewritten from memory at every flush,
// which needs no free list, no incremental b-tree surgery and no journal, and
// costs a copy of at most a few hundred kilobytes.
package store
