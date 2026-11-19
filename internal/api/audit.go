package api

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
	"unicode/utf8"
)

// DefaultAuditCapacity is how many write operations the API remembers.
//
// The bound is fixed for the same reason the failure record's is: the record
// exists so an operator can see what was done to a running daemon, and it must
// not grow with the number of requests. A few dozen entries cover "what changed
// in the last few minutes", which is the question it answers.
const DefaultAuditCapacity = 64

// The write operations the API records.
const (
	// ActionPolicySelect pins a manual policy group to a member.
	ActionPolicySelect = "policy.select"
	// ActionConfigReload re-reads the configuration file.
	ActionConfigReload = "config.reload"
	// ActionConfigUpdate writes local settings to the configuration file.
	ActionConfigUpdate = "config.update"
	// ActionSubscriptionRefresh forces one subscription to fetch now.
	ActionSubscriptionRefresh = "subscription.refresh"
)

// The outcomes an audit entry can carry.
const (
	// ResultOK is a write operation that took effect.
	ResultOK = "ok"
	// ResultFailed is a write operation that was refused or failed. The daemon
	// state is unchanged in that case, which is what makes the distinction
	// worth recording.
	ResultFailed = "failed"
)

// maxAuditDetailLen bounds the detail of one entry. The detail repeats a group
// and a member name or a configuration problem, both of which are written by
// the user; the cut keeps one entry from crowding out the rest of the ring.
const maxAuditDetailLen = 240

// AuditEntry is one write operation the API carried out or refused.
type AuditEntry struct {
	// Time is when the request was answered.
	Time time.Time
	// Action is one of the Action constants.
	Action string
	// Result is ResultOK or ResultFailed.
	Result string
	// Detail names what changed, or why nothing did.
	Detail string
	// Remote is the address of the client, without its port.
	Remote string
}

// auditLog is a fixed-size ring of the most recent write operations. Writing
// past the end overwrites the oldest entry, the same eviction rule the failure
// record uses.
type auditLog struct {
	mu    sync.Mutex
	buf   []AuditEntry
	next  int
	count int
}

// newAuditLog returns a ring of the given capacity, which must be positive.
func newAuditLog(capacity int) *auditLog {
	return &auditLog{buf: make([]AuditEntry, capacity)}
}

// add appends an entry, dropping the oldest one when the ring is full.
func (a *auditLog) add(entry AuditEntry) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.buf[a.next] = entry
	a.next = (a.next + 1) % len(a.buf)
	if a.count < len(a.buf) {
		a.count++
	}
}

// snapshot copies the retained entries, oldest first, keeping at most limit of
// the newest ones.
func (a *auditLog) snapshot(limit int) []AuditEntry {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]AuditEntry, 0, a.count)
	start := a.next - a.count
	if start < 0 {
		start += len(a.buf)
	}
	for i := 0; i < a.count; i++ {
		out = append(out, a.buf[(start+i)%len(a.buf)])
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}

// len returns how many entries are retained.
func (a *auditLog) len() int {
	if a == nil {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.count
}

// capacity returns how many entries fit.
func (a *auditLog) capacity() int {
	if a == nil {
		return 0
	}
	return len(a.buf)
}

// record keeps one entry and mirrors it to the process log.
//
// The record is the source of truth: it is queryable and survives a log level
// that hides info lines. The log line exists so an operator who is watching the
// daemon sees a change as it happens, without polling the endpoint.
func (s *Server) record(r *http.Request, action, result, detail string) {
	entry := AuditEntry{
		Time:   time.Now(),
		Action: action,
		Result: result,
		Detail: truncateRunes(detail, maxAuditDetailLen),
		Remote: remoteHost(r),
	}
	s.audit.add(entry)

	level := slog.LevelInfo
	if result != ResultOK {
		level = slog.LevelWarn
	}
	s.logger.Log(context.Background(), level, "api "+action,
		"result", result, "detail", entry.Detail, "remote", entry.Remote)
}

// remoteHost returns the client address of a request without its port.
func remoteHost(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// truncateRunes cuts text to at most max bytes at a rune boundary, so a record
// stays valid text even when a name contains multi-byte characters.
func truncateRunes(text string, max int) string {
	if len(text) <= max {
		return text
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(text[cut]) {
		cut--
	}
	return text[:cut] + "..."
}
