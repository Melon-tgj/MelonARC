package sysproxy

// Status is the runtime takeover state a controller can report to a client.
//
// It is a snapshot of facts, not a decision: the desktop shell decides what to
// show. Keeping the four facts here rather than letting a client re-read the
// configuration and the snapshot file is what makes the states consistent with
// what this process actually did.
type Status struct {
	// Applied is true when this process itself wrote the desktop proxy setting
	// and has not put it back yet. A setting the user turned on by hand is not
	// ours and never sets this.
	Applied bool
	// RecoveryFailed is true when a takeover record left by an earlier process
	// could not be fully put back. The record is retained on disk on purpose so
	// a later start can retry; the shell must say so rather than report a clean
	// machine.
	RecoveryFailed bool
	// Detail is a short, non-secret reason for RecoveryFailed. It never holds
	// a proxy address with credentials or the content of a snapshot.
	Detail string
}

// Status returns the controller's current report.
//
// The fields are written only on the startup and shutdown paths (Enable,
// Recover, Release), before the API begins serving, so reading them from an
// API handler needs no lock. A controller that has done nothing reports the
// zero value: nothing applied, nothing failed.
func (c *Controller) Status() Status {
	return Status{
		Applied:        c.applied,
		RecoveryFailed: c.recoveryFailed,
		Detail:         c.recoveryDetail,
	}
}

// noteRecovery records a recovery problem without changing which settings this
// process owns. Callers still return the underlying error to their caller.
func (c *Controller) noteRecovery(detail string) {
	c.recoveryFailed = true
	c.recoveryDetail = detail
}
