//go:build !linux && !windows && !darwin

package sysproxy

import "context"

// platform returns a backend that refuses, so a build for another system keeps
// the configuration readable and reports why the setting cannot be written
// instead of silently doing nothing.
func platform() Backend { return unsupported{} }

// unsupported is the backend of a system this build cannot configure.
type unsupported struct{}

func (unsupported) Name() string { return "unsupported" }

func (unsupported) Enabled(context.Context) (bool, error) { return false, ErrUnsupported }

func (unsupported) Apply(context.Context, Settings) error { return ErrUnsupported }

func (unsupported) Plan(context.Context, Settings) (Snapshot, error) {
	return Snapshot{}, ErrUnsupported
}

func (unsupported) Commit(context.Context, Snapshot) error { return ErrUnsupported }

func (unsupported) Restore(context.Context, Snapshot) (RestoreResult, error) {
	return RestoreResult{}, ErrUnsupported
}

func (unsupported) Clear(context.Context) error { return ErrUnsupported }
