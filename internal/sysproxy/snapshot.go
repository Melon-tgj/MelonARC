package sysproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// SnapshotFile is the name of the takeover record in the data directory.
//
// The record is written BEFORE the first setting is changed. A process that is
// killed between writing the settings and exiting normally therefore still
// leaves the machine with a description of what it changed, which the next
// start can put back.
const SnapshotFile = "system-proxy.json"

// Field is one system setting around a takeover.
//
// The distinction between Before and Written is what protects a user who edits
// the proxy settings while the daemon runs: a restore touches a field only
// while its current value is still Written. Anything else belongs to the user.
type Field struct {
	// Schema is the gsettings schema. It is empty for a registry value.
	Schema string `json:"schema,omitempty"`
	// Key is the gsettings key or the registry value name. On macOS it is the
	// kind of proxy setting within one network service.
	Key string `json:"key"`
	// Service is the network service a macOS field belongs to. It is empty for
	// the other backends, whose setting is not per service.
	Service string `json:"service,omitempty"`

	// Before is the value in force before the takeover, in the same form the
	// backend writes it. BeforeKind is its registry value type.
	Before     string `json:"before,omitempty"`
	BeforeKind string `json:"before_kind,omitempty"`
	// Present is false when the value did not exist before the takeover. Such a
	// value is deleted on restore rather than written back.
	Present bool `json:"present"`

	// Written is the value this program put in place, and WrittenKind is its
	// registry value type. Both are used only for the equality check.
	Written     string `json:"written"`
	WrittenKind string `json:"written_kind,omitempty"`

	// Observed marks a value that is recorded but never written, so a restore
	// has nothing to put back. macOS keeps the PAC address in a field that can
	// only be written together with "switch it on"; the takeover therefore only
	// switches PAC off and records the address for whoever reads the file.
	Observed bool `json:"observed,omitempty"`
}

// Snapshot is one takeover, persisted so a hard kill cannot lose it.
type Snapshot struct {
	Backend string    `json:"backend"`
	TakenAt time.Time `json:"taken_at"`
	Fields  []Field   `json:"fields"`
}

// RestoreResult reports what a restore did. Kept counts fields the user changed
// after the takeover, and which the program therefore refused to overwrite.
type RestoreResult struct {
	Restored int
	Kept     int
}

// restoreFields puts a snapshot back one field at a time, in reverse order.
//
// Reverse order matters: both backends write the "switch the proxy on" field
// last, so a restore has to put that one back first. Otherwise there is a
// window in which an enabled proxy still points at an address the daemon is
// about to stop answering.
//
// read reports the current value and whether it exists. A missing value means
// the user deleted it, which is a change the restore must keep.
func restoreFields[T any](
	fields []Field,
	read func(Field) (T, bool, error),
	same func(Field, T) bool,
	put func(Field) error,
	del func(Field) error,
) (RestoreResult, error) {
	var result RestoreResult
	var problems []error
	for i := len(fields) - 1; i >= 0; i-- {
		f := fields[i]
		if f.Observed {
			continue
		}
		current, present, err := read(f)
		if err != nil {
			problems = append(problems, fmt.Errorf("read %s: %w", fieldName(f), err))
			continue
		}
		if !present || !same(f, current) {
			result.Kept++
			continue
		}
		if f.Present {
			err = put(f)
		} else {
			err = del(f)
		}
		if err != nil {
			problems = append(problems, fmt.Errorf("restore %s: %w", fieldName(f), err))
			continue
		}
		result.Restored++
	}
	return result, errors.Join(problems...)
}

// fieldName is how a field is named in an error message: the network service
// and the kind of setting on macOS, the schema and the key elsewhere.
func fieldName(f Field) string {
	switch {
	case f.Service != "":
		return f.Service + " " + f.Key
	case f.Schema != "":
		return f.Schema + " " + f.Key
	default:
		return f.Key
	}
}

// saveSnapshot replaces the takeover record atomically. A partial file would be
// worse than no file: the next start could not tell which fields it owns.
func saveSnapshot(path string, snap Snapshot) error {
	if path == "" {
		return nil
	}
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return fmt.Errorf("encode the system proxy snapshot: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, "."+SnapshotFile+"-*")
	if err != nil {
		return fmt.Errorf("create a system proxy snapshot in %s: %w", dir, err)
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("set the snapshot permissions: %w", err)
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return fmt.Errorf("write the snapshot: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close the snapshot: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("install %s: %w", path, err)
	}
	return nil
}

// loadSnapshot reads a takeover record. A missing file is not an error: it is
// the normal state of a machine the daemon never took over.
func loadSnapshot(path string) (Snapshot, error) {
	var snap Snapshot
	if path == "" {
		return snap, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return snap, err
	}
	if err := json.Unmarshal(data, &snap); err != nil {
		return snap, fmt.Errorf("decode %s: %w", path, err)
	}
	if snap.Backend == "" || len(snap.Fields) == 0 {
		return snap, fmt.Errorf("%s holds no takeover record", path)
	}
	return snap, nil
}

// removeSnapshot forgets a takeover. It is called only after the restore has
// succeeded, so a failed restore leaves the record for the next start.
func removeSnapshot(path string) error {
	if path == "" {
		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove %s: %w", path, err)
	}
	return nil
}

// recover is the startup path for a takeover a previous process did not live
// to release. It is deliberately separate from Release: Release knows its own
// snapshot, recover has to trust the file on disk.
func recoverSnapshot(ctx context.Context, path string, b Backend) (bool, error) {
	if path == "" {
		return false, nil
	}
	snap, err := loadSnapshot(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	if snap.Backend != b.Name() {
		return false, fmt.Errorf("%s was written by the %q backend, this machine uses %q; the record is kept",
			path, snap.Backend, b.Name())
	}
	if _, err := b.Restore(ctx, snap); err != nil {
		return false, err
	}
	if err := removeSnapshot(path); err != nil {
		return false, err
	}
	return true, nil
}
