package subscription

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// cacheDirName is the directory below the data directory that holds subscription
// bodies. It sits beside the API token file, which is the other thing the core
// keeps there.
const cacheDirName = "subscriptions"

// cachePath returns where a subscription's last good body is kept, or "" when
// the cache is off.
func (m *Manager) cachePath(name string) string {
	if m.opts.CacheDir == "" {
		return ""
	}
	return filepath.Join(m.opts.CacheDir, cacheDirName, safeFileName(name)+".txt")
}

// safeFileName turns a subscription name into a file name. Names may contain
// characters a path must not, and the result only has to be stable.
func safeFileName(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "subscription"
	}
	return b.String()
}

// writeCache stores a body as the last good result. A failure to write is
// logged, not returned: the nodes are in memory and the daemon can run; losing
// the cache only costs the next cold start.
func (m *Manager) writeCache(name string, body []byte) {
	path := m.cachePath(name)
	if path == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		m.log().Warn("cannot create the subscription cache directory", "error", err)
		return
	}
	// The body is written to a temporary file and renamed into place so a
	// reader never sees half a list.
	tmp, err := os.CreateTemp(filepath.Dir(path), ".sub-*")
	if err != nil {
		m.log().Warn("cannot write the subscription cache", "error", err)
		return
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		m.log().Warn("cannot write the subscription cache", "error", err)
		return
	}
	if err := tmp.Close(); err != nil {
		m.log().Warn("cannot write the subscription cache", "error", err)
		return
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		m.log().Warn("cannot restrict the subscription cache file", "error", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		m.log().Warn("cannot install the subscription cache file", "error", err)
	}
}

// readCache returns the last good body of a subscription.
func (m *Manager) readCache(name string) ([]byte, error) {
	path := m.cachePath(name)
	if path == "" {
		return nil, fmt.Errorf("the cache is off")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("the cached body is empty")
	}
	return body, nil
}
