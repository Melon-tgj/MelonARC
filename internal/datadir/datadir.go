// Package datadir locates the directory the core keeps its local state in and
// manages the API token file inside it.
//
// The daemon and the CLI resolve the directory the same way, which is what lets
// the CLI find the token without being told where it is: an explicit setting
// wins, otherwise the platform configuration directory plus the product name.
// The token file is the only thing distributed this way for now; a future
// connection log or latency history would live next to it.
package datadir

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Fixed names and limits of the directory.
const (
	// DefaultDirName is the directory created under the user's configuration
	// directory when nothing else is configured.
	DefaultDirName = "melonarc"
	// TokenFile is the name of the API token file inside the data directory.
	TokenFile = "api-token"
	// MaxTokenLen bounds what ReadToken accepts. A token is 43 bytes of base64
	// today; the limit only exists so a corrupt or replaced file is rejected
	// instead of being sent as an Authorization header.
	MaxTokenLen = 512
)

// File modes. The data directory holds a credential, so neither the directory
// nor the file is shared with other users of the machine.
const (
	dirMode   os.FileMode = 0o700
	tokenMode os.FileMode = 0o600
)

// Default returns the data directory used when none is configured: the
// platform's configuration directory plus DefaultDirName.
func Default() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("datadir: no configuration directory for this user: %w", err)
	}
	return filepath.Join(base, DefaultDirName), nil
}

// Resolve returns the data directory to use. An empty explicit value means the
// default; a relative one is resolved against baseDir, which for the daemon is
// the directory of its configuration file, so a relative setting does not
// depend on the working directory a service manager happens to start it in.
func Resolve(baseDir, explicit string) (string, error) {
	dir := strings.TrimSpace(explicit)
	if dir == "" {
		return Default()
	}
	if !filepath.IsAbs(dir) {
		if baseDir == "" {
			return "", fmt.Errorf("datadir: %q is relative and there is no base directory to resolve it against", dir)
		}
		dir = filepath.Join(baseDir, dir)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("datadir: resolve %s: %w", dir, err)
	}
	return filepath.Clean(abs), nil
}

// TokenPath returns the path of the token file inside a data directory.
func TokenPath(dir string) string { return filepath.Join(dir, TokenFile) }

// WriteToken writes token to the data directory and returns the path it wrote.
//
// The file is created with 0600 and replaced atomically: a client reading the
// file either sees the previous token or the new one, never a partial write, and
// a token file left over from a previous run cannot survive as a stale
// credential if the write fails.
func WriteToken(dir, token string) (string, error) {
	if err := checkToken(token); err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return "", fmt.Errorf("datadir: create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, "."+TokenFile+"-*")
	if err != nil {
		return "", fmt.Errorf("datadir: create a token file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	// CreateTemp already uses 0600, but an explicit chmod keeps the guarantee
	// from depending on that, and covers the case of a umask applied by a
	// caller's own file creation.
	if err := tmp.Chmod(tokenMode); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return "", fmt.Errorf("datadir: set the token file permissions: %w", err)
	}
	if _, err := tmp.WriteString(token + "\n"); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return "", fmt.Errorf("datadir: write the token file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return "", fmt.Errorf("datadir: flush the token file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return "", fmt.Errorf("datadir: close the token file: %w", err)
	}
	path := TokenPath(dir)
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return "", fmt.Errorf("datadir: install %s: %w", path, err)
	}
	return path, nil
}

// ReadToken reads the token file of a data directory. The trailing newline the
// daemon writes is not part of the token.
func ReadToken(dir string) (string, error) { return ReadTokenFile(TokenPath(dir)) }

// ReadTokenFile reads a token file by path, which is what a client uses when it
// was pointed at a file explicitly.
func ReadTokenFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("datadir: read %s: %w", path, err)
	}
	token := strings.TrimSpace(string(data))
	if err := checkToken(token); err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	return token, nil
}

// checkToken rejects a value that cannot be sent as a bearer token. The check is
// deliberately about shape rather than about the alphabet: what matters is that
// the file holds one non-empty line and not a message a user pasted there.
func checkToken(token string) error {
	switch {
	case token == "":
		return errors.New("datadir: the token is empty")
	case len(token) > MaxTokenLen:
		return fmt.Errorf("datadir: the token is longer than %d bytes", MaxTokenLen)
	}
	for i := 0; i < len(token); i++ {
		if c := token[i]; c <= 0x20 || c == 0x7f {
			return errors.New("datadir: the token contains whitespace or control characters")
		}
	}
	return nil
}
