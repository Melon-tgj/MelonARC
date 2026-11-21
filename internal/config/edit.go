package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// GeneralPatch is the set of [General] values the local API may change.
//
// Pointers keep "absent" distinct from "set to false or empty": a settings
// client that only wants to turn the desktop proxy off must not clear the log
// level as a side effect. The fields are deliberately few; adding another one
// is a validation rule, an edit rule and one more test, not a new transport.
type GeneralPatch struct {
	LogLevel    *string
	SystemProxy *bool
}

// UpdateGeneralFile applies patch to the [General] section of path. The file
// is parsed and validated after the edit, so an invalid patch never replaces a
// loadable configuration on disk. Every other line is kept in place, including
// comments and blank lines, and the write is atomic within the directory.
func UpdateGeneralFile(path string, patch GeneralPatch) error {
	if patch.LogLevel == nil && patch.SystemProxy == nil {
		return errors.New("a settings update must change at least one field")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read configuration: %w", err)
	}
	updated, err := editGeneral(data, patch)
	if err != nil {
		return err
	}
	cfg, err := Parse(updated)
	if err != nil {
		return fmt.Errorf("validate edited configuration: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("validate edited configuration: %w", err)
	}
	if err := atomicWrite(path, updated); err != nil {
		return err
	}
	return nil
}

// SubscriptionPatch is one [Subscription] declaration the local API adds.
//
// Interval is a duration rather than a string so a caller cannot smuggle a
// second option or a comment into the line; a zero value means the package
// default of six hours.
type SubscriptionPatch struct {
	Name     string
	URL      string
	Interval time.Duration
}

// ErrConfigChanged reports that the file no longer holds the bytes a caller
// prepared against. The create path maps it to a conflict the client may retry.
var ErrConfigChanged = errors.New("the configuration file changed while the request was in flight")

// SubscriptionConflict reports a name that already carries a different
// declaration. The URL is deliberately left out of the message: it may carry a
// private token, and this error is written to logs and audit records.
type SubscriptionConflict struct {
	Name string
}

func (e *SubscriptionConflict) Error() string {
	return fmt.Sprintf("subscription %q already exists with a different declaration", e.Name)
}

// ValidateSubscriptionPatch rejects a declaration that cannot be written as a
// single [Subscription] line and round-trip through Parse unchanged. The rules
// are the same ones the loader applies; a value that fails them must be refused
// with a client error before any network access or file write.
func ValidateSubscriptionPatch(patch SubscriptionPatch) error {
	if err := validName(patch.Name); err != nil {
		return err
	}
	if strings.ContainsAny(patch.Name, "=\r\n") {
		return fmt.Errorf("name %q cannot be written as a single key", patch.Name)
	}
	if strings.IndexFunc(patch.URL, func(r rune) bool {
		return r <= 0x20 || r == 0x7f || r == '"' || r == '\r' || r == '\n'
	}) >= 0 {
		return fmt.Errorf("the url contains a character that cannot be written on one line")
	}
	if err := validSubscriptionURL(patch.URL); err != nil {
		return err
	}
	interval := patch.Interval
	if interval == 0 {
		interval = defaultSubscriptionInterval
	}
	if interval < minSubscriptionInterval {
		return fmt.Errorf("interval must be at least %s", minSubscriptionInterval)
	}
	return nil
}

// EditSubscription returns the text with the declaration added. It reports
// changed=false when the name already carries exactly the same declaration, so
// a retried create is idempotent without rewriting the file. A name with a
// different declaration is a SubscriptionConflict.
func EditSubscription(data []byte, patch SubscriptionPatch) ([]byte, bool, error) {
	if err := ValidateSubscriptionPatch(patch); err != nil {
		return nil, false, err
	}
	interval := patch.Interval
	if interval == 0 {
		interval = defaultSubscriptionInterval
	}
	lines := splitLines(data)
	section := -1
	for i, line := range lines {
		text := cleanLine(line.text)
		if !strings.HasPrefix(text, "[") {
			continue
		}
		name, err := parseSectionHeader(text)
		if err != nil {
			return nil, false, fmt.Errorf("line %d: %w", line.number, err)
		}
		if strings.EqualFold(name, "Subscription") {
			section = i
			break
		}
	}
	line := fmt.Sprintf("%s = %s interval=%d", patch.Name, patch.URL, int64(interval/time.Second))
	if section >= 0 {
		end := len(lines)
		for i := section + 1; i < len(lines); i++ {
			text := cleanLine(lines[i].text)
			if strings.HasPrefix(text, "[") {
				if _, err := parseSectionHeader(text); err != nil {
					return nil, false, fmt.Errorf("line %d: %w", lines[i].number, err)
				}
				end = i
				break
			}
			key, value, ok := splitKeyValue(text)
			if !ok || !strings.EqualFold(key, patch.Name) {
				continue
			}
			existing, err := parseSubscription(key, value, lines[i].number)
			if err != nil {
				return nil, false, fmt.Errorf("line %d: %w", lines[i].number, err)
			}
			if existing.URL == patch.URL && existing.Interval == interval {
				return data, false, nil
			}
			return nil, false, &SubscriptionConflict{Name: patch.Name}
		}
		tail := append([]sourceLine{{text: line}}, lines[section+1:end]...)
		lines = append(lines[:section+1], append(tail, lines[end:]...)...)
	} else {
		if len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1].text) != "" {
			lines = append(lines, sourceLine{})
		}
		lines = append(lines, sourceLine{text: "[Subscription]"}, sourceLine{text: line})
	}
	updated := []byte(strings.Join(plainLines(lines), "\n"))
	cfg, err := Parse(updated)
	if err != nil {
		return nil, false, fmt.Errorf("validate edited configuration: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, false, fmt.Errorf("validate edited configuration: %w", err)
	}
	return updated, true, nil
}

// CheckFileVersion reports whether path still holds expected bytes. A create
// calls it inside the daemon's commit section, before writing and installing,
// so a concurrent hand edit cannot be overwritten by a stale declaration.
func CheckFileVersion(path string, expected []byte) error {
	current, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read configuration: %w", err)
	}
	if !bytes.Equal(current, expected) {
		return ErrConfigChanged
	}
	return nil
}

// ReplaceFile writes updated to path only when the file still holds expected.
// The candidate is parsed and validated again at the commit point, so a failed
// create never leaves a configuration the next startup would refuse.
func ReplaceFile(path string, expected, updated []byte) error {
	current, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read configuration: %w", err)
	}
	if !bytes.Equal(current, expected) {
		return ErrConfigChanged
	}
	cfg, err := Parse(updated)
	if err != nil {
		return fmt.Errorf("validate edited configuration: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("validate edited configuration: %w", err)
	}
	return atomicWrite(path, updated)
}

// editGeneral returns the patched text without touching the file. It is a
// function of its arguments so the line rules can be tested without a disk.
func editGeneral(data []byte, patch GeneralPatch) ([]byte, error) {
	lines := splitLines(data)
	general := -1
	for i, line := range lines {
		text := cleanLine(line.text)
		if !strings.HasPrefix(text, "[") {
			continue
		}
		name, err := parseSectionHeader(text)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", line.number, err)
		}
		if strings.EqualFold(name, "General") {
			general = i
			break
		}
	}
	if general < 0 {
		return nil, errors.New("the configuration has no [General] section")
	}

	foundLog := false
	foundProxy := false
	end := len(lines)
	for i := general + 1; i < len(lines); i++ {
		text := cleanLine(lines[i].text)
		if strings.HasPrefix(text, "[") {
			if _, err := parseSectionHeader(text); err != nil {
				return nil, fmt.Errorf("line %d: %w", lines[i].number, err)
			}
			end = i
			break
		}
		key, _, ok := splitKeyValue(cleanLine(lines[i].text))
		if !ok {
			continue
		}
		lower := strings.ToLower(key)
		switch lower {
		case "log-level":
			if patch.LogLevel == nil || foundLog {
				continue
			}
			lines[i].text = replaceValue(lines[i].text, *patch.LogLevel)
			foundLog = true
		case "system-proxy":
			if patch.SystemProxy == nil || foundProxy {
				continue
			}
			value := "off"
			if *patch.SystemProxy {
				value = "on"
			}
			lines[i].text = replaceValue(lines[i].text, value)
			foundProxy = true
		}
	}

	// Missing keys are inserted after the section header in a fixed order, so
	// two clients writing different fields do not produce different layouts.
	var inserted []sourceLine
	if patch.LogLevel != nil && !foundLog {
		inserted = append(inserted, sourceLine{text: "log-level = " + *patch.LogLevel})
	}
	if patch.SystemProxy != nil && !foundProxy {
		value := "off"
		if *patch.SystemProxy {
			value = "on"
		}
		inserted = append(inserted, sourceLine{text: "system-proxy = " + value})
	}
	if len(inserted) > 0 {
		tail := append([]sourceLine{}, inserted...)
		tail = append(tail, lines[general+1:end]...)
		lines = append(lines[:general+1], append(tail, lines[end:]...)...)
	}
	return []byte(strings.Join(plainLines(lines), "\n")), nil
}

// replaceValue keeps the key and any trailing comment of a line. Only the
// value between the first "=" and the comment is replaced.
func replaceValue(raw, value string) string {
	equal := strings.IndexByte(raw, '=')
	if equal < 0 {
		return raw
	}
	prefix := strings.TrimRight(raw[:equal], " \t") + " = "
	remainder := raw[equal+1:]
	inQuotes := false
	for i := 1; i < len(remainder); i++ {
		switch remainder[i] {
		case '"':
			inQuotes = !inQuotes
		case '#', ';':
			if !inQuotes && (remainder[i-1] == ' ' || remainder[i-1] == '\t') {
				return prefix + value + " " + strings.TrimLeft(remainder[i:], " \t")
			}
		}
	}
	return prefix + value
}

func plainLines(lines []sourceLine) []string {
	out := make([]string, len(lines))
	for i, line := range lines {
		out[i] = line.text
	}
	return out
}

// atomicWrite replaces path through a new file in the same directory. The new
// file is private until rename; the mode of an existing configuration is kept
// so an editor's permissions do not change behind its back.
func atomicWrite(path string, data []byte) error {
	mode := os.FileMode(0o600)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".melonarc-config-*")
	if err != nil {
		return fmt.Errorf("create temporary configuration: %w", err)
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return fmt.Errorf("set configuration mode: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write configuration: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync configuration: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close configuration: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("replace configuration: %w", err)
	}
	return nil
}
