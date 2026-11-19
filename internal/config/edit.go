package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
