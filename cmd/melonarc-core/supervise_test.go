package main

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/melon-tgj/melonarc/internal/config"
)

// loadSupervisedConfig writes a configuration with the given [General] body into
// dir and loads it, so BaseDir is dir and a relative data-dir is predictable.
func loadSupervisedConfig(t *testing.T, dir, general string) *config.Config {
	t.Helper()
	path := filepath.Join(dir, "melonarc.conf")
	raw := "[General]\n" + general + "\n[Rule]\nFINAL,DIRECT\n"
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatalf("write configuration: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	return cfg
}

// bufferLogger keeps the log so a test can assert what a user would read.
func bufferLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})), &buf
}

// A shell that passes an absolute data directory must get exactly that
// directory, whatever the configuration says — including the relative value the
// example file carries, which is the case that used to split the token from the
// shell.
func TestResolveDataDirPrefersTheFlag(t *testing.T) {
	dir := t.TempDir()
	cfg := loadSupervisedConfig(t, dir, "data-dir = ./melonarc-data")

	logger, logs := bufferLogger()
	fromFile, err := resolveDataDir(cfg, "", logger)
	if err != nil {
		t.Fatalf("resolveDataDir without a flag: %v", err)
	}
	if want := filepath.Join(dir, "melonarc-data"); fromFile != want {
		t.Fatalf("data directory without a flag: got %q, want %q", fromFile, want)
	}
	if logs.Len() != 0 {
		t.Fatalf("a configuration-only start logged %q", logs.String())
	}

	override := filepath.Join(t.TempDir(), "flag-state")
	fromFlag, err := resolveDataDir(cfg, override, logger)
	if err != nil {
		t.Fatalf("resolveDataDir with a flag: %v", err)
	}
	if fromFlag != override {
		t.Fatalf("data directory with a flag: got %q, want %q", fromFlag, override)
	}
	// The disagreement is reported once, and the message names both directories
	// so a reader can see which one the token and the history will follow.
	logged := logs.String()
	if !strings.Contains(logged, "-data-dir") || !strings.Contains(logged, fromFile) {
		t.Fatalf("the override was not reported with both paths: %q", logged)
	}
}

// A flag that names the directory the file already names is not a disagreement,
// and saying so once per start would turn a correct setup into a warning.
func TestResolveDataDirStaysQuietWhenBothAgree(t *testing.T) {
	dir := t.TempDir()
	cfg := loadSupervisedConfig(t, dir, "data-dir = ./melonarc-data")

	logger, logs := bufferLogger()
	got, err := resolveDataDir(cfg, filepath.Join(dir, "melonarc-data"), logger)
	if err != nil {
		t.Fatalf("resolveDataDir: %v", err)
	}
	if want := filepath.Join(dir, "melonarc-data"); got != want {
		t.Fatalf("data directory: got %q, want %q", got, want)
	}
	if logs.Len() != 0 {
		t.Fatalf("two equal paths logged %q", logs.String())
	}
}

// An empty flag keeps the configuration in charge; the default case must not
// become a warning either.
func TestResolveDataDirFallsBackToThePlatformDefault(t *testing.T) {
	dir := t.TempDir()
	cfg := loadSupervisedConfig(t, dir, "log-level = error")

	logger, _ := bufferLogger()
	got, err := resolveDataDir(cfg, "   ", logger)
	if err != nil {
		t.Fatalf("resolveDataDir: %v", err)
	}
	want, err := os.UserConfigDir()
	if err != nil {
		t.Fatalf("UserConfigDir: %v", err)
	}
	if got != filepath.Join(want, "melonarc") {
		t.Fatalf("default data directory: got %q", got)
	}
}

// The liveness pipe has to be a pipe. A terminal, a regular file or the null
// device report end of file immediately, and accepting them would make the
// daemon exit the moment it started.
func TestCheckLivenessPipeAcceptsOnlyAPipe(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer read.Close()
	defer write.Close()
	if err := checkLivenessPipe(read); err != nil {
		t.Fatalf("a pipe was refused: %v", err)
	}

	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}
	defer null.Close()
	if err := checkLivenessPipe(null); err == nil {
		t.Fatal("the null device was accepted as a liveness pipe")
	}

	file, err := os.CreateTemp(t.TempDir(), "not-a-pipe-*")
	if err != nil {
		t.Fatalf("create a temporary file: %v", err)
	}
	defer file.Close()
	if err := checkLivenessPipe(file); err == nil {
		t.Fatal("a regular file was accepted as a liveness pipe")
	}
}

// End of file is the shutdown request, and it must arrive exactly once: the
// cancel function is what releases the whole shutdown order.
func TestWatchLivenessStopsOnEndOfFile(t *testing.T) {
	var calls int32
	done := make(chan struct{})
	logger, _ := bufferLogger()
	watchLiveness(strings.NewReader(""), logger, func() {
		atomic.AddInt32(&calls, 1)
		close(done)
	})
	<-done
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("stop calls after end of file: got %d, want 1", got)
	}
}

// A pipe that is still open must not be read as a shutdown: that is the whole
// point of the mechanism.
func TestWatchLivenessWaitsForTheWriterToClose(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer read.Close()

	var started sync.WaitGroup
	started.Add(1)
	var calls int32
	stopped := make(chan struct{})
	logger, _ := bufferLogger()
	go func() {
		started.Done()
		watchLiveness(read, logger, func() {
			atomic.AddInt32(&calls, 1)
			close(stopped)
		})
	}()
	started.Wait()

	select {
	case <-stopped:
		t.Fatal("an open pipe was read as a shutdown")
	case <-time.After(50 * time.Millisecond):
	}
	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Fatalf("stop calls while the pipe was open: got %d, want 0", got)
	}

	write.Close()
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("closing the writing end did not stop the watcher")
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("stop calls after the writer closed: got %d, want 1", got)
	}
}

// -check reports the data directory the flag names, and names it without
// creating anything: the shell asks before it writes.
func TestCheckReportsTheDataDirectoryFromTheFlag(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "melonarc.conf")
	raw := "[General]\nlog-level = error\ndata-dir = ./melonarc-data\n[Rule]\nFINAL,DIRECT\n"
	if err := os.WriteFile(cfgPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write configuration: %v", err)
	}
	override := filepath.Join(t.TempDir(), "from-the-shell")

	var runErr error
	out := captureStdout(t, func() {
		runErr = run([]string{"-config", cfgPath, "-check", "-data-dir", override})
	})
	if runErr != nil {
		t.Fatalf("-check: %v", runErr)
	}
	if !strings.Contains(out, "data: "+override+"\n") {
		t.Fatalf("-check did not report the flag's data directory:\n%s", out)
	}
	if _, err := os.Stat(override); !os.IsNotExist(err) {
		t.Fatalf("-check created %s (stat error: %v)", override, err)
	}
}
