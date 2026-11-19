// Supervising the daemon from a desktop shell.
//
// Two things a shell needs are not expressible in the configuration file: which
// data directory is in force, and whether the shell that started the process is
// still there. Both are command line flags for the same reason -api-listen is
// one: they describe the process the shell spawned, not the file it shares with
// the CLI.
//
// The data directory is a flag because the shell owns it. A configuration can
// carry a data-dir of its own — the example file does, relative to itself — and
// when the two disagree the token, the observation history and the system proxy
// record end up in a directory the shell does not read. Handing the path to the
// child removes the possibility instead of documenting it.
//
// The liveness pipe is the second half of the same idea. A shell that is force
// quit never gets to send SIGTERM, so the daemon would keep running with the
// machine still pointed at its listeners. The kernel closes the shell's writing
// end of the pipe whatever happens to it, and end of file is then the one signal
// that survives a crash.
package main

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/melon-tgj/melonarc/internal/config"
	"github.com/melon-tgj/melonarc/internal/datadir"
)

// resolveDataDir returns the data directory in force: the -data-dir flag when it
// is given, the configuration otherwise.
//
// Both values are resolved exactly the same way, so an absolute path from the
// shell and an absolute path in the file name the same directory. The flag wins
// because the shell is the one that reads the token back; a file that names a
// different directory is not an error (it is a file written for the CLI), but it
// is worth one line, because everything the daemon records follows the flag from
// then on.
func resolveDataDir(cfg *config.Config, override string, logger *slog.Logger) (string, error) {
	fromConfig, err := datadir.Resolve(cfg.BaseDir, cfg.General.DataDir)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(override) == "" {
		return fromConfig, nil
	}
	fromFlag, err := datadir.Resolve(cfg.BaseDir, override)
	if err != nil {
		return "", err
	}
	if fromFlag != fromConfig {
		logger.Warn("the data directory comes from -data-dir, not from the configuration",
			"data_dir", fromFlag, "configured", fromConfig)
	}
	return fromFlag, nil
}

// checkLivenessPipe rejects a supervised start whose standard input cannot
// report the parent's death.
//
// A terminal, a regular file and the null device all report end of file at once,
// which the watcher reads as "the shell is gone". Refusing to start is the
// honest answer to a flag that cannot work.
func checkLivenessPipe(f *os.File) error {
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("-supervise-stdin: cannot inspect standard input: %w", err)
	}
	if info.Mode()&os.ModeNamedPipe == 0 {
		return errors.New("-supervise-stdin: standard input is not a pipe; the shell that starts the daemon must pass one")
	}
	return nil
}

// watchLiveness turns the closing of the pipe into a shutdown request, through
// the same cancel function SIGTERM uses, so the shutdown order is unchanged.
//
// The shell never writes to the pipe. Anything that arrives anyway is discarded
// and counted: interpreting it would give a file descriptor the power to change
// what the daemon does.
func watchLiveness(r io.Reader, logger *slog.Logger, stop func()) {
	buf := make([]byte, 256)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			logger.Warn("unexpected input on the liveness pipe", "bytes", n)
		}
		if err != nil {
			logger.Info("the supervising process closed the liveness pipe", "shutting_down", true)
			stop()
			return
		}
	}
}
