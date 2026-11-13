// Command melonarc-cli is the command line client for MelonARC.
//
// It talks to a running core daemon over the local API and never performs
// privileged work itself. The token is read from the data directory of the core
// unless it is given explicitly, so no argument is needed in the common case.
package main

import (
	"os"

	"github.com/melon-tgj/melonarc/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
