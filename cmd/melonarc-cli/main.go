// Command melonarc-cli is the command line client for MelonARC.
//
// It talks to a running core daemon over the local API and never performs
// privileged work itself.
package main

import "fmt"

// version is the build version placeholder, overridden at link time later on.
const version = "0.1.0-dev"

func main() {
	fmt.Printf("melonarc-cli %s\n", version)
}
