// Command melonarc-core is the entry point of the MelonARC core daemon.
//
// The daemon owns every privileged operation (TUN device, routes, system
// proxy) and exposes a local API that the CLI and the desktop UI share.
package main

import "fmt"

// version is the build version placeholder, overridden at link time later on.
const version = "0.1.0-dev"

func main() {
	fmt.Printf("melonarc-core %s\n", version)
}
