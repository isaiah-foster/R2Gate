// Command r2notary is the independent verifier for R2Notary logs.
// It shares no code with the TypeScript writer; see PLAN.md §5.7.
package main

import (
	"fmt"
	"io"
	"os"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "0.0.0-dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && args[0] == "version" {
		fmt.Fprintln(stdout, "r2notary", version)
		return 0
	}
	fmt.Fprintln(stderr, "usage: r2notary version")
	fmt.Fprintln(stderr, "(checkpoint, inclusion, consistency, monitor, findings arrive in M5/M6)")
	return 2
}
