// Command tripline dispatches subcommands.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/Parthkomalwad/tripline/internal/version"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintf(stderr, "usage: %s <command>\ncommands: version\n", version.Name)
		return 2
	}
	switch args[0] {
	case "version":
		fmt.Fprintf(stdout, "%s %s\n", version.Name, version.Version)
		return 0
	default:
		fmt.Fprintf(stderr, "%s: unknown command %q\n", version.Name, args[0])
		return 2
	}
}
