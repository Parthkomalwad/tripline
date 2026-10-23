package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Parthkomalwad/tripline/internal/watcher"
)

// cmdSensor handles "tripline sensor add -config c.yaml <sensor-id>".
func cmdSensor(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "add" {
		fmt.Fprintln(stderr, "usage: tripline sensor add -config c.yaml <sensor-id>")
		return 2
	}
	fs := flag.NewFlagSet("sensor add", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "tripline.yaml", "config file")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: tripline sensor add -config c.yaml <sensor-id>")
		return 2
	}
	cfg, err := watcher.LoadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "tripline:", err)
		return 1
	}
	if err := os.MkdirAll(cfg.Watcher.StateDir, 0o700); err != nil {
		fmt.Fprintln(stderr, "tripline:", err)
		return 1
	}
	tokens, err := watcher.LoadTokens(cfg.Watcher.StateDir)
	if err != nil {
		fmt.Fprintln(stderr, "tripline:", err)
		return 1
	}
	token, err := tokens.Add(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(stderr, "tripline:", err)
		return 1
	}
	fmt.Fprintln(stderr, "Store this token securely. It is shown once and cannot be read back.")
	fmt.Fprintln(stdout, token)
	return 0
}
