package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Parthkomalwad/tripline/internal/audit"
	"github.com/Parthkomalwad/tripline/internal/watcher"
)

// runAudit handles "tripline audit verify".
func runAudit(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "verify" {
		fmt.Fprintln(stderr, "usage: tripline audit verify [-config path] [-file path]")
		return 2
	}
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "tripline.yaml", "config file")
	file := fs.String("file", "", "audit file (default <state_dir>/audit.jsonl)")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if *file == "" {
		cfg, err := watcher.LoadConfig(*cfgPath)
		if err != nil {
			fmt.Fprintln(stderr, "load config:", err)
			return 1
		}
		*file = filepath.Join(cfg.Watcher.StateDir, "audit.jsonl")
	}
	f, err := os.Open(*file)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer f.Close()
	n, err := audit.VerifyCount(f)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stdout, "ok: %d entries\n", n)
	return 0
}
