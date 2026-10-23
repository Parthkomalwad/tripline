// Command tripline dispatches subcommands.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/Parthkomalwad/tripline/internal/version"
	"github.com/Parthkomalwad/tripline/internal/watcher"
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
	case "watcher":
		return runWatcher(args[1:], stderr)
	case "audit":
		return runAudit(args[1:], stdout, stderr)
	case "sensor":
		return cmdSensor(args[1:], stdout, stderr)
	case "init":
		return cmdInit(args[1:], stdout, stderr)
	case "status":
		return cmdStatus(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "%s: unknown command %q\n", version.Name, args[0])
		return 2
	}
}

func runWatcher(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("watcher", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "tripline.yaml", "config file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	log := slog.New(slog.NewJSONHandler(stderr, nil))
	cfg, err := watcher.LoadConfig(*cfgPath)
	if err != nil {
		log.Error("load config", "err", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := watcher.Run(ctx, cfg, log); err != nil {
		log.Error("watcher stopped", "err", err)
		return 1
	}
	return 0
}
