package main

import (
	"context"
	"flag"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/Parthkomalwad/tripline/internal/sensor/egress"
)

// runEgress handles "tripline sensor egress -config c.yaml".
func runEgress(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("sensor egress", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "tripline.yaml", "config file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	log := slog.New(slog.NewJSONHandler(stderr, nil))
	cfg, err := egress.LoadConfig(*cfgPath)
	if err != nil {
		log.Error("load config", "err", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := egress.Run(ctx, cfg, log); err != nil {
		log.Error("egress sensor", "err", err)
		return 1
	}
	return 0
}
