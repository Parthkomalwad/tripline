package sinks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"slices"
	"sync/atomic"
	"time"

	"github.com/Parthkomalwad/tripline/internal/event"
	"github.com/Parthkomalwad/tripline/internal/rules"
)

const (
	queueSize = 1000
	tries     = 3
)

// Spec is one sink from the config: Type is "slack" or "webhook", URLEnv
// names the environment variable that holds the URL.
type Spec struct{ Type, URLEnv string }

type sink struct {
	name string
	send func(Alert) error
}

// Dispatcher queues alerts and delivers them from one worker goroutine.
// Delivery never blocks the caller.
type Dispatcher struct {
	Log     *slog.Logger
	Backoff time.Duration // base wait between tries; doubles each try
	Stdout  io.Writer

	// Counters, for metrics. Sent and Failed count per sink delivery.
	Queued, Sent, Failed, Dropped, Skipped atomic.Int64

	sinks []sink
	queue chan Alert
	done  chan struct{}
}

// New builds a dispatcher with the stdout sink plus the given sinks. A sink
// whose URL variable is empty is logged by variable name, counted and skipped.
func New(specs []Spec, log *slog.Logger, getenv func(string) string) *Dispatcher {
	d := &Dispatcher{Log: log, Backoff: time.Second, Stdout: os.Stdout,
		queue: make(chan Alert, queueSize), done: make(chan struct{})}
	d.sinks = append(d.sinks, sink{"stdout", func(a Alert) error {
		return json.NewEncoder(d.Stdout).Encode(a)
	}})
	client := &http.Client{Timeout: 10 * time.Second}
	for _, s := range specs {
		var payload func(Alert) any
		switch s.Type {
		case "webhook":
			payload = func(a Alert) any { return a }
		case "slack":
			payload = slackPayload
		default:
			log.Error("sink skipped: unknown type", "type", s.Type)
			d.Skipped.Add(1)
			continue
		}
		u := ""
		if s.URLEnv != "" {
			u = getenv(s.URLEnv)
		}
		if u == "" {
			log.Error("sink skipped: URL environment variable is empty", "type", s.Type, "env", s.URLEnv)
			d.Skipped.Add(1)
			continue
		}
		d.sinks = append(d.sinks, sink{s.Type, func(a Alert) error { return post(client, u, payload(a)) }})
	}
	return d
}

// post sends JSON. Returned errors never contain the URL.
func post(c *http.Client, u string, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	resp, err := c.Post(u, "application/json", bytes.NewReader(body))
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

// Send queues an alert. When the queue is full it logs, counts and returns.
func (d *Dispatcher) Send(a Alert) {
	select {
	case d.queue <- a:
		d.Queued.Add(1)
	default:
		d.Dropped.Add(1)
		d.Log.Error("alert dropped: queue full", "trace_id", a.TraceID, "rule_id", a.RuleID)
	}
}

// Observe is a watcher observer: it queues one alert per matched rule whose
// on_match has "alert" or "page".
func (d *Dispatcher) Observe(e *event.Event, matched []*rules.Rule) {
	for _, r := range matched {
		if slices.Contains(r.OnMatch, "alert") || slices.Contains(r.OnMatch, "page") {
			d.Send(NewAlert(e, r))
		}
	}
}

// Start runs the worker until ctx ends, then drains the queue once.
func (d *Dispatcher) Start(ctx context.Context) {
	go func() {
		defer close(d.done)
		for {
			select {
			case a := <-d.queue:
				d.deliver(a)
			case <-ctx.Done():
				for {
					select {
					case a := <-d.queue:
						d.deliver(a)
					default:
						return
					}
				}
			}
		}
	}()
}

// Add registers another sink. Call it before Start.
func (d *Dispatcher) Add(name string, send func(Alert) error) {
	d.sinks = append(d.sinks, sink{name, send})
}

// Done is closed when the worker has stopped.
func (d *Dispatcher) Done() <-chan struct{} { return d.done }

func (d *Dispatcher) deliver(a Alert) {
	for _, s := range d.sinks {
		var err error
		wait := d.Backoff
		for i := 1; i <= tries; i++ {
			if err = s.send(a); err == nil {
				break
			}
			if i < tries {
				time.Sleep(wait)
				wait *= 2
			}
		}
		if err != nil {
			d.Failed.Add(1)
			d.Log.Error("alert delivery failed", "sink", s.name, "trace_id", a.TraceID, "err", err)
			continue
		}
		d.Sent.Add(1)
	}
}
