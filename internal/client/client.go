// Package client sends sensor events to the watcher. It batches events,
// buffers them on disk when the watcher is down, and never blocks callers.
package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Parthkomalwad/tripline/internal/event"
)

const (
	queueSize = 1024
	maxChunk  = 500 // events per POST, well under the watcher batch limit
)

// Config configures a Client. Token is never logged.
type Config struct {
	URL            string // watcher base URL
	Token          string
	Source         string // event source, for heartbeats
	SourceID       string
	Subject        string // heartbeat subject
	BufferPath     string // JSONL file; empty disables disk buffering
	BufferMax      int64  // byte cap of the buffer file
	FlushEvery     time.Duration
	HeartbeatEvery time.Duration
	HTTP           *http.Client
	Log            *slog.Logger
}

// Client is safe for concurrent use.
type Client struct {
	cfg     Config
	queue   chan event.Event
	buf     *buffer
	dropped atomic.Int64 // events lost because the queue was full
	stop    chan struct{}
	wg      sync.WaitGroup
}

// TokenFromEnv reads a token from the named environment variable.
func TokenFromEnv(name string) (string, error) {
	t := strings.TrimSpace(os.Getenv(name))
	if t == "" {
		return "", fmt.Errorf("environment variable %s is empty", name)
	}
	return t, nil
}

// TokenFromFile reads a token from a file.
func TokenFromFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	t := strings.TrimSpace(string(b))
	if t == "" {
		return "", fmt.Errorf("token file %s is empty", path)
	}
	return t, nil
}

// NewID returns a random event id.
func NewID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return "evt_" + hex.EncodeToString(b[:])
}

// New starts the sending loop. Call Close to stop it.
func New(cfg Config) *Client {
	if cfg.FlushEvery == 0 {
		cfg.FlushEvery = 2 * time.Second
	}
	if cfg.HeartbeatEvery == 0 {
		cfg.HeartbeatEvery = 30 * time.Second
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 5 * time.Second}
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	c := &Client{cfg: cfg, queue: make(chan event.Event, queueSize), stop: make(chan struct{})}
	if cfg.BufferPath != "" {
		c.buf = &buffer{path: cfg.BufferPath, max: cfg.BufferMax}
	}
	c.wg.Add(1)
	go c.loop()
	return c
}

// Send queues an event and returns at once. If the queue is full the event
// is dropped and counted.
func (c *Client) Send(e event.Event) {
	select {
	case c.queue <- e:
	default:
		c.dropped.Add(1)
	}
}

// Dropped returns the number of events lost so far.
func (c *Client) Dropped() int64 {
	n := c.dropped.Load()
	if c.buf != nil {
		n += c.buf.dropped.Load()
	}
	return n
}

// Close stops the loop after one last send attempt.
func (c *Client) Close() {
	close(c.stop)
	c.wg.Wait()
}

func (c *Client) heartbeat() event.Event {
	return event.Event{ID: NewID(), TS: time.Now().UTC(), Source: c.cfg.Source,
		SourceID: c.cfg.SourceID, Subject: c.cfg.Subject,
		Kind: event.KindHeartbeat, Decision: event.DecisionNone}
}

func (c *Client) loop() {
	defer c.wg.Done()
	flush := time.NewTicker(c.cfg.FlushEvery)
	hb := time.NewTicker(c.cfg.HeartbeatEvery)
	defer flush.Stop()
	defer hb.Stop()
	var batch []event.Event
	send := func() { c.deliver(batch); batch = batch[:0] }
	for {
		select {
		case e := <-c.queue:
			batch = append(batch, e)
			if len(batch) >= maxChunk {
				send()
			}
		case <-hb.C:
			batch = append(batch, c.heartbeat())
		case <-flush.C:
			send()
		case <-c.stop:
			for len(c.queue) > 0 {
				batch = append(batch, <-c.queue)
			}
			send()
			return
		}
	}
}

// deliver sends new events, after any buffered ones to keep order. Events
// that cannot be sent go to the disk buffer.
func (c *Client) deliver(batch []event.Event) {
	if c.buf != nil && c.buf.nonEmpty() {
		if len(batch) > 0 {
			c.buf.append(batch, c.cfg.Log)
		}
		c.drain()
		return
	}
	for len(batch) > 0 {
		n := min(len(batch), maxChunk)
		if err := c.post(batch[:n]); err != nil {
			c.cfg.Log.Warn("watcher unreachable, buffering events", "err", err, "events", len(batch))
			if c.buf != nil {
				c.buf.append(batch, c.cfg.Log)
			} else {
				c.dropped.Add(int64(len(batch)))
			}
			return
		}
		batch = batch[n:]
	}
}

// drain resends the disk buffer and keeps what still fails.
func (c *Client) drain() {
	evs, err := c.buf.load()
	if err != nil {
		c.cfg.Log.Error("read event buffer", "err", err)
		return
	}
	for len(evs) > 0 {
		n := min(len(evs), maxChunk)
		if err := c.post(evs[:n]); err != nil {
			break
		}
		evs = evs[n:]
	}
	if err := c.buf.replace(evs); err != nil {
		c.cfg.Log.Error("rewrite event buffer", "err", err)
	}
}

type result struct {
	Rejected []json.RawMessage `json:"rejected"`
}

// post sends one chunk. Events the watcher rejects are not retried, since
// the same event would fail again; they are logged by count.
func (c *Client) post(evs []event.Event) error {
	body, err := json.Marshal(evs)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(c.cfg.URL, "/")+"/v1/events", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.cfg.HTTP.Do(req)
	if err != nil {
		return errors.New("request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("watcher returned %d", resp.StatusCode)
	}
	var res result
	if json.NewDecoder(resp.Body).Decode(&res) == nil && len(res.Rejected) > 0 {
		c.cfg.Log.Warn("watcher rejected events", "count", len(res.Rejected))
	}
	return nil
}
