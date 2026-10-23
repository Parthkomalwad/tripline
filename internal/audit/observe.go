package audit

import (
	"log/slog"
	"sync"

	"github.com/Parthkomalwad/tripline/internal/event"
	"github.com/Parthkomalwad/tripline/internal/rules"
)

type item struct {
	typ  string
	data any
}

// Async returns watcher observers that append "event" and "event.rejected"
// entries from one background goroutine, so ingest never waits on fsync.
// A write failure is logged and does not stop ingest. Call stop to drain
// the queue and close the log.
func (l *Log) Async(log *slog.Logger) (obs func(*event.Event, []*rules.Rule), rej func(string, string), stop func()) {
	q := make(chan item, 4096)
	done := make(chan struct{})
	var mu sync.RWMutex
	closed := false
	go func() {
		defer close(done)
		for it := range q {
			if err := l.Append(it.typ, it.data); err != nil {
				log.Error("audit: append failed", "type", it.typ, "err", err)
			}
		}
	}()
	send := func(it item) {
		mu.RLock()
		defer mu.RUnlock()
		if closed {
			log.Error("audit: dropped entry after stop", "type", it.typ)
			return
		}
		select {
		case q <- it:
		default:
			log.Error("audit: queue full, dropped entry", "type", it.typ)
		}
	}
	obs = func(e *event.Event, _ []*rules.Rule) {
		// Copy: the caller may reuse e after the observer returns.
		c := *e
		send(item{"event", &c})
	}
	rej = func(sensorID, reason string) {
		send(item{"event.rejected", map[string]string{"sensor_id": sensorID, "reason": reason}})
	}
	stop = func() {
		mu.Lock()
		if !closed {
			closed = true
			close(q)
		}
		mu.Unlock()
		<-done
		if err := l.Close(); err != nil {
			log.Error("audit: close failed", "err", err)
		}
	}
	return
}
