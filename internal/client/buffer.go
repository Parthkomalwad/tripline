package client

import (
	"bufio"
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"sync/atomic"

	"github.com/Parthkomalwad/tripline/internal/event"
)

// buffer is a JSONL file of events the watcher has not received. When it
// grows past max bytes, the oldest events are dropped and counted. Only the
// client loop uses it.
// ponytail: whole-file read and rewrite, fine for tens of MiB; use segments if the cap grows.
type buffer struct {
	path    string
	max     int64
	dropped atomic.Int64
}

func (b *buffer) nonEmpty() bool {
	fi, err := os.Stat(b.path)
	return err == nil && fi.Size() > 0
}

func (b *buffer) load() ([]event.Event, error) {
	data, err := os.ReadFile(b.path)
	if err != nil {
		return nil, err
	}
	var out []event.Event
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		var e event.Event
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			b.dropped.Add(1) // torn or corrupt line
			continue
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

// append adds events, then trims the oldest lines to fit the cap.
func (b *buffer) append(evs []event.Event, log *slog.Logger) {
	old, _ := b.load()
	if err := b.replace(append(old, evs...)); err != nil {
		log.Error("write event buffer", "err", err)
		b.dropped.Add(int64(len(evs)))
	}
}

// replace rewrites the file with evs, dropping the oldest to fit the cap.
func (b *buffer) replace(evs []event.Event) error {
	lines := make([][]byte, len(evs))
	var size int64
	for i, e := range evs {
		l, _ := json.Marshal(e)
		lines[i] = append(l, '\n')
		size += int64(len(lines[i]))
	}
	for b.max > 0 && size > b.max && len(lines) > 0 {
		size -= int64(len(lines[0]))
		lines = lines[1:]
		b.dropped.Add(1)
	}
	if len(lines) == 0 {
		err := os.Remove(b.path)
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	tmp := b.path + ".tmp"
	if err := os.WriteFile(tmp, bytes.Join(lines, nil), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, b.path)
}
