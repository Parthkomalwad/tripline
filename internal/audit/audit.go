// Package audit writes a tamper-evident, append-only log. Each entry holds
// the hash of the entry before it, so any edit, insert or reorder breaks
// the chain at a known seq. Deleting the final entries cannot be detected
// from the file alone.
package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Zero is the prev value of the first entry.
const Zero = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

// maxLine bounds one entry, so a corrupt file cannot exhaust memory.
const maxLine = 4 << 20

// Entry is one line of the log.
type Entry struct {
	Seq  uint64          `json:"seq"`
	TS   string          `json:"ts"`
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
	Prev string          `json:"prev"`
	Hash string          `json:"hash"`
}

// hashBody is the canonical form that hash covers: the entry without the
// hash field, marshaled by encoding/json with this fixed field order
// (seq, ts, type, data, prev) and no whitespace. data is the compact JSON
// of the payload. ts is the exact string stored in the entry.
type hashBody struct {
	Seq  uint64          `json:"seq"`
	TS   string          `json:"ts"`
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
	Prev string          `json:"prev"`
}

func (e *Entry) sum() (string, error) {
	b, err := json.Marshal(hashBody{e.Seq, e.TS, e.Type, e.Data, e.Prev})
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:]), nil
}

// parse decodes one line strictly and checks its own hash.
func parse(line []byte) (*Entry, error) {
	var e Entry
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		return nil, fmt.Errorf("bad JSON: %w", err)
	}
	if dec.More() {
		return nil, errors.New("bad JSON: trailing data")
	}
	want, err := e.sum()
	if err != nil {
		return nil, fmt.Errorf("bad JSON: %w", err)
	}
	if e.Hash != want {
		return nil, errors.New("hash mismatch")
	}
	return &e, nil
}

// Log is an open audit file. It is safe for concurrent use.
type Log struct {
	mu     sync.Mutex
	f      *os.File
	seq    uint64
	prev   string
	broken error
}

// Open opens or creates the log and resumes the chain from the last line.
// It refuses to open a log whose last line is damaged.
func Open(path string) (*Log, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	l := &Log{f: f, prev: Zero}
	if err := l.resume(); err != nil {
		f.Close()
		return nil, err
	}
	return l, nil
}

func (l *Log) resume() error {
	r := bufio.NewReaderSize(l.f, 64<<10)
	var last []byte
	for {
		line, err := r.ReadBytes('\n')
		if err == io.EOF {
			if len(line) > 0 {
				return errors.New("audit: last line has no newline")
			}
			break
		}
		if err != nil {
			return err
		}
		if len(line) > maxLine {
			return errors.New("audit: line too long")
		}
		last = line
	}
	if last != nil {
		e, err := parse(last)
		if err != nil {
			return fmt.Errorf("audit: last line: %w", err)
		}
		l.seq, l.prev = e.Seq, e.Hash
	}
	_, err := l.f.Seek(0, io.SeekEnd)
	return err
}

// Append adds one entry and fsyncs it. data must marshal to a JSON value.
func (l *Log) Append(typ string, data any) error {
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.broken != nil {
		return fmt.Errorf("audit: log is broken: %w", l.broken)
	}
	e := Entry{
		Seq:  l.seq + 1,
		TS:   time.Now().UTC().Format(time.RFC3339Nano),
		Type: typ,
		Data: raw,
		Prev: l.prev,
	}
	if e.Hash, err = e.sum(); err != nil {
		return err
	}
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if _, err := l.f.Write(append(line, '\n')); err != nil {
		l.broken = err // a partial line may be on disk: stop appending
		return err
	}
	if err := l.f.Sync(); err != nil {
		l.broken = err
		return err
	}
	l.seq, l.prev = e.Seq, e.Hash
	return nil
}

// Close closes the file.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Close()
}

// Verify reads a whole log and returns an error that names the first bad seq.
func Verify(r io.Reader) error {
	_, err := VerifyCount(r)
	return err
}

// VerifyCount is Verify plus the number of valid entries.
func VerifyCount(r io.Reader) (uint64, error) {
	br := bufio.NewReaderSize(r, 64<<10)
	var n uint64
	prev := Zero
	for {
		line, err := br.ReadBytes('\n')
		if err != nil && err != io.EOF {
			return n, err
		}
		if len(line) == 0 {
			return n, nil
		}
		want := n + 1
		if len(line) > maxLine {
			return n, fmt.Errorf("seq %d: line too long", want)
		}
		if line[len(line)-1] != '\n' {
			return n, fmt.Errorf("seq %d: last line has no newline", want)
		}
		e, perr := parse(line)
		switch {
		case perr != nil:
			return n, fmt.Errorf("seq %d: %w", want, perr)
		case e.Seq != want:
			return n, fmt.Errorf("seq %d: found seq %d (line deleted, inserted or reordered)", want, e.Seq)
		case e.Prev != prev:
			return n, fmt.Errorf("seq %d: prev link broken", want)
		}
		n, prev = want, e.Hash
	}
}
