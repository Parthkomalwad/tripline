package audit

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Parthkomalwad/tripline/internal/event"
)

func build(t *testing.T, n int) (string, []string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if err := l.Append("event", map[string]int{"i": i}); err != nil {
			t.Fatal(err)
		}
	}
	l.Close()
	b, _ := os.ReadFile(path)
	return path, strings.SplitAfter(strings.TrimSuffix(string(b), "\n"), "\n")
}

func TestVerify(t *testing.T) {
	_, lines := build(t, 5)
	for i := range lines[:4] {
		lines[i] = strings.TrimSuffix(lines[i], "\n") + "\n"
	}
	lines[4] += "\n"
	flip := strings.Replace(lines[2], `"i":2`, `"i":9`, 1)
	cases := []struct {
		name string
		in   []string
		want string // "" means valid
	}{
		{"valid", lines, ""},
		{"edited", []string{lines[0], lines[1], flip, lines[3], lines[4]}, "seq 3"},
		{"deleted", []string{lines[0], lines[1], lines[3], lines[4]}, "seq 3"},
		{"inserted", []string{lines[0], lines[1], lines[1], lines[2], lines[3]}, "seq 3"},
		{"reordered", []string{lines[0], lines[2], lines[1], lines[3]}, "seq 2"},
		{"bad json", []string{lines[0], "not json\n"}, "seq 2"},
		{"bad prev", []string{lines[1]}, "seq 1"},
	}
	for _, c := range cases {
		err := Verify(strings.NewReader(strings.Join(c.in, "")))
		if c.want == "" {
			if err != nil {
				t.Errorf("%s: %v", c.name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", c.name, err, c.want)
		}
	}
}

func TestFirstEntryChain(t *testing.T) {
	_, lines := build(t, 1)
	if !strings.Contains(lines[0], `"seq":1`) || !strings.Contains(lines[0], `"prev":"`+Zero+`"`) {
		t.Errorf("first entry: %s", lines[0])
	}
}

func TestResumeKeepsChain(t *testing.T) {
	path, _ := build(t, 3)
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Append("event.rejected", map[string]string{"sensor_id": "s", "reason": "r"}); err != nil {
		t.Fatal(err)
	}
	l.Close()
	b, _ := os.ReadFile(path)
	n, err := VerifyCount(bytes.NewReader(b))
	if err != nil || n != 4 {
		t.Fatalf("n=%d err=%v", n, err)
	}
}

func TestOpenRefusesBrokenTail(t *testing.T) {
	path, _ := build(t, 2)
	b, _ := os.ReadFile(path)
	for name, data := range map[string][]byte{
		"edited": bytes.Replace(b, []byte(`"i":1`), []byte(`"i":7`), 1),
		"cut":    b[:len(b)-5],
	} {
		os.WriteFile(path, data, 0o600)
		if l, err := Open(path); err == nil {
			l.Close()
			t.Errorf("%s: Open accepted a broken tail", name)
		}
	}
}

func TestConcurrentAppend(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, _ := Open(path)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l.Append("event", map[string]int{"x": 1})
		}()
	}
	wg.Wait()
	l.Close()
	b, _ := os.ReadFile(path)
	if n, err := VerifyCount(bytes.NewReader(b)); err != nil || n != 20 {
		t.Fatalf("n=%d err=%v", n, err)
	}
}

func TestAsyncObservers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, _ := Open(path)
	obs, rej, stop := l.Async(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	obs(&event.Event{ID: "a", TS: time.Unix(0, 0).UTC(), Kind: event.KindHeartbeat}, nil)
	rej("s1", "bad")
	stop()
	b, _ := os.ReadFile(path)
	s := string(b)
	if !strings.Contains(s, `"type":"event"`) || !strings.Contains(s, `"type":"event.rejected"`) || !strings.Contains(s, `"sensor_id":"s1"`) {
		t.Errorf("entries: %s", s)
	}
	if err := Verify(strings.NewReader(s)); err != nil {
		t.Error(err)
	}
}
