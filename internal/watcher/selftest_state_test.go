package watcher

import (
	"strings"
	"testing"
	"time"

	"github.com/Parthkomalwad/tripline/internal/event"
)

func selftestEvent(result string) *event.Event {
	return &event.Event{Source: "watcher.selftest", SourceID: "watcher-selftest", Kind: event.KindSelftestResult,
		Attrs: map[string]any{"probe": "egress-deny", "result": result}}
}

func TestSelftestPassRate7d(t *testing.T) {
	s := NewState()
	now := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
	s.Now = func() time.Time { return now }
	if s.Status().SelftestPassRate7d != nil {
		t.Fatal("want nil with no runs")
	}
	now = now.Add(-8 * 24 * time.Hour) // old failure, falls out of the window
	s.observe(selftestEvent("fail"), nil)
	now = now.Add(8 * 24 * time.Hour)
	for _, r := range []string{"pass", "pass", "pass", "fail", "skip"} {
		s.observe(selftestEvent(r), nil)
	}
	got := s.Status().SelftestPassRate7d
	if got == nil || *got != 0.75 {
		t.Fatalf("rate %v, want 0.75", got)
	}
	now = now.Add(7*24*time.Hour + time.Minute) // everything aged out
	if s.Status().SelftestPassRate7d != nil {
		t.Fatal("want nil after window")
	}
}

func TestSelftestHistoryPersistsAndCounts(t *testing.T) {
	dir := t.TempDir()
	s := NewState()
	s.observe(selftestEvent("pass"), nil)
	if err := s.Save(dir); err != nil {
		t.Fatal(err)
	}
	s2 := NewState()
	if err := s2.Load(dir); err != nil {
		t.Fatal(err)
	}
	if r := s2.Status().SelftestPassRate7d; r == nil || *r != 1 {
		t.Fatalf("rate after reload %v", r)
	}
	var b strings.Builder
	s.WriteMetrics(&b)
	if want := `tripline_selftest_runs_total{probe="egress-deny",result="pass"} 1`; !strings.Contains(b.String(), want) {
		t.Fatalf("metrics missing %q", want)
	}
}
