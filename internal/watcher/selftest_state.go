package watcher

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/Parthkomalwad/tripline/internal/event"
)

const (
	selftestFile   = "selftest.json"
	selftestWindow = 7 * 24 * time.Hour
)

// selftestRun is one probe result in the 7-day history.
type selftestRun struct {
	TS     time.Time `json:"ts"`
	Probe  string    `json:"probe"`
	Result string    `json:"result"`
}

type runKey struct{ probe, result string }

// recordSelftest counts a selftest.result event and keeps it in the history.
// The caller holds s.mu.
func (s *State) recordSelftest(e *event.Event, now time.Time) {
	probe, _ := e.Attrs["probe"].(string)
	result, _ := e.Attrs["result"].(string)
	if s.selftestRuns == nil {
		s.selftestRuns = map[runKey]int64{}
	}
	s.selftestRuns[runKey{probe, result}]++
	s.history = append(s.pruneLocked(now), selftestRun{now, probe, result})
	s.historyDirty = true
}

func (s *State) pruneLocked(now time.Time) []selftestRun {
	cut := now.Add(-selftestWindow)
	i := 0
	for i < len(s.history) && !s.history[i].TS.After(cut) {
		i++
	}
	return s.history[i:]
}

// passRateLocked is pass/(pass+fail) over the last 7 days. Skips do not count.
// It is nil when there are no runs.
func (s *State) passRateLocked(now time.Time) *float64 {
	var pass, fail int
	for _, r := range s.pruneLocked(now) {
		switch r.Result {
		case "pass":
			pass++
		case "fail":
			fail++
		}
	}
	if pass+fail == 0 {
		return nil
	}
	v := float64(pass) / float64(pass+fail)
	return &v
}

func (s *State) writeSelftestMetrics(w io.Writer) {
	keys := sortedKeys(s.selftestRuns, func(k runKey) string { return k.probe + "\x00" + k.result })
	for _, k := range keys {
		fmt.Fprintf(w, "tripline_selftest_runs_total{probe=\"%s\",result=\"%s\"} %d\n",
			escLabel.Replace(k.probe), escLabel.Replace(k.result), s.selftestRuns[k])
	}
}

func (s *State) loadSelftest(dir string) error {
	data, err := os.ReadFile(filepath.Join(dir, selftestFile))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var h []selftestRun
	if err := json.Unmarshal(data, &h); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	h = append(h, s.history...)
	sort.Slice(h, func(i, j int) bool { return h[i].TS.Before(h[j].TS) })
	s.history = h
	return nil
}

func (s *State) saveSelftest(dir string) error {
	s.mu.Lock()
	if !s.historyDirty {
		s.mu.Unlock()
		return nil
	}
	data, err := json.Marshal(s.pruneLocked(s.Now()))
	s.historyDirty = false
	s.mu.Unlock()
	if err == nil {
		tmp := filepath.Join(dir, selftestFile+".tmp")
		if err = os.WriteFile(tmp, data, 0o600); err == nil {
			err = os.Rename(tmp, filepath.Join(dir, selftestFile))
		}
	}
	if err != nil {
		s.mu.Lock()
		s.historyDirty = true
		s.mu.Unlock()
	}
	return err
}
