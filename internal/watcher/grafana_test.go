package watcher

import (
	"bytes"
	"encoding/json"
	"os"
	"regexp"
	"testing"
)

var (
	metricRe  = regexp.MustCompile(`tripline_[a-z0-9_]+`)
	emittedRe = regexp.MustCompile(`(?m)^(?:# TYPE )?(tripline_[a-z0-9_]+)`)
)

// emittedMetrics returns every metric name that /metrics writes, including
// histogram series suffixes.
func emittedMetrics() map[string]bool {
	var buf bytes.Buffer
	NewState().WriteMetrics(&buf)
	out := map[string]bool{}
	for _, m := range emittedRe.FindAllStringSubmatch(buf.String(), -1) {
		out[m[1]] = true
	}
	return out
}

// unknownMetrics lists tripline_ names in exprs that /metrics does not emit.
func unknownMetrics(exprs []string, known map[string]bool) []string {
	var bad []string
	for _, e := range exprs {
		for _, name := range metricRe.FindAllString(e, -1) {
			if !known[name] {
				bad = append(bad, name)
			}
		}
	}
	return bad
}

func TestGrafanaDashboardMetrics(t *testing.T) {
	data, err := os.ReadFile("../../deploy/grafana/tripline.json")
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		Panels []struct {
			Targets []struct {
				Expr string `json:"expr"`
			} `json:"targets"`
		} `json:"panels"`
	}
	if err := json.Unmarshal(data, &d); err != nil {
		t.Fatal(err)
	}
	var exprs []string
	for _, p := range d.Panels {
		for _, tg := range p.Targets {
			exprs = append(exprs, tg.Expr)
		}
	}
	if len(exprs) == 0 {
		t.Fatal("dashboard has no panel expressions")
	}
	known := emittedMetrics()
	if bad := unknownMetrics(exprs, known); len(bad) > 0 {
		t.Fatalf("dashboard uses metrics /metrics does not emit: %v", bad)
	}
}

func TestUnknownMetricDetected(t *testing.T) {
	bad := unknownMetrics([]string{"rate(tripline_no_such_total[5m]) + tripline_bundle_version"}, emittedMetrics())
	if len(bad) != 1 || bad[0] != "tripline_no_such_total" {
		t.Fatalf("got %v", bad)
	}
}
