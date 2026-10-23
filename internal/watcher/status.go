package watcher

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

type sourceView struct {
	SourceID      string    `json:"source_id"`
	Source        string    `json:"source"`
	LastHeartbeat time.Time `json:"last_heartbeat"`
	Silent        bool      `json:"silent"`
}

type coverageView struct {
	SensorType string `json:"sensor_type"`
	Active     int    `json:"active"`
	Gap        bool   `json:"gap"`
}

// StatusDoc is the schema of GET /status.json. The tripline status CLI reads it.
type StatusDoc struct {
	BundleVersion      int64          `json:"bundle_version"`
	Sources            []sourceView   `json:"sources"`
	Coverage           []coverageView `json:"coverage"`
	SelftestPassRate7d *float64       `json:"selftest_pass_rate_7d"`
	RecentAlerts       []Alert        `json:"recent_alerts"`
	EventsRejected     int64          `json:"events_rejected"`
}

// Status builds the current status document.
func (s *State) Status() StatusDoc {
	now := s.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	silent := map[string]bool{}
	for _, id := range s.silentLocked(now) {
		silent[id] = true
	}
	doc := StatusDoc{
		BundleVersion:  s.bundle,
		Sources:        []sourceView{},
		Coverage:       []coverageView{},
		RecentAlerts:   append([]Alert{}, s.recent...),
		EventsRejected: s.rejected,
	}
	active := map[string]int{}
	for id, src := range s.sources {
		doc.Sources = append(doc.Sources, sourceView{id, src.Source, src.LastHeartbeat, silent[id]})
		if !silent[id] {
			active[src.Source]++
		}
	}
	sort.Slice(doc.Sources, func(i, j int) bool { return doc.Sources[i].SourceID < doc.Sources[j].SourceID })
	for _, t := range SensorTypes {
		doc.Coverage = append(doc.Coverage, coverageView{t, active[t], active[t] == 0})
	}
	return doc
}

// StatusHandler serves /, /status.json and /metrics.
func (s *State) StatusHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = page.Execute(w, s.Status())
	})
	mux.HandleFunc("GET /status.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s.Status())
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		s.WriteMetrics(w)
	})
	return mux
}

var page = template.Must(template.New("status").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>tripline status</title>
<style>
body{font:15px/1.5 system-ui,sans-serif;max-width:60rem;margin:2rem auto;padding:0 1rem;color:#1a1a1a;background:#fff}
table{border-collapse:collapse;width:100%;margin-bottom:1.5rem}
th,td{text-align:left;padding:.3rem .6rem;border-bottom:1px solid #ccc}
.gap{color:#b00020;font-weight:700}
</style></head><body>
<h1>tripline status</h1>
<p>Bundle version: {{.BundleVersion}}. Events rejected: {{.EventsRejected}}.</p>
<h2>Coverage</h2>
<table><tr><th>Sensor type</th><th>Active sources</th><th>State</th></tr>
{{range .Coverage}}<tr><td>{{.SensorType}}</td><td>{{.Active}}</td><td>{{if .Gap}}<span class="gap">NOT WATCHED</span>{{else}}watched{{end}}</td></tr>
{{end}}</table>
<h2>Sources</h2>
<table><tr><th>Source ID</th><th>Source</th><th>Last heartbeat</th><th>State</th></tr>
{{range .Sources}}<tr><td>{{.SourceID}}</td><td>{{.Source}}</td><td>{{if .LastHeartbeat.IsZero}}never{{else}}{{.LastHeartbeat.Format "2006-01-02 15:04:05 MST"}}{{end}}</td><td>{{if .Silent}}<span class="gap">SILENT</span>{{else}}ok{{end}}</td></tr>
{{else}}<tr><td colspan="4">No sources yet.</td></tr>
{{end}}</table>
<h2>Self-test pass rate (7 days)</h2>
<p>{{if .SelftestPassRate7d}}{{.SelftestPassRate7d}}{{else}}no data{{end}}</p>
<h2>Recent alerts</h2>
<table><tr><th>Time</th><th>Rule</th><th>Severity</th><th>Trace ID</th><th>Subject</th></tr>
{{range .RecentAlerts}}<tr><td>{{.TS.Format "2006-01-02 15:04:05 MST"}}</td><td>{{.RuleID}}</td><td>{{.Severity}}</td><td>{{.TraceID}}</td><td>{{.Subject}}</td></tr>
{{else}}<tr><td colspan="5">No alerts.</td></tr>
{{end}}</table>
</body></html>
`))

// escLabel escapes a label value per the Prometheus text format.
var escLabel = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

func header(w io.Writer, name, help, typ string) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
}

func sortedKeys[K comparable](m map[K]int64, key func(K) string) []K {
	keys := make([]K, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return key(keys[i]) < key(keys[j]) })
	return keys
}

// WriteMetrics writes all metrics in the Prometheus text format (0.0.4).
func (s *State) WriteMetrics(w io.Writer) {
	s.mu.Lock()
	defer s.mu.Unlock()

	header(w, "tripline_events_total", "Accepted events by kind, decision and source.", "counter")
	for _, k := range sortedKeys(s.events, func(k eventKey) string { return k.kind + "\x00" + k.decision + "\x00" + k.source }) {
		fmt.Fprintf(w, "tripline_events_total{kind=\"%s\",decision=\"%s\",source=\"%s\"} %d\n",
			escLabel.Replace(k.kind), escLabel.Replace(k.decision), escLabel.Replace(k.source), s.events[k])
	}
	header(w, "tripline_events_rejected_total", "Events rejected at ingest.", "counter")
	fmt.Fprintf(w, "tripline_events_rejected_total %d\n", s.rejected)

	header(w, "tripline_alerts_total", "Alerts raised by severity and rule.", "counter")
	for _, k := range sortedKeys(s.alerts, func(k alertKey) string { return k.severity + "\x00" + k.rule }) {
		fmt.Fprintf(w, "tripline_alerts_total{severity=\"%s\",rule_id=\"%s\"} %d\n",
			escLabel.Replace(k.severity), escLabel.Replace(k.rule), s.alerts[k])
	}
	header(w, "tripline_rule_matches_total", "Rule matches by rule and mode.", "counter")
	for _, k := range sortedKeys(s.matches, func(k matchKey) string { return k.rule + "\x00" + k.mode }) {
		fmt.Fprintf(w, "tripline_rule_matches_total{rule_id=\"%s\",mode=\"%s\"} %d\n",
			escLabel.Replace(k.rule), escLabel.Replace(k.mode), s.matches[k])
	}
	// No samples until self-tests exist (M2).
	header(w, "tripline_selftest_runs_total", "Self-test probe runs by probe and result.", "counter")

	header(w, "tripline_source_last_heartbeat_seconds", "Unix time of the last heartbeat per source.", "gauge")
	ids := make([]string, 0, len(s.sources))
	for id, src := range s.sources {
		if !src.LastHeartbeat.IsZero() {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		fmt.Fprintf(w, "tripline_source_last_heartbeat_seconds{source_id=\"%s\"} %d\n",
			escLabel.Replace(id), s.sources[id].LastHeartbeat.Unix())
	}
	header(w, "tripline_bundle_version", "Active rule bundle version.", "gauge")
	fmt.Fprintf(w, "tripline_bundle_version %d\n", s.bundle)

	// Declared, empty until sensors report latency.
	header(w, "tripline_sensor_decision_latency_seconds", "Sensor decision latency.", "histogram")
	for _, le := range []string{"0.001", "0.01", "0.1", "1", "+Inf"} {
		fmt.Fprintf(w, "tripline_sensor_decision_latency_seconds_bucket{le=\"%s\"} 0\n", le)
	}
	fmt.Fprint(w, "tripline_sensor_decision_latency_seconds_sum 0\ntripline_sensor_decision_latency_seconds_count 0\n")
}
