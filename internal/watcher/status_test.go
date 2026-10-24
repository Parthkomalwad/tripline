package watcher

import (
	"encoding/json"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Parthkomalwad/tripline/internal/event"
	"github.com/Parthkomalwad/tripline/internal/rules"
)

var t0 = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

func testState() (*State, *time.Time) {
	now := t0
	s := NewState()
	s.Now = func() time.Time { return now }
	return s, &now
}

func ev(kind event.Kind, id, source, subject string) *event.Event {
	return &event.Event{ID: "e1", TS: t0, Source: source, SourceID: id, Subject: subject, Kind: kind, Decision: event.DecisionAllow}
}

func TestHeartbeatAndSilent(t *testing.T) {
	s, now := testState()
	var fired []string
	s.OnSilent = func(id string) { fired = append(fired, id) }
	s.observe(ev(event.KindHeartbeat, "egress-1", "sensor.egress", "host"), nil)

	*now = t0.Add(4*time.Minute + 59*time.Second)
	if got := s.Silent(*now); len(got) != 0 {
		t.Fatalf("silent too early: %v", got)
	}
	*now = t0.Add(5 * time.Minute)
	if got := s.Silent(*now); len(got) != 1 || got[0] != "egress-1" {
		t.Fatalf("want egress-1 silent, got %v", got)
	}
	s.CheckSilent()
	s.CheckSilent()
	if len(fired) != 1 {
		t.Fatalf("OnSilent fired %d times, want 1", len(fired))
	}
	// A new heartbeat clears silence and re-arms the callback.
	s.observe(ev(event.KindHeartbeat, "egress-1", "sensor.egress", "host"), nil)
	if len(s.Silent(*now)) != 0 {
		t.Fatal("still silent after heartbeat")
	}
	*now = now.Add(6 * time.Minute)
	s.CheckSilent()
	if len(fired) != 2 {
		t.Fatalf("OnSilent fired %d times, want 2", len(fired))
	}
}

func TestPersistHeartbeats(t *testing.T) {
	dir := t.TempDir()
	s, _ := testState()
	s.observe(ev(event.KindHeartbeat, "egress-1", "sensor.egress", "host"), nil)
	if err := s.Save(dir); err != nil {
		t.Fatal(err)
	}
	s2, _ := testState()
	if err := s2.Load(dir); err != nil {
		t.Fatal(err)
	}
	if st := s2.Status(); len(st.Sources) != 1 || !st.Sources[0].LastHeartbeat.Equal(t0) {
		t.Fatalf("not restored: %+v", st.Sources)
	}
}

func alertRule() []*rules.Rule {
	return []*rules.Rule{{ID: "r1", Severity: "high", Mode: rules.ModeMonitor, OnMatch: []string{"alert"}}}
}

func TestStatusJSONShape(t *testing.T) {
	s, _ := testState()
	s.observe(ev(event.KindHeartbeat, "egress-1", "sensor.egress", "host"), nil)
	s.observe(ev(event.KindTripwireHit, "trap-1", "watcher.trap", "decoy"), alertRule())
	rec := httptest.NewRecorder()
	s.StatusHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/status.json", nil))
	var m map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"bundle_version", "sources", "coverage", "selftest_pass_rate_7d", "recent_alerts", "events_rejected"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing key %s", k)
		}
	}
	if string(m["selftest_pass_rate_7d"]) != "null" {
		t.Errorf("pass rate = %s, want null", m["selftest_pass_rate_7d"])
	}
	var doc StatusDoc
	_ = json.Unmarshal(rec.Body.Bytes(), &doc)
	if len(doc.Coverage) != len(SensorTypes) || len(doc.RecentAlerts) != 1 || doc.RecentAlerts[0].TraceID != "e1" {
		t.Fatalf("unexpected doc: %+v", doc)
	}
	for _, c := range doc.Coverage {
		wantGap := c.SensorType != "sensor.egress" // trap-1 never sent a heartbeat but is live by event
		if c.SensorType == "watcher.trap" {
			wantGap = false
		}
		if c.Gap != wantGap {
			t.Errorf("%s gap=%v want %v", c.SensorType, c.Gap, wantGap)
		}
	}
}

// Lines of the text format: comment, or name{labels} value.
var sample = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*(\{([a-zA-Z_][a-zA-Z0-9_]*="([^"\\\n]|\\[\\"n])*",?)+\})? [-+0-9.eE]+$`)

func TestMetricsFormat(t *testing.T) {
	s, _ := testState()
	s.observe(ev(event.KindHeartbeat, "a\"b\\c\nd", "sensor.egress", "host"), alertRule())
	rec := httptest.NewRecorder()
	s.StatusHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body := rec.Body.String()
	if !strings.HasSuffix(body, "\n") || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain; version=0.0.4") {
		t.Fatal("bad terminator or content type")
	}
	typed := map[string]bool{}
	for _, l := range strings.Split(strings.TrimSuffix(body, "\n"), "\n") {
		switch {
		case strings.HasPrefix(l, "# HELP "):
		case strings.HasPrefix(l, "# TYPE "):
			name := strings.Fields(l)[2]
			if typed[name] {
				t.Errorf("duplicate TYPE %s", name)
			}
			typed[name] = true
		case !sample.MatchString(l):
			t.Errorf("bad sample line %q", l)
		}
	}
	for _, want := range []string{
		`tripline_source_last_heartbeat_seconds{source_id="a\"b\\c\nd"} ` + "1767268800",
		`tripline_events_total{kind="heartbeat",decision="allow",source="sensor.egress"} 1`,
		`tripline_alerts_total{severity="high",rule_id="r1"} 1`,
		`tripline_rule_matches_total{rule_id="r1",mode="monitor"} 1`,
		`tripline_sensor_decision_latency_seconds_bucket{le="+Inf"} 0`,
		`# TYPE tripline_selftest_runs_total counter`,
		`tripline_bundle_version 0`,
	} {
		if !strings.Contains(body, want+"\n") && !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestHTMLEscapesSubject(t *testing.T) {
	s, _ := testState()
	s.observe(ev(event.KindTripwireHit, "trap-1", "watcher.trap", "<script>alert(1)</script>"), alertRule())
	rec := httptest.NewRecorder()
	s.StatusHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	body := rec.Body.String()
	if strings.Contains(body, "<script>") || !strings.Contains(body, "&lt;script&gt;") {
		t.Fatal("subject not escaped")
	}
	if !strings.Contains(body, "Not watched") || !strings.Contains(body, "No self-test has run yet") {
		t.Fatal("missing gap or no-data text")
	}
}

func TestWatcherSourcesNeverSilent(t *testing.T) {
	s := NewState()
	start := time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)
	s.Now = func() time.Time { return start }
	s.observe(&event.Event{ID: "e", TS: start, Source: "watcher.trap", SourceID: "watcher-trap", Subject: "x", Kind: event.KindTripwireHit, Decision: event.DecisionNone}, nil)
	if got := s.Silent(start.Add(time.Hour)); len(got) != 0 {
		t.Errorf("silent = %v, want none", got)
	}
}

func TestStatusPageShowsPassRateAndFinding(t *testing.T) {
	s := NewState()
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	s.Now = func() time.Time { return now }
	for i, r := range []string{"pass", "pass", "pass", "fail"} {
		s.history = append(s.history, selftestRun{now.Add(time.Duration(i-4) * time.Hour), "egress-deny", r})
	}
	var buf strings.Builder
	if err := page.Execute(&buf, s.view()); err != nil {
		t.Fatal(err)
	}
	body := buf.String()
	for _, want := range []string{"75%", "The egress-deny self-test failed", "Attack path", "Not watched"} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q", want)
		}
	}
}
