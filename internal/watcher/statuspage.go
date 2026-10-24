package watcher

import (
	"fmt"
	"html/template"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Parthkomalwad/tripline/internal/version"
)

// The status page answers one question: is anything trying to get out,
// and do the protections still work? It is server-rendered, has no script
// and refreshes itself every 30 seconds.

// step is one of the three things every attack must do after it gets in.
type step struct {
	Name    string
	Means   string
	Sensors []string // sensor types that see this step
	Kinds   []string // event kinds whose alerts belong to this step
}

var steps = []step{
	{"Touch secrets", "Credential files and decoys read on a host", []string{"node.falco", "hook.claude-code", "hook.cursor"}, []string{"secret.read", "hook.tool_call"}},
	{"Send them out", "Connections to unknown or lookalike hosts, foreign API keys", []string{"sensor.egress"}, []string{"egress.connect", "egress.provider_request"}},
	{"Use the keys", "A stolen decoy used against the trap, odd key usage", []string{"watcher.trap", "keyusage"}, []string{"tripwire.hit", "keyusage.anomaly"}},
}

var sensorLabels = map[string]string{
	"sensor.egress": "Egress sensor", "hook.claude-code": "Claude Code hook", "hook.cursor": "Cursor hook",
	"node.falco": "Falco node sensor", "keyusage": "Key-usage connector", "watcher.trap": "Decoy trap",
}

type sensorRow struct {
	Label  string
	Active int
}

type stepView struct {
	Name, Means string
	Sensors     []sensorRow
	Watched     bool // at least one sensor active
	Alerts      int  // in the last 24 h
	Last        string
}

type alertRow struct {
	Time, Ago, Rule, Severity, Trace, Subject string
	Critical                                  bool
}

type probeRow struct {
	Probe, Result, Ago string
	Fail, Skip         bool
}

type dayBar struct {
	Label           string
	Pass, Fail      int
	PassH, FailH    int // bar heights in px
	X, FailY, PassY int // positions in px
}

type sourceRow struct {
	ID, Type, Heartbeat string
	Silent, Internal    bool
}

type pageView struct {
	Host, Version, Updated string
	Finding                string
	FindingBad             bool
	Critical24, Alerts24   int
	PassRate               string // "100%" or "—"
	Runs7                  int
	Reporting, Sources     int
	Silent                 int
	Bundle                 int64
	Rejected               int64
	Steps                  []stepView
	Alerts                 []alertRow
	MoreAlerts             int
	Probes                 []probeRow
	Days                   []dayBar
	MaxRuns                int
	SourceRows             []sourceRow
}

const chartH = 72 // self-test bar plot height in px

func ago(now, t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d s ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d min ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h ago", int(d.Hours()))
	}
	return fmt.Sprintf("%d days ago", int(d.Hours()/24))
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// view builds everything the page shows from one status snapshot, so the
// strip, the attack path and the tables cannot disagree.
func (s *State) view() pageView {
	doc := s.Status()
	now := s.Now()
	s.mu.Lock()
	history := append([]selftestRun{}, s.pruneLocked(now)...)
	s.mu.Unlock()

	host, _ := os.Hostname()
	v := pageView{Host: host, Version: version.Version, Updated: now.Format("15:04:05"),
		Bundle: doc.BundleVersion, Rejected: doc.EventsRejected, PassRate: "—"}

	active := map[string]int{}
	for _, c := range doc.Coverage {
		active[c.SensorType] = c.Active
	}

	// Alerts in the last 24 h, by step.
	dayAgo := now.Add(-24 * time.Hour)
	perKind := map[string][]Alert{}
	for _, a := range doc.RecentAlerts {
		if a.TS.After(dayAgo) {
			v.Alerts24++
			if a.Severity == "critical" {
				v.Critical24++
			}
			perKind[a.Kind] = append(perKind[a.Kind], a)
		}
	}
	for _, st := range steps {
		sv := stepView{Name: st.Name, Means: st.Means}
		for _, t := range st.Sensors {
			sv.Sensors = append(sv.Sensors, sensorRow{sensorLabels[t], active[t]})
			if active[t] > 0 {
				sv.Watched = true
			}
		}
		var latest Alert
		for _, k := range st.Kinds {
			for _, a := range perKind[k] {
				sv.Alerts++
				if a.TS.After(latest.TS) {
					latest = a
				}
			}
		}
		if sv.Alerts > 0 {
			sv.Last = latest.RuleID + " · " + ago(now, latest.TS)
		}
		v.Steps = append(v.Steps, sv)
	}

	for i, a := range doc.RecentAlerts {
		if i == 6 {
			v.MoreAlerts = len(doc.RecentAlerts) - 6
			break
		}
		v.Alerts = append(v.Alerts, alertRow{Time: a.TS.UTC().Format("15:04 UTC"), Ago: ago(now, a.TS), Rule: a.RuleID,
			Severity: a.Severity, Trace: a.TraceID, Subject: a.Subject, Critical: a.Severity == "critical"})
	}

	// Self-tests: the latest result per probe and a 7-day bar per day.
	latest := map[string]selftestRun{}
	v.Runs7 = len(history)
	var pass, fail int
	days := make([]dayBar, 7)
	for i := range days {
		days[i].Label = now.AddDate(0, 0, i-6).Format("Mon")
	}
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	for _, r := range history {
		latest[r.Probe] = r
		d := 6 - int(today.Sub(time.Date(r.TS.Year(), r.TS.Month(), r.TS.Day(), 0, 0, 0, 0, now.Location())).Hours()/24)
		switch r.Result {
		case "pass":
			pass++
			if d >= 0 && d < 7 {
				days[d].Pass++
			}
		case "fail":
			fail++
			if d >= 0 && d < 7 {
				days[d].Fail++
			}
		}
	}
	if pass+fail > 0 {
		v.PassRate = fmt.Sprintf("%.0f%%", 100*float64(pass)/float64(pass+fail))
	}
	for _, d := range days {
		if n := d.Pass + d.Fail; n > v.MaxRuns {
			v.MaxRuns = n
		}
	}
	for i := range days {
		if v.MaxRuns > 0 {
			days[i].PassH = days[i].Pass * chartH / v.MaxRuns
			days[i].FailH = days[i].Fail * chartH / v.MaxRuns
		}
		days[i].X = i * 48
		days[i].PassY = chartH - days[i].PassH
		days[i].FailY = days[i].PassY - days[i].FailH
	}
	v.Days = days
	for _, p := range []string{"egress-deny", "egress-allow", "trap-alive", "bundle-current"} {
		if r, ok := latest[p]; ok {
			v.Probes = append(v.Probes, probeRow{p, r.Result, ago(now, r.TS), r.Result == "fail", r.Result == "skip"})
		}
	}

	for _, src := range doc.Sources {
		internal := strings.HasPrefix(src.Source, "watcher.")
		if !internal {
			v.Sources++
			if src.Silent {
				v.Silent++
			} else {
				v.Reporting++
			}
		}
		hb := ago(now, src.LastHeartbeat)
		if internal {
			hb = "built in"
		}
		v.SourceRows = append(v.SourceRows, sourceRow{src.SourceID, src.Source, hb, src.Silent, internal})
	}
	sort.SliceStable(v.SourceRows, func(i, j int) bool { return v.SourceRows[i].Silent && !v.SourceRows[j].Silent })

	// The finding: the one fact that most needs attention.
	failed := ""
	for _, p := range v.Probes {
		if p.Fail {
			failed = p.Probe
			break
		}
	}
	switch {
	case v.Critical24 > 0:
		a := doc.RecentAlerts[0]
		v.Finding = fmt.Sprintf("%s in the last 24 hours. Latest: %s on %s, %s.", plural(v.Critical24, "critical alert", "critical alerts"), a.RuleID, a.Subject, ago(now, a.TS))
		v.FindingBad = true
	case failed != "":
		v.Finding = fmt.Sprintf("The %s self-test failed. A protection may not be working.", failed)
		v.FindingBad = true
	case v.Silent > 0:
		v.Finding = fmt.Sprintf("%s sent no heartbeat for 5 minutes or more.", plural(v.Silent, "source", "sources"))
		v.FindingBad = true
	default:
		v.Finding = "Nothing has tripped in the last 24 hours."
	}
	return v
}

var page = template.Must(template.New("status").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="30">
<title>tripline · watcher status</title>
<style>
:root{
  --ground:#191817;--surface:#1f1e1d;--raised:#272523;--border:#2e2c2a;--rule:#262422;
  --text:#f0eee6;--muted:#b4b0a8;--faint:#9c9890;
  --accent:#d97757;--negative:#ef6b6b;--pill-neg-bg:#3a1f1f;--pill-neg-ink:#ff9d9d;
  --positive:#5fbf86;--pill-pos-bg:#1c2b22;--pill-pos-ink:#8fd9ad;--pill-bg:#2e2c2a;
  --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
}
@media (prefers-color-scheme:light){:root{
  --ground:#f4f3ef;--surface:#ffffff;--raised:#f7f6f2;--border:#e4e2dc;--rule:#eeece7;
  --text:#1f1e1d;--muted:#57544f;--faint:#6b6862;
  --accent:#b5532f;--negative:#c4242a;--pill-neg-bg:#ffedea;--pill-neg-ink:#831c1e;
  --positive:#247b50;--pill-pos-bg:#dcfae5;--pill-pos-ink:#04250e;--pill-bg:#eeece7;
}}
*{box-sizing:border-box}
body{margin:0;background:var(--ground);color:var(--text);font:14px/20px system-ui,-apple-system,"Segoe UI",sans-serif}
a{color:inherit}
.num{font-variant-numeric:tabular-nums}
.bar{height:48px;display:flex;align-items:center;gap:12px;padding:0 24px;border-bottom:1px solid var(--border)}
.brand{display:flex;align-items:center;gap:8px;font-weight:600;text-decoration:none}
.scope{color:var(--muted)}
.bar nav{margin-left:auto;display:flex;gap:20px}
.bar nav a{color:var(--muted);text-decoration:none}
.bar nav a:hover,.bar nav a:focus-visible{color:var(--text)}
main{max-width:1200px;margin:0 auto;padding:32px 24px 48px}
/* grid: 12 columns, 16px gap; at 1152px wide: 2 x 568 + 16 = 1152, 760 + 16 + 376 = 1152 */
.grid{display:grid;grid-template-columns:repeat(12,1fr);gap:16px;align-items:start}
.title{grid-column:1/-1;display:flex;align-items:flex-end;gap:24px;margin-bottom:8px}
h1{font-size:24px;line-height:32px;font-weight:600;margin:0}
.finding{margin:4px 0 0;font-size:16px;line-height:24px;color:var(--muted)}
.finding.bad{color:var(--text)}
.finding.bad::before{content:"";display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--negative);margin-right:8px;vertical-align:1px}
.fresh{margin-left:auto;color:var(--faint);font-size:12px;white-space:nowrap}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:8px}
.kpis{grid-column:1/-1;display:grid;grid-template-columns:1.4fr 1fr 1fr 1fr 1fr}
.kpi{padding:16px 20px}
.kpi+.kpi{border-left:1px solid var(--border)}
.kpi .label{color:var(--muted);font-size:13px}
.kpi .value{font-size:24px;line-height:32px;margin-top:4px}
.kpi .value small{font-size:14px;color:var(--faint)}
.kpi .lead{font-size:32px;line-height:40px;font-weight:600}
.kpi .lead.hot{color:var(--negative)}
.kpi .sub{color:var(--faint);font-size:12px}
h2{font-size:16px;line-height:24px;font-weight:600;margin:0}
.head{display:flex;align-items:baseline;gap:12px;padding:16px 20px 8px}
.head .meta{margin-left:auto;color:var(--faint);font-size:12px}
.path{grid-column:1/-1}
.steps{display:grid;grid-template-columns:repeat(3,1fr)}
.step{padding:8px 20px 20px;position:relative}
.step+.step{border-left:1px solid var(--border)}
.step h3{font-size:16px;line-height:24px;margin:0;font-weight:600}
.step .means{color:var(--muted);margin:2px 0 12px;min-height:40px}
.count{font-size:32px;line-height:40px;font-weight:600}
.count.hit{color:var(--accent)}
.count small{font-size:14px;font-weight:400;color:var(--faint)}
.last{color:var(--muted);font-size:12px;min-height:16px}
.sensors{list-style:none;margin:12px 0 0;padding:12px 0 0;border-top:1px solid var(--rule)}
.sensors li{display:flex;justify-content:space-between;padding:2px 0}
.on{color:var(--text)}
.off{color:var(--faint)}
.gapnote{display:inline-block;margin-top:12px;padding:2px 8px;border-radius:4px;background:var(--pill-neg-bg);color:var(--pill-neg-ink);font-size:12px}
.flow{position:absolute;top:18px;right:-7px;width:12px;height:12px;z-index:1;color:var(--faint)}
.alerts{grid-column:span 8}
.side{grid-column:span 4;display:grid;gap:16px}
table{width:100%;border-collapse:collapse}
th{font-weight:400;color:var(--faint);font-size:12px;text-align:left;padding:0 20px 8px}
td{padding:12px 20px;border-top:1px solid var(--rule);vertical-align:top}
td .sub{display:block;color:var(--faint);font-size:12px;margin-top:2px}
.id{font-family:var(--mono);font-size:13px}
.pill{display:inline-block;flex:none;white-space:nowrap;padding:1px 8px;border-radius:4px;font-size:12px;background:var(--pill-bg);color:var(--muted)}
.pill.crit{background:var(--pill-neg-bg);color:var(--pill-neg-ink)}
.pill.pass{background:var(--pill-pos-bg);color:var(--pill-pos-ink)}
.empty{margin:4px 20px 20px;padding:12px 16px;border:1px dashed var(--border);border-radius:8px;color:var(--muted)}
.more{display:block;padding:12px 20px;border-top:1px solid var(--rule);color:var(--muted);font-size:13px}
.chart{padding:4px 20px 0}
.chart svg{display:block;width:100%;height:auto}
.chart text{fill:var(--faint);font-size:11px}
.probes{list-style:none;margin:0;padding:8px 20px 16px}
.probes li{display:flex;align-items:center;gap:8px;padding:6px 0}
.probes .ago{margin-left:auto;color:var(--faint);font-size:12px}
.sources li .type{color:var(--faint);font-size:12px}
footer{max-width:1200px;margin:0 auto;padding:0 24px 32px;color:var(--faint);font-size:12px}
@media (max-width:900px){
  .kpis{grid-template-columns:1fr 1fr}
  .kpi:first-child{grid-column:1/-1}
  .kpi+.kpi{border-left:0;border-top:1px solid var(--border)}
  .steps{grid-template-columns:1fr}
  .step+.step{border-left:0;border-top:1px solid var(--border)}
  .flow{display:none}
  .alerts,.side{grid-column:1/-1}
  .title{flex-wrap:wrap}
  .fresh{margin-left:0}
}
@media (max-width:640px){
  main{padding:20px 16px 32px}
  .bar{padding:0 16px}
  .bar .scope{display:none}
  th:nth-child(3),td:nth-child(3){display:none}
  td,th{padding-left:16px;padding-right:16px}
  .path .head .meta{display:none}
}
</style></head><body>
<header class="bar">
  <a class="brand" href="/" aria-label="tripline status">
    <svg width="22" height="22" viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="var(--accent)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 15h7l3-6 3 6h7"/></svg>
    tripline
  </a>
  <span class="scope">watcher{{with .Host}} on {{.}}{{end}}</span>
  <nav><a href="/status.json">status.json</a><a href="/metrics">metrics</a></nav>
</header>
<main class="grid">
  <div class="title">
    <div>
      <h1>Watcher status</h1>
      <p class="finding{{if .FindingBad}} bad{{end}}">{{.Finding}}</p>
    </div>
    <span class="fresh">Updated {{.Updated}} · refreshes every 30 s</span>
  </div>

  <section class="panel kpis" aria-label="Summary">
    <div class="kpi"><div class="label">Critical alerts, last 24 h</div>
      <div class="lead num{{if .Critical24}} hot{{end}}">{{.Critical24}}</div>
      <div class="sub">{{.Alerts24}} alerts in total</div></div>
    <div class="kpi"><div class="label">Self-tests passed, 7 days</div>
      <div class="value num">{{.PassRate}}</div><div class="sub">{{.Runs7}} probe runs</div></div>
    <div class="kpi"><div class="label">Sensors reporting</div>
      <div class="value num">{{.Reporting}}<small> of {{.Sources}}</small></div>
      <div class="sub">{{if .Silent}}{{.Silent}} silent{{else}}none silent{{end}}</div></div>
    <div class="kpi"><div class="label">Rule bundle</div>
      <div class="value num">{{if .Bundle}}v{{.Bundle}}{{else}}—{{end}}</div>
      <div class="sub">{{if .Bundle}}signed{{else}}floor rules only{{end}}</div></div>
    <div class="kpi"><div class="label">Events rejected</div>
      <div class="value num">{{.Rejected}}</div><div class="sub">failed validation</div></div>
  </section>

  <section class="panel path" aria-labelledby="path-h">
    <div class="head"><h2 id="path-h">Attack path</h2><span class="meta">alerts in the last 24 h, per step every attack must take</span></div>
    <div class="steps">
    {{range $i, $s := .Steps}}
      <div class="step">
        {{if lt $i 2}}<svg class="flow" viewBox="0 0 12 12" aria-hidden="true"><path d="M2 2l5 4-5 4" fill="none" stroke="currentColor" stroke-width="1.5"/></svg>{{end}}
        <h3>{{$s.Name}}</h3>
        <p class="means">{{$s.Means}}</p>
        <div class="count num{{if $s.Alerts}} hit{{end}}">{{$s.Alerts}}<small> {{if eq $s.Alerts 1}}alert{{else}}alerts{{end}}</small></div>
        <div class="last">{{with $s.Last}}Latest: {{.}}{{end}}</div>
        <ul class="sensors">
          {{range $s.Sensors}}<li><span class="{{if .Active}}on{{else}}off{{end}}">{{.Label}}</span><span class="num {{if .Active}}on{{else}}off{{end}}">{{if .Active}}{{.Active}} active{{else}}not deployed{{end}}</span></li>{{end}}
        </ul>
        {{if not $s.Watched}}<span class="gapnote">Not watched</span>{{end}}
      </div>
    {{end}}
    </div>
  </section>

  <section class="panel alerts" aria-labelledby="alerts-h">
    <div class="head"><h2 id="alerts-h">Recent alerts</h2><span class="meta">newest first</span></div>
    {{if .Alerts}}
    <table>
      <thead><tr><th>Rule</th><th>Severity</th><th>Trace ID</th><th style="text-align:right">When</th></tr></thead>
      <tbody>
      {{range .Alerts}}<tr>
        <td>{{.Rule}}<span class="sub">{{.Subject}}</span></td>
        <td><span class="pill{{if .Critical}} crit{{end}}">{{.Severity}}</span></td>
        <td class="id">{{.Trace}}</td>
        <td class="num" style="text-align:right">{{.Time}}<span class="sub">{{.Ago}}</span></td>
      </tr>{{end}}
      </tbody>
    </table>
    {{if .MoreAlerts}}<span class="more">{{.MoreAlerts}} older alerts are in the audit log and in status.json.</span>{{end}}
    {{else}}<p class="empty">No alerts since the watcher started. Trip a decoy to test the path end to end.</p>{{end}}
  </section>

  <div class="side">
    <section class="panel" aria-labelledby="st-h">
      <div class="head"><h2 id="st-h">Self-tests</h2><span class="meta num">{{.PassRate}} passed, 7 days</span></div>
      {{if .Runs7}}
      <div class="chart">
        <svg viewBox="0 0 336 96" role="img" aria-label="Self-test runs per day for 7 days, passes and failures">
          <line x1="0" y1="72.5" x2="336" y2="72.5" stroke="var(--border)"/>
          {{range $i, $d := .Days}}
            <g transform="translate({{$d.X}},0)">
              {{if $d.PassH}}<rect x="10" y="{{$d.PassY}}" width="28" height="{{$d.PassH}}" fill="var(--muted)"><title>{{$d.Label}}: {{$d.Pass}} passed</title></rect>{{end}}
              {{if $d.FailH}}<rect x="10" y="{{$d.FailY}}" width="28" height="{{$d.FailH}}" fill="var(--negative)"><title>{{$d.Label}}: {{$d.Fail}} failed</title></rect>{{end}}
              <text x="24" y="90" text-anchor="middle">{{$d.Label}}</text>
            </g>
          {{end}}
        </svg>
      </div>
      <ul class="probes">
        {{range .Probes}}<li><span class="pill{{if .Fail}} crit{{else if not .Skip}} pass{{end}}">{{.Result}}</span><span>{{.Probe}}</span><span class="ago">{{.Ago}}</span></li>{{end}}
      </ul>
      {{else}}<p class="empty">No self-test has run yet. The first run starts 10 seconds after the watcher starts.</p>{{end}}
    </section>

    <section class="panel" aria-labelledby="src-h">
      <div class="head"><h2 id="src-h">Sources</h2><span class="meta">heartbeat every 30 s</span></div>
      {{if .SourceRows}}
      <ul class="probes sources">
        {{range .SourceRows}}<li><span class="pill{{if .Silent}} crit{{else if not .Internal}} pass{{end}}">{{if .Silent}}silent{{else}}ok{{end}}</span><span>{{.ID}}<span class="sub type"> · {{.Type}}</span></span><span class="ago">{{.Heartbeat}}</span></li>{{end}}
      </ul>
      {{else}}<p class="empty">No sensor has reported yet. Add one with tripline sensor add.</p>{{end}}
    </section>
  </div>
</main>
<footer>tripline {{.Version}} · watch-only unless a signed bundle sets enforce</footer>
</body></html>
`))
