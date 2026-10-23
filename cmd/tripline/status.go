package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Parthkomalwad/tripline/internal/watcher"
)

// statusDoc is the contract of GET /status.json on watcher.status_page.
type statusDoc struct {
	BundleVersion int `json:"bundle_version"`
	Sources       []struct {
		SourceID      string `json:"source_id"`
		Source        string `json:"source"`
		LastHeartbeat string `json:"last_heartbeat"`
		Silent        bool   `json:"silent"`
	} `json:"sources"`
	Coverage []struct {
		SensorType string `json:"sensor_type"`
		Active     int    `json:"active"`
		Gap        bool   `json:"gap"`
	} `json:"coverage"`
	SelftestPassRate7d *float64 `json:"selftest_pass_rate_7d"`
	RecentAlerts       []struct {
		TS       string `json:"ts"`
		RuleID   string `json:"rule_id"`
		Severity string `json:"severity"`
		TraceID  string `json:"trace_id"`
		Subject  string `json:"subject"`
	} `json:"recent_alerts"`
	EventsRejected int `json:"events_rejected"`
}

// cmdStatus handles "tripline status [-config c.yaml] [-json]".
func cmdStatus(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "tripline.yaml", "config file")
	asJSON := fs.Bool("json", false, "print the raw status JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := watcher.LoadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "tripline:", err)
		return 1
	}
	addr := cfg.Watcher.StatusPage
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://" + addr + "/status.json")
	if err != nil {
		fmt.Fprintf(stderr, "tripline: watcher unreachable at %s: %v\nA watcher that does not answer is itself a signal. Check that it is running.\n", addr, err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(stderr, "tripline: watcher at %s returned HTTP %d\n", addr, resp.StatusCode)
		return 1
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		fmt.Fprintln(stderr, "tripline: reading status:", err)
		return 1
	}
	if *asJSON {
		stdout.Write(body)
		fmt.Fprintln(stdout)
		return 0
	}
	var s statusDoc
	if err := json.Unmarshal(body, &s); err != nil {
		fmt.Fprintln(stderr, "tripline: bad status response:", err)
		return 1
	}
	printStatus(stdout, &s)
	return 0
}

func printStatus(w io.Writer, s *statusDoc) {
	fmt.Fprintf(w, "Rule bundle version: %d\n", s.BundleVersion)
	fmt.Fprintf(w, "Events rejected: %d\n", s.EventsRejected)
	if s.SelftestPassRate7d == nil {
		fmt.Fprintln(w, "Self-test pass rate (7d): no data")
	} else {
		fmt.Fprintf(w, "Self-test pass rate (7d): %.1f%%\n", *s.SelftestPassRate7d*100)
	}
	fmt.Fprintln(w, "\nSources:")
	if len(s.Sources) == 0 {
		fmt.Fprintln(w, "  none")
	}
	for _, x := range s.Sources {
		flag := ""
		if x.Silent {
			flag = "  SILENT"
		}
		fmt.Fprintf(w, "  %s (%s) last heartbeat %s%s\n", x.SourceID, x.Source, x.LastHeartbeat, flag)
	}
	fmt.Fprintln(w, "\nCoverage:")
	for _, c := range s.Coverage {
		state := "watched"
		if c.Gap || c.Active == 0 {
			state = "NOT WATCHED"
		}
		fmt.Fprintf(w, "  %s: %s\n", c.SensorType, state)
	}
	fmt.Fprintln(w, "\nRecent alerts:")
	if len(s.RecentAlerts) == 0 {
		fmt.Fprintln(w, "  none")
	}
	for i, a := range s.RecentAlerts {
		if i == 5 {
			break
		}
		fmt.Fprintf(w, "  %s %s [%s] %s trace=%s\n", a.TS, a.RuleID, a.Severity, a.Subject, a.TraceID)
	}
}
