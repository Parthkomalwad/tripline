# tripline Grafana dashboard

`tripline.json` shows watcher health: self-test pass rate, alerts, events, rule matches, source heartbeats, bundle version and rejected events.

## Import

1. In Grafana, open Dashboards, New, Import.
2. Upload `tripline.json`.
3. Pick your Prometheus data source for `DS_PROMETHEUS`.

## Scrape config

The watcher serves `/metrics` on the address in `watcher.status_page`. The default is `127.0.0.1:7701`.

```yaml
scrape_configs:
  - job_name: tripline
    scrape_interval: 30s
    static_configs:
      - targets: ["127.0.0.1:7701"]
```

The status listener binds to localhost by default. Prometheus must run on the same host, or you must change `watcher.status_page` on purpose. The listener has no authentication, so do not expose it on a public interface.

## Notes

- The heartbeat panel turns red at 300 seconds. A source that never sent a heartbeat has no series.
- The decision latency panel reads `tripline_sensor_decision_latency_seconds`. The watcher declares this histogram but does not fill it yet. The panel stays empty until sensors report latency.
- `internal/watcher/grafana_test.go` fails when a panel uses a metric that `/metrics` does not emit.
