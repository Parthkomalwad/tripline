package egress

import (
	"sync/atomic"
	"time"
)

// LatencyBuckets are the upper bounds in seconds, as in the watcher metrics.
// The last bucket is +Inf.
var LatencyBuckets = [...]float64{0.001, 0.01, 0.1, 1}

// Histogram records decision latency. Counts are per bucket, not cumulative.
type Histogram struct {
	counts   [len(LatencyBuckets) + 1]atomic.Uint64
	sumNanos atomic.Int64
}

// Observe records one decision.
func (h *Histogram) Observe(d time.Duration) {
	h.sumNanos.Add(int64(d))
	s := d.Seconds()
	for i, le := range LatencyBuckets {
		if s <= le {
			h.counts[i].Add(1)
			return
		}
	}
	h.counts[len(LatencyBuckets)].Add(1)
}

// Snapshot returns cumulative bucket counts (the last is the total), and the sum in seconds.
func (h *Histogram) Snapshot() (cum []uint64, sum float64) {
	var t uint64
	for i := range h.counts {
		t += h.counts[i].Load()
		cum = append(cum, t)
	}
	return cum, time.Duration(h.sumNanos.Load()).Seconds()
}
