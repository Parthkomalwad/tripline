package egress

import (
	"net/http"

	"github.com/Parthkomalwad/tripline/internal/event"
)

// SelftestHost is the reserved CONNECT target of the egress-deny probe.
// RFC 2606 says .invalid never resolves, so the proxy never dials it.
const SelftestHost = "selftest.tripline.invalid"

// selftest sends the probe event (bypassing aggregation, so every probe is
// reported) and answers 403 when denied, else 502 since the host cannot resolve.
func (p *Proxy) selftest(w http.ResponseWriter, host string, port int, v verdict) {
	e := p.newEvent(aggKey{host, port, v.decision}, v.ruleID, 1, false)
	e.Attrs["selftest"] = true
	p.send(e)
	if v.decision == event.DecisionDeny {
		http.Error(w, "blocked by tripline", http.StatusForbidden)
		return
	}
	http.Error(w, "cannot reach destination", http.StatusBadGateway)
}
