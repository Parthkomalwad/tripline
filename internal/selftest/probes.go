package selftest

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/Parthkomalwad/tripline/internal/event"
	"github.com/Parthkomalwad/tripline/internal/sensor/egress"
	"github.com/Parthkomalwad/tripline/internal/tripwire"
)

const connectTimeout = 10 * time.Second

// connect sends CONNECT target through the proxy and returns the status
// code. It sends no tunnel bytes and closes the connection at once.
func connect(proxyURL, target string) (int, error) {
	u, err := url.Parse(proxyURL)
	if err != nil || u.Host == "" {
		return 0, fmt.Errorf("bad proxy_url")
	}
	c, err := net.DialTimeout("tcp", u.Host, connectTimeout)
	if err != nil {
		return 0, fmt.Errorf("cannot reach proxy: %w", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(connectTimeout))
	if _, err := io.WriteString(c, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n"); err != nil {
		return 0, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: http.MethodConnect})
	if err != nil {
		return 0, err
	}
	return resp.StatusCode, nil
}

// egressDeny passes when the sensor reports the reserved-host CONNECT as
// denied or observed, with attrs.selftest set, in time.
func (r *Runner) egressDeny(s Sensor) (string, string) {
	w := r.expect(func(e *event.Event) bool {
		return e.Kind == event.KindEgressConnect && e.SourceID == s.ID &&
			e.Attrs["host"] == egress.SelftestHost && e.Attrs["selftest"] == true &&
			(e.Decision == event.DecisionDeny || e.Decision == event.DecisionObserve)
	})
	if _, err := connect(s.ProxyURL, egress.SelftestHost+":443"); err != nil {
		r.drop(w)
		return Fail, err.Error()
	}
	timeout := r.DenyTimeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	if !r.await(w, timeout) {
		return Fail, fmt.Sprintf("no denied or observed selftest event from the sensor within %s", timeout)
	}
	return Pass, ""
}

// drop removes a waiter that will not be awaited.
func (r *Runner) drop(w *waiter) { r.await(w, 0) }

// egressAllow passes when the allowlisted host gets a 200 tunnel.
func (r *Runner) egressAllow(s Sensor) (string, string) {
	host := r.AllowHost
	if host == "" {
		host = DefaultAllowHost
	}
	code, err := connect(s.ProxyURL, host)
	switch {
	case err != nil:
		return Fail, err.Error()
	case code != http.StatusOK:
		return Fail, fmt.Sprintf("allowed host got status %d, want 200", code)
	}
	return Pass, ""
}

// discard is a ResponseWriter that drops the response.
type discard struct{ h http.Header }

func (d discard) Header() http.Header         { return d.h }
func (d discard) Write(b []byte) (int, error) { return len(b), nil }
func (d discard) WriteHeader(int)             {}

// trapAlive hits the self-test decoy in process and passes when the
// watcher observes the tripwire.hit with selftest=true.
func (r *Runner) trapAlive() (string, string) {
	d, ok := r.Registry.Selftest()
	if !ok {
		var err error
		if d, err = r.Registry.Add("selftest", "selftest", true); err != nil {
			return Fail, "cannot create the selftest decoy: " + err.Error()
		}
	}
	fp := tripwire.Fingerprint(d.Token)
	w := r.expect(func(e *event.Event) bool {
		return e.Kind == event.KindTripwireHit && e.Attrs["token_fp"] == fp && e.Attrs["selftest"] == true
	})
	req, err := http.NewRequest(http.MethodGet, "/trap/"+d.Token+"/selftest", http.NoBody)
	if err != nil {
		r.drop(w)
		return Fail, err.Error()
	}
	req.RemoteAddr = "127.0.0.1:0"
	r.Trap.ServeHTTP(discard{http.Header{}}, req)
	if !r.await(w, time.Second) {
		return Fail, "the trap did not report a selftest hit"
	}
	return Pass, ""
}
