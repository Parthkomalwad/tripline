// Package egress is the egress sensor: a forward proxy that decides on
// CONNECT requests by host and port. It never terminates TLS.
//
// Only CONNECT is handled (RFC 9110 section 9.3.6). Plain HTTP proxying is
// out of scope: other methods get 405. The proxy never depends on the watcher:
// events go to a non-blocking send function, and enforcement uses the last
// rules set with SetRules.
package egress

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Parthkomalwad/tripline/internal/event"
)

// Proxy is a CONNECT-only forward proxy. Create it with New.
type Proxy struct {
	cfg     Config
	send    func(event.Event)
	log     *slog.Logger
	rs      ruleState
	agg     *aggregator
	Latency Histogram

	// DialTimeout and IdleTimeout bound a tunnel. Tests may shorten them.
	DialTimeout time.Duration
	IdleTimeout time.Duration
}

// New returns a proxy. send must not block (client.Client.Send does not).
func New(cfg Config, send func(event.Event), log *slog.Logger) *Proxy {
	if log == nil {
		log = slog.Default()
	}
	return &Proxy{cfg: cfg, send: send, log: log,
		agg:         &aggregator{window: time.Minute, entries: map[aggKey]*aggEntry{}},
		DialTimeout: 10 * time.Second, IdleTimeout: 5 * time.Minute}
}

// ServeHTTP handles one request.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		w.Header().Set("Allow", http.MethodConnect)
		http.Error(w, "only CONNECT is supported", http.StatusMethodNotAllowed)
		return
	}
	host, port, err := splitTarget(r.Host)
	if err != nil {
		http.Error(w, "bad CONNECT target", http.StatusBadRequest) // RFC 9110: invalid port => 400
		return
	}
	v := p.decide(host, port)
	p.report(host, port, v)
	if v.decision == event.DecisionDeny {
		http.Error(w, "blocked by tripline", http.StatusForbidden)
		return
	}
	up, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), p.DialTimeout)
	if err != nil {
		http.Error(w, "cannot reach destination", http.StatusBadGateway)
		return
	}
	defer up.Close()
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	cc, brw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer cc.Close()
	// A 2xx to CONNECT must not carry Content-Length or Transfer-Encoding.
	if _, err := io.WriteString(cc, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if n := brw.Reader.Buffered(); n > 0 { // client bytes read ahead with the request
		b, _ := brw.Reader.Peek(n)
		if _, err := up.Write(b); err != nil {
			return
		}
	}
	p.tunnel(cc, up)
}

// splitTarget parses host:port. The port is required and must be 1-65535.
func splitTarget(hostport string) (string, int, error) {
	h, ps, err := net.SplitHostPort(hostport)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(ps)
	if err != nil || port < 1 || port > 65535 || h == "" {
		return "", 0, fmt.Errorf("invalid target")
	}
	return strings.TrimSuffix(strings.ToLower(h), "."), port, nil
}

// tunnel copies bytes both ways until both sides end or go idle.
func (p *Proxy) tunnel(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() { p.copyIdle(b, a); done <- struct{}{} }()
	go func() { p.copyIdle(a, b); done <- struct{}{} }()
	<-done
	<-done
}

// copyIdle is io.Copy with an idle deadline on the source. At the end it
// half-closes the destination so the peer sees EOF.
func (p *Proxy) copyIdle(dst, src net.Conn) {
	_, _ = io.Copy(dst, idleReader{src, p.IdleTimeout})
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	} else {
		_ = dst.Close()
	}
}

type idleReader struct {
	c    net.Conn
	idle time.Duration
}

func (r idleReader) Read(b []byte) (int, error) {
	_ = r.c.SetReadDeadline(time.Now().Add(r.idle))
	return r.c.Read(b)
}
