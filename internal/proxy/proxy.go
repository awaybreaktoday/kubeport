// Package proxy runs a local HTTPS reverse proxy that terminates TLS with
// a leaf certificate issued by the kubeport local CA and forwards plaintext
// requests to the port-forward tunnel via a caller-supplied DialContext.
//
// The DialContext lets the caller route upstream traffic over an
// authenticated IPC endpoint (Unix domain socket or Windows named pipe)
// instead of a TCP loopback port, so other local processes cannot bypass
// the TLS terminator by dialing the upstream directly.
package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"time"
)

// DialFunc matches http.Transport.DialContext.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Proxy is an HTTPS reverse proxy listening on ListenAddr.
type Proxy struct {
	ListenAddr string // e.g. "127.0.0.1:443"
	Dial       DialFunc
	Hostname   string // host header to pass upstream (optional)
	Cert       tls.Certificate

	server *http.Server
}

// New builds a Proxy. Dial is used for every upstream connection; the
// address argument passed to Dial is a sentinel and should be ignored.
func New(listenAddr string, dial DialFunc, hostname string, cert tls.Certificate) *Proxy {
	return &Proxy{
		ListenAddr: listenAddr,
		Dial:       dial,
		Hostname:   hostname,
		Cert:       cert,
	}
}

// Start begins serving. It returns once the listener is bound, with the
// server running in a background goroutine. Errors from the background
// goroutine are delivered via the returned channel.
func (p *Proxy) Start() (<-chan error, error) {
	// The host portion of the upstream URL is opaque — routing is done by
	// p.Dial, not by net.Dial on the URL's host. We use a sentinel so that
	// any mistaken direct-dial gets a fast, loud failure rather than
	// silently hitting 127.0.0.1.
	upstreamURL := &url.URL{Scheme: "http", Host: "kubeport.internal"}
	rp := httputil.NewSingleHostReverseProxy(upstreamURL)

	origDirector := rp.Director
	hostname := p.Hostname
	rp.Director = func(r *http.Request) {
		origDirector(r)
		if hostname != "" {
			r.Host = hostname
			r.Header.Set("X-Forwarded-Host", hostname)
		}
		r.Header.Set("X-Forwarded-Proto", "https")
	}

	rp.Transport = &http.Transport{
		DialContext: p.Dial,
		// Disable keep-alives across the custom dialer: the SPDY stream
		// model treats each accepted connection as a fresh tunnel, and
		// holding a client-side idle connection open keeps a stream
		// allocated on the apiserver side for no benefit.
		DisableKeepAlives: true,
	}

	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		http.Error(w, fmt.Sprintf("kubeport upstream error: %v", err), http.StatusBadGateway)
	}

	p.server = &http.Server{
		Addr:              p.ListenAddr,
		Handler:           rp,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{p.Cert},
			MinVersion:   tls.VersionTLS12,
		},
	}

	ln, err := net.Listen("tcp", p.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("bind %s: %w", p.ListenAddr, err)
	}
	tlsLn := tls.NewListener(ln, p.server.TLSConfig)

	errCh := make(chan error, 1)
	go func() {
		if err := p.server.Serve(tlsLn); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()
	return errCh, nil
}

// Stop gracefully shuts down the proxy.
func (p *Proxy) Stop(ctx context.Context) error {
	if p.server == nil {
		return nil
	}
	return p.server.Shutdown(ctx)
}

// ParseHostPort splits "host:port" and returns the port as int.
func ParseHostPort(addr string) (string, int, error) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		return "", 0, err
	}
	return h, n, nil
}
