package outbound

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// DefaultProbeTimeout bounds a probe whose context carries no deadline.
const DefaultProbeTimeout = 5 * time.Second

// probeBodyLimit is how much of the response body a probe reads to confirm that
// the tunnel carries data. The latency is measured at the response headers, so
// the body never inflates it.
const probeBodyLimit = 8 << 10

// probeUserAgent identifies the core to the server being probed.
const probeUserAgent = "MelonARC"

// Resolver maps a policy target name to the dialer that handles it. It is what
// makes a probe follow the same path as the traffic: a DIRECT member resolves to
// the direct dialer, a proxy member to that proxy, and a nested group to
// whichever member it currently routes to.
type Resolver func(name string) (Dialer, error)

// Prober probes the members of one policy group through their own outbound. It
// implements policy.Prober, whose method only names a member; the target URL is
// bound when the prober is built, one prober per group, so each group keeps its
// own url= without the interface having to carry it.
type Prober struct {
	url     *url.URL
	resolve Resolver
	timeout time.Duration
}

// NewProber builds a prober for one group URL.
func NewProber(rawURL string, resolve Resolver) (*Prober, error) {
	if resolve == nil {
		return nil, errors.New("outbound: prober needs a resolver")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("outbound: probe url %q: %w", rawURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("outbound: probe url %q is not http or https", rawURL)
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("outbound: probe url %q has no host", rawURL)
	}
	return &Prober{
		url:     u,
		resolve: resolve,
		timeout: DefaultProbeTimeout,
	}, nil
}

// Probe measures the time to the response headers of the group URL, dialing
// through the outbound the member resolves to. A member whose outbound cannot
// dial, whose request fails, or whose answer is an error status is unhealthy;
// the returned latency is only meaningful when the error is nil.
func (p *Prober) Probe(ctx context.Context, member string) (time.Duration, error) {
	if member == "" {
		return 0, errors.New("outbound: probe without a member name")
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.timeout)
		defer cancel()
	}
	dialer, err := p.resolve(member)
	if err != nil {
		return 0, fmt.Errorf("probe %s: %w", member, err)
	}
	transport := &http.Transport{
		// The tunnel replaces the network: every dial of the request goes
		// through the member's outbound, so the probe follows the policy
		// instead of always leaving the host directly.
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, address)
		},
		DisableKeepAlives:      true,
		DisableCompression:     true,
		ForceAttemptHTTP2:      false,
		MaxResponseHeaderBytes: 16 << 10,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		// A redirect proves the path works; following it would only add
		// latency and could loop.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url.String(), nil)
	if err != nil {
		return 0, fmt.Errorf("probe %s: %w", member, err)
	}
	req.Header.Set("User-Agent", probeUserAgent)
	req.Header.Set("Accept", "*/*")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("probe %s: %w", member, err)
	}
	latency := time.Since(start)
	// Read a little of the body so a tunnel that answers headers but carries
	// no payload does not count as healthy.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, probeBodyLimit))
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 399 {
		return 0, fmt.Errorf("probe %s: %s answered %d %s",
			member, p.url, resp.StatusCode, http.StatusText(resp.StatusCode))
	}
	return latency, nil
}
