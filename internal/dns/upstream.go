package dns

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Defaults for the plaintext upstream.
const (
	// DefaultUpstreamTimeout bounds one attempt against one server, over one
	// transport. The resolver still bounds the whole lookup, so a slow server
	// cannot hold a request for longer than that budget.
	//
	// One second, not more, because the whole lookup has a budget of its own
	// (DefaultTimeout) and the fallback to the system resolver has to fit in the
	// remainder. A question costs at most two attempts per server, one per
	// transport, so two servers answering nothing spend four seconds and leave
	// the last second of a five second budget for the fallback. A configuration
	// with more servers, or a shorter budget, lowers this setting: the worst
	// case is servers times transports times this value, and anything past the
	// budget means the fallback is never reached.
	DefaultUpstreamTimeout = time.Second
	// DefaultDNSPort is the port a server address without one is given.
	DefaultDNSPort = "53"
)

// Answer is what an upstream said about a name.
type Answer struct {
	// IPs are the addresses of the answer, IPv4 first, in the order the server
	// listed them.
	IPs []net.IP
	// TTL is how long the server allows the answer to be reused. Zero means the
	// server did not say, which is the case for the system resolver.
	TTL time.Duration
}

// ExchangeFunc asks an upstream for the addresses of a name. A name the upstream
// knows does not exist must be reported as a *NegativeError, so the resolver can
// cache the answer for exactly as long as the upstream allowed.
type ExchangeFunc func(ctx context.Context, host string) (Answer, error)

// NegativeKind says why a name has no address.
type NegativeKind string

// The two ways an upstream reports "no address".
const (
	// NegativeNXDomain is "this name does not exist".
	NegativeNXDomain NegativeKind = "nxdomain"
	// NegativeNoData is "the name exists but carries no address of the family
	// that was asked for".
	NegativeNoData NegativeKind = "nodata"
)

// NegativeError is a definitive "no address" answer. It is the only failure the
// resolver treats as a property of the name instead of a property of the moment,
// and it carries the lifetime the upstream asked for.
//
// It unwraps to ErrNotFound, so a caller that only wants to know whether the
// name exists does not have to know about this type.
type NegativeError struct {
	// Name is the name that was asked for.
	Name string
	// Kind is which of the two negative answers the upstream gave.
	Kind NegativeKind
	// Reason is a short human readable explanation.
	Reason string
	// Lifetime is how long the upstream allows the answer to be remembered.
	// Zero means the answer did not carry the information.
	Lifetime time.Duration
}

// Error implements error.
func (e *NegativeError) Error() string {
	return fmt.Sprintf("dns: %s: %s", e.Name, e.Reason)
}

// Unwrap makes errors.Is(err, ErrNotFound) true for a negative answer.
func (e *NegativeError) Unwrap() error { return ErrNotFound }

// Upstream is a plaintext DNS client. It asks the configured servers in order,
// over UDP first and over TCP when the answer was cut short or the datagram
// attempt failed, and reports the lifetime the answer carried.
//
// It is stateless apart from its configuration: caching belongs to the resolver,
// which is the only place that knows how a name is used.
type Upstream struct {
	servers []string
	timeout time.Duration
}

// NewUpstream builds a client for the given servers. An address may be an IP
// literal (the default port is used) or host:port; a name is rejected, because
// resolving the resolver would need a resolver.
func NewUpstream(servers []string, timeout time.Duration) (*Upstream, error) {
	if len(servers) == 0 {
		return nil, errors.New("dns: no upstream server is configured")
	}
	if timeout <= 0 {
		timeout = DefaultUpstreamTimeout
	}
	normalised := make([]string, 0, len(servers))
	seen := make(map[string]bool, len(servers))
	for _, server := range servers {
		addr, err := ParseNameServer(server)
		if err != nil {
			return nil, err
		}
		if seen[addr] {
			continue
		}
		seen[addr] = true
		normalised = append(normalised, addr)
	}
	return &Upstream{servers: normalised, timeout: timeout}, nil
}

// Servers returns the addresses the client asks, in order.
func (u *Upstream) Servers() []string {
	if u == nil {
		return nil
	}
	return append([]string(nil), u.servers...)
}

// ParseNameServer normalises one configured server address: an IP literal keeps
// the default port, host:port is validated, anything else is rejected.
//
// It is exported because configuration validation and the client must agree on
// what a server address is; a second parser would eventually disagree.
func ParseNameServer(server string) (string, error) {
	s := strings.TrimSpace(server)
	if s == "" {
		return "", errors.New("dns: a nameserver address is empty")
	}
	if host, port, err := net.SplitHostPort(s); err == nil {
		if net.ParseIP(host) == nil {
			return "", fmt.Errorf("dns: nameserver %q must be an IP address, not a name", s)
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", fmt.Errorf("dns: nameserver %q has an invalid port", s)
		}
		return net.JoinHostPort(host, port), nil
	}
	if net.ParseIP(s) == nil {
		return "", fmt.Errorf("dns: nameserver %q is neither an IP address nor host:port", s)
	}
	return net.JoinHostPort(s, DefaultDNSPort), nil
}

// Exchange asks the configured servers, in order, for the addresses of host.
//
// A negative answer ends the search: the name does not exist, and another server
// would only say so again. A transport failure moves on to the next server; when
// every server failed, the last failure is returned.
func (u *Upstream) Exchange(ctx context.Context, host string) (Answer, error) {
	if len(u.servers) == 0 {
		return Answer{}, errors.New("dns: no upstream server is configured")
	}
	var lastErr error
	for _, server := range u.servers {
		ans, err := u.exchangeServer(ctx, server, host)
		if err == nil {
			return ans, nil
		}
		if isNotFound(err) {
			return Answer{}, err
		}
		lastErr = fmt.Errorf("%s: %w", server, err)
		if ctx.Err() != nil {
			return Answer{}, lastErr
		}
	}
	return Answer{}, lastErr
}

// exchangeServer asks one server for both address families concurrently, so a
// server that answers neither costs one timeout rather than two.
func (u *Upstream) exchangeServer(ctx context.Context, server, host string) (Answer, error) {
	families := [2]uint16{typeA, typeAAAA}
	var (
		wg      sync.WaitGroup
		records [2][]answerRecord
		errs    [2]error
	)
	for i, qtype := range families {
		wg.Add(1)
		go func(i int, qtype uint16) {
			defer wg.Done()
			records[i], errs[i] = u.query(ctx, server, host, qtype)
		}(i, qtype)
	}
	wg.Wait()

	var (
		ips      []net.IP
		ttl      uint32
		haveTTL  bool
		negative *NegativeError
		failure  error
	)
	for i := range records {
		switch {
		case errs[i] == nil:
			for _, record := range records[i] {
				ips = append(ips, record.ip)
				if !haveTTL || record.ttl < ttl {
					ttl, haveTTL = record.ttl, true
				}
			}
		case isNotFound(errs[i]):
			var neg *NegativeError
			if errors.As(errs[i], &neg) {
				// NXDOMAIN is the stronger statement: prefer it over NODATA
				// from the other family, which is only about one record type.
				if negative == nil || (negative.Kind == NegativeNoData && neg.Kind == NegativeNXDomain) {
					negative = neg
				}
			}
		default:
			if failure == nil {
				failure = errs[i]
			}
		}
	}

	switch {
	case len(ips) > 0:
		return Answer{IPs: dedupeIPs(ips), TTL: time.Duration(ttl) * time.Second}, nil
	case negative != nil:
		return Answer{}, negative
	case failure != nil:
		return Answer{}, failure
	default:
		return Answer{}, &NegativeError{
			Name:   host,
			Kind:   NegativeNoData,
			Reason: "the answer carries no address",
		}
	}
}

// query asks one question over one server and interprets the answer.
func (u *Upstream) query(ctx context.Context, server, host string, qtype uint16) ([]answerRecord, error) {
	resp, err := u.roundTrip(ctx, server, host, qtype)
	if err != nil {
		return nil, err
	}
	switch resp.rcode {
	case rcodeNoError:
	case rcodeNXDomain:
		return nil, &NegativeError{
			Name:     host,
			Kind:     NegativeNXDomain,
			Reason:   "the name does not exist",
			Lifetime: soaLifetime(resp),
		}
	default:
		return nil, fmt.Errorf("the server answered with rcode %d", resp.rcode)
	}
	if len(resp.records) == 0 {
		return nil, &NegativeError{
			Name:     host,
			Kind:     NegativeNoData,
			Reason:   "the answer carries no address",
			Lifetime: soaLifetime(resp),
		}
	}
	return resp.records, nil
}

// soaLifetime returns the lifetime a negative answer asked for, zero when the
// answer carried no SOA record.
func soaLifetime(resp *response) time.Duration {
	if !resp.hasSOA {
		return 0
	}
	return time.Duration(resp.soaTTL) * time.Second
}

// roundTrip sends one question and returns the parsed answer. UDP is tried
// first; a truncated answer, or a datagram attempt that failed outright, is
// retried over TCP against the same server.
//
// Truncation is read from the header rather than from a parse of the body: a
// truncated message may well end in the middle of a record, and the client has to
// ask again over the stream instead of reporting a malformed answer.
func (u *Upstream) roundTrip(ctx context.Context, server, host string, qtype uint16) (*response, error) {
	id, err := newQueryID()
	if err != nil {
		return nil, err
	}
	query, err := buildQuery(id, host, qtype)
	if err != nil {
		return nil, err
	}

	var udpErr error
	msg, err := u.exchangeUDP(ctx, server, query, id)
	if err != nil {
		udpErr = err
	} else {
		needsStream, err := answerNeedsStream(msg, id)
		if err != nil {
			udpErr = err
		} else if !needsStream {
			return parseResponse(msg)
		}
	}

	msg, tcpErr := u.exchangeTCP(ctx, server, query, id)
	if tcpErr != nil {
		if udpErr != nil {
			return nil, fmt.Errorf("udp: %v; tcp: %w", udpErr, tcpErr)
		}
		return nil, fmt.Errorf("the datagram answer was truncated and tcp: %w", tcpErr)
	}
	return parseResponse(msg)
}

// answerNeedsStream reads the two header fields that decide whether a datagram
// answer can be used at all. It works on the header alone, because a truncated
// message may end in the middle of a record and would fail a parse for a reason
// that is not an error.
func answerNeedsStream(msg []byte, id uint16) (bool, error) {
	if len(msg) < headerLen {
		return false, fmt.Errorf("%w: the answer is shorter than a header", errMalformedMessage)
	}
	if binary.BigEndian.Uint16(msg[0:2]) != id {
		return false, fmt.Errorf("%w: the answer carries a different identifier", errMalformedMessage)
	}
	return binary.BigEndian.Uint16(msg[2:4])&flagTruncated != 0, nil
}

// exchangeUDP sends one question over a connected datagram socket and reads the
// first answer that carries the expected identifier.
func (u *Upstream) exchangeUDP(ctx context.Context, server string, query []byte, id uint16) ([]byte, error) {
	dialer := &net.Dialer{Timeout: u.timeout}
	conn, err := dialer.DialContext(ctx, "udp", server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(deadlineFor(ctx, u.timeout)); err != nil {
		return nil, err
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, maxUDPMessage)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		if n < headerLen {
			continue
		}
		if binary.BigEndian.Uint16(buf[0:2]) != id {
			// A stray or spoofed datagram on the socket; the deadline bounds
			// how long this can go on.
			continue
		}
		return append([]byte(nil), buf[:n]...), nil
	}
}

// exchangeTCP sends one question over a stream, length-prefixed as RFC 1035
// requires.
func (u *Upstream) exchangeTCP(ctx context.Context, server string, query []byte, id uint16) ([]byte, error) {
	dialer := &net.Dialer{Timeout: u.timeout}
	conn, err := dialer.DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(deadlineFor(ctx, u.timeout)); err != nil {
		return nil, err
	}
	message := make([]byte, 2, 2+len(query))
	binary.BigEndian.PutUint16(message, uint16(len(query)))
	message = append(message, query...)
	if _, err := conn.Write(message); err != nil {
		return nil, err
	}
	var length uint16
	if err := binary.Read(io.LimitReader(conn, 2), binary.BigEndian, &length); err != nil {
		return nil, err
	}
	if length < headerLen {
		return nil, fmt.Errorf("%w: the stream carries a %d byte message", errMalformedMessage, length)
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	if binary.BigEndian.Uint16(buf[0:2]) != id {
		return nil, fmt.Errorf("%w: the answer carries a different identifier", errMalformedMessage)
	}
	return buf, nil
}

// newQueryID picks an unpredictable identifier. A predictable one lets an
// off-path attacker answer before the real server does.
func newQueryID() (uint16, error) {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, fmt.Errorf("dns: no query identifier: %w", err)
	}
	return binary.BigEndian.Uint16(b[:]), nil
}

// deadlineFor bounds one attempt by the shorter of the configured timeout and
// the caller's deadline.
func deadlineFor(ctx context.Context, timeout time.Duration) time.Time {
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		return ctxDeadline
	}
	return deadline
}
