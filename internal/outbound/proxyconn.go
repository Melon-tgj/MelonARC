package outbound

import (
	"context"
	"fmt"
	"net"
	"time"
)

// dialProxyHop connects to a proxy endpoint and optionally secures the hop
// with the shared TLS base. Every tunnelling protocol that runs over a TCP hop
// uses it, so deadlines, cancellation and TLS are applied in exactly one place.
func dialProxyHop(ctx context.Context, server, host string, timeout time.Duration, tlsOpts TLSOptions) (net.Conn, error) {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", server, err)
	}
	setConnDeadline(conn, ctx, timeout)
	if !tlsOpts.Enabled {
		return conn, nil
	}
	secured, err := tlsOpts.Wrap(ctx, conn, host)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return secured, nil
}

// completeHandshake runs a protocol handshake under a cancellation guard and
// clears the handshake deadline when it succeeds. The returned connection is
// ready for the caller's unbounded relay.
func completeHandshake(ctx context.Context, conn net.Conn, fn func(net.Conn) (net.Conn, error)) (net.Conn, error) {
	release := guardConn(ctx, conn)
	stream, err := fn(conn)
	if err != nil {
		release()
		_ = conn.Close()
		return nil, err
	}
	if !release() {
		_ = conn.Close()
		return nil, ctx.Err()
	}
	_ = conn.SetDeadline(time.Time{})
	return stream, nil
}
