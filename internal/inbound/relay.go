package inbound

import (
	"io"
	"net"
	"sync"
)

// relay copies bytes in both directions between a client and its upstream until
// both directions have ended.
//
// An end of stream is propagated as a half close rather than a teardown: a
// client that has sent its request shuts down its write side and still expects
// the response, and an upstream that has answered shuts down its side while the
// client may still be sending. Only a real error tears the pair down, because a
// byte stream has no way to signal one.
func relay(client, upstream net.Conn) {
	abort := func() {
		_ = client.Close()
		_ = upstream.Close()
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		copyDirection(upstream, client, abort)
	}()
	go func() {
		defer wg.Done()
		copyDirection(client, upstream, abort)
	}()
	wg.Wait()
}

// copyDirection moves bytes from src to dst. When src ends normally the write
// side of dst is closed and the other direction keeps running.
func copyDirection(dst, src net.Conn, abort func()) {
	if _, err := io.Copy(dst, src); err != nil {
		abort()
		return
	}
	closeWrite(dst)
}

// closeWrite ends the write direction of c and leaves reads open. A connection
// that cannot express a half close is closed instead, which is the closest
// approximation available: the peer sees the end of the stream either way.
func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}
