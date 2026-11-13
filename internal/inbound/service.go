package inbound

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"runtime/debug"
	"sync"
	"time"
)

// Accept backoff bounds. A listener that fails to accept keeps retrying, but
// with a growing pause so a broken socket does not spin a core.
const (
	minAcceptBackoff = 5 * time.Millisecond
	maxAcceptBackoff = time.Second
)

// Service is one bound inbound listener: it accepts connections and hands each
// to a protocol handler until it is closed. A constructor binds the listener
// and starts accepting, so a Service that exists is a Service that serves.
type Service struct {
	protocol string
	logger   *slog.Logger
	listener net.Listener
	handle   func(context.Context, net.Conn)
	metrics  *Metrics

	ctx    context.Context
	cancel context.CancelFunc

	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool

	wg         sync.WaitGroup
	acceptDone chan struct{}
	closeOnce  sync.Once
	closeErr   error
}

// newService wraps a bound listener and starts the accept loop.
func newService(protocol string, listener net.Listener, handle func(context.Context, net.Conn), metrics *Metrics, logger *slog.Logger) *Service {
	ctx, cancel := context.WithCancel(context.Background())
	s := &Service{
		protocol:   protocol,
		logger:     loggerOrDiscard(logger),
		listener:   listener,
		handle:     handle,
		metrics:    metrics,
		ctx:        ctx,
		cancel:     cancel,
		conns:      make(map[net.Conn]struct{}),
		acceptDone: make(chan struct{}),
	}
	s.metrics.listen(protocol)
	s.wg.Add(1)
	go s.accept()
	return s
}

// Protocol names the listener, "http" or "socks5".
func (s *Service) Protocol() string { return s.protocol }

// Addr is the address the listener is bound to, with the real port when the
// requested one was 0.
func (s *Service) Addr() string { return s.listener.Addr().String() }

// accept takes connections until the listener is closed.
func (s *Service) accept() {
	defer s.wg.Done()
	defer close(s.acceptDone)
	backoff := time.Duration(0)
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if s.isClosed() || errors.Is(err, net.ErrClosed) {
				return
			}
			backoff = nextBackoff(backoff)
			s.logger.Warn("inbound accept failed", "protocol", s.protocol, "error", err, "retry_in", backoff)
			select {
			case <-time.After(backoff):
			case <-s.ctx.Done():
				return
			}
			continue
		}
		backoff = 0
		if !s.track(conn) {
			_ = conn.Close()
			return
		}
		go s.serve(conn)
	}
}

// serve runs one connection's handler and releases it afterwards.
//
// A panicking handler takes its connection down, not the daemon: a protocol bug
// on one client must not stop the listener for every other client. The deferred
// statements run on that path too, so the connection counter comes back down
// whether the handler returned, failed or panicked.
func (s *Service) serve(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()
	defer s.untrack(conn)
	defer func() {
		if p := recover(); p != nil {
			s.logger.Error("inbound handler panicked",
				"protocol", s.protocol, "panic", p, "stack", string(debug.Stack()))
		}
	}()
	s.handle(s.ctx, conn)
}

// track registers a connection together with the handler that will serve it.
//
// The wait group is incremented under the same lock Close uses to freeze the
// set, so no handler can start after Close has snapshotted the connections and
// the wait that follows cannot miss one.
func (s *Service) track(conn net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.conns[conn] = struct{}{}
	s.wg.Add(1)
	s.metrics.connectionOpened(s.protocol)
	return true
}

// untrack forgets a connection whose handler has returned.
func (s *Service) untrack(conn net.Conn) {
	s.mu.Lock()
	delete(s.conns, conn)
	s.mu.Unlock()
	s.metrics.connectionClosed(s.protocol)
}

// isClosed reports whether Close has begun.
func (s *Service) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// Close stops accepting, closes the connections still in flight and waits for
// their handlers to return. The wait is bounded by ctx.
//
// In-flight connections are closed rather than drained: a byte stream has
// nothing to flush, and a client that holds a tunnel open would otherwise keep
// the process alive until the timeout. A second call returns the result of the
// first.
func (s *Service) Close(ctx context.Context) error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		conns := make([]net.Conn, 0, len(s.conns))
		for c := range s.conns {
			conns = append(conns, c)
		}
		s.mu.Unlock()

		// Cancelling aborts dials that are still in progress.
		s.cancel()
		if err := s.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			s.closeErr = err
		}
		<-s.acceptDone
		for _, c := range conns {
			_ = c.Close()
		}

		done := make(chan struct{})
		go func() {
			s.wg.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-ctx.Done():
			if s.closeErr == nil {
				s.closeErr = ctx.Err()
			}
		}
	})
	return s.closeErr
}

// nextBackoff doubles the pause between failed accepts up to the maximum.
func nextBackoff(current time.Duration) time.Duration {
	switch {
	case current == 0:
		return minAcceptBackoff
	case current >= maxAcceptBackoff:
		return maxAcceptBackoff
	default:
		return current * 2
	}
}

// loggerOrDiscard returns a logger that swallows everything when l is nil, so
// the callers never have to test for one.
func loggerOrDiscard(l *slog.Logger) *slog.Logger {
	if l != nil {
		return l
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
