package inbound

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/melon-tgj/melonarc/internal/outbound"
	"github.com/melon-tgj/melonarc/internal/rules"
)

// TestHandlerReplaceSwapsTheConfiguration is the property a reload depends on:
// a listener that was started with one handler serves the next request with the
// rules and groups of the configuration installed afterwards.
func TestHandlerReplaceSwapsTheConfiguration(t *testing.T) {
	echo := startEcho(t)
	target := outbound.Target{Host: "127.0.0.1", Port: portOfAddress(t, echo)}
	env := newTestEnv(t, envOptions{
		rules: []string{"FINAL,alpha"},
		leaves: map[string]outbound.Dialer{
			"alpha": outbound.NewDirect(),
			"beta":  outbound.NewDirect(),
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), testDeadline)
	defer cancel()

	conn, sel, err := env.handler.Stream(ctx, Request{Target: target, Network: networkTCP})
	if err != nil {
		t.Fatalf("Stream before the replacement: %v", err)
	}
	conn.Close()
	if sel.Target != "alpha" {
		t.Fatalf("first request went to %q, want alpha", sel.Target)
	}

	if err := env.handler.Replace(HandlerOptions{
		Matcher: newTestProgram(t, "FINAL,beta"),
		Router:  env.router,
	}); err != nil {
		t.Fatalf("Replace: %v", err)
	}

	conn, sel, err = env.handler.Stream(ctx, Request{Target: target, Network: networkTCP})
	if err != nil {
		t.Fatalf("Stream after the replacement: %v", err)
	}
	conn.Close()
	if sel.Target != "beta" {
		t.Fatalf("second request went to %q, want beta", sel.Target)
	}

	// The explanation path reads the same state, so the API cannot describe the
	// configuration that is no longer in force.
	exp, err := env.handler.Explain(ctx, rules.Query{Name: "example.test"})
	if err != nil {
		t.Fatalf("Explain: %v", err)
	}
	if exp.Decision.Target != "beta" {
		t.Errorf("Explain routed to %q, want beta", exp.Decision.Target)
	}
}

func TestHandlerReplaceRejectsIncompleteOptions(t *testing.T) {
	env := newTestEnv(t, envOptions{
		rules:  []string{"FINAL,alpha"},
		leaves: map[string]outbound.Dialer{"alpha": outbound.NewDirect()},
	})
	if err := env.handler.Replace(HandlerOptions{Router: env.router}); err == nil {
		t.Error("Replace accepted a handler without a matcher")
	}
	if err := env.handler.Replace(HandlerOptions{Matcher: newTestProgram(t, "FINAL,alpha")}); err == nil {
		t.Error("Replace accepted a handler without a router")
	}
	// A rejected replacement leaves the previous configuration in place.
	echo := startEcho(t)
	conn, sel, err := env.handler.Stream(context.Background(), Request{
		Target:  outbound.Target{Host: "127.0.0.1", Port: portOfAddress(t, echo)},
		Network: networkTCP,
	})
	if err != nil {
		t.Fatalf("the handler stopped routing after a rejected replacement: %v", err)
	}
	conn.Close()
	if sel.Target != "alpha" {
		t.Errorf("request went to %q, want the program from before the replacement", sel.Target)
	}
}

// TestHandlerReplaceIsSafeWhileServing replaces the configuration while
// connections are being routed. It is the shape of a reload under load, and the
// race detector is the assertion.
func TestHandlerReplaceIsSafeWhileServing(t *testing.T) {
	echo := startEcho(t)
	target := outbound.Target{Host: "127.0.0.1", Port: portOfAddress(t, echo)}
	env := newTestEnv(t, envOptions{
		rules: []string{"FINAL,alpha"},
		leaves: map[string]outbound.Dialer{
			"alpha": outbound.NewDirect(),
			"beta":  outbound.NewDirect(),
		},
	})

	programs := []*rules.Program{
		newTestProgram(t, "FINAL,alpha"),
		newTestProgram(t, "FINAL,beta"),
	}

	ctx, cancel := context.WithTimeout(context.Background(), testDeadline)
	defer cancel()

	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if err := env.handler.Replace(HandlerOptions{Matcher: programs[i%len(programs)], Router: env.router}); err != nil {
				t.Errorf("Replace: %v", err)
				return
			}
		}
	}()

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				conn, sel, err := env.handler.Stream(ctx, Request{Target: target, Network: networkTCP})
				if err != nil {
					t.Errorf("Stream: %v", err)
					return
				}
				conn.Close()
				if sel.Target != "alpha" && sel.Target != "beta" {
					t.Errorf("request went to %q, want one of the two programs", sel.Target)
					return
				}
			}
		}()
	}

	// Let the routers finish before the replacement loop is stopped, so the
	// assertions above have all run.
	time.Sleep(10 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// portOfAddress returns the numeric port of a host:port address.
func portOfAddress(t *testing.T, address string) uint16 {
	t.Helper()
	target, err := outbound.ParseTarget(address)
	if err != nil {
		t.Fatalf("%q is not a target: %v", address, err)
	}
	return target.Port
}
