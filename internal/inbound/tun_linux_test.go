//go:build linux

package inbound

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/melon-tgj/melonarc/internal/outbound"
)

// loopbackDialer is the outbound of the real-device integration test. It
// reaches a local server instead of the TUN destination (dialling that address
// again would route straight back into the device), while still going through
// the real compiled rules and the real Handler pipeline. For datagrams it
// supplies an in-memory shared association, so the test can inject a reply
// without an unconnected UDP socket.
type loopbackDialer struct {
	target string

	mu      sync.Mutex
	streams []string
	shared  *memorySharedConn
}

func (d *loopbackDialer) DialContext(ctx context.Context, address string) (net.Conn, error) {
	d.mu.Lock()
	d.streams = append(d.streams, address)
	d.mu.Unlock()
	dialer := net.Dialer{Timeout: 5 * time.Second}
	return dialer.DialContext(ctx, "tcp", d.target)
}

func (d *loopbackDialer) DialPacket(context.Context, string) (outbound.PacketConn, error) {
	return nil, errors.New("loopbackDialer: the shared association should be used")
}

func (d *loopbackDialer) DialSharedUDP(context.Context) (outbound.SharedPacketConn, error) {
	conn := newMemorySharedConn()
	d.mu.Lock()
	d.shared = conn
	d.mu.Unlock()
	return conn, nil
}

func (d *loopbackDialer) current() *memorySharedConn {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.shared
}

func (d *loopbackDialer) dialed() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.streams...)
}

// loopbackProbe is inside 127.0.0.0/8. Some sandboxes refuse connect() to any
// other range, so the test routes this one address at the device instead of a
// documentation prefix. On an ordinary host any address routed at the device
// works; the rest of the test is identical.
const loopbackProbe = "127.0.0.9"

// localNetRequest is the RTM_NEWROUTE/RTM_DELROUTE message for the kernel's
// "local 127.0.0.0/8 dev lo" route. That route outranks the main table, so it
// has to be lifted for the duration of the test; it is restored by cleanup.
func localNetRequest(index int) []byte {
	payload := make([]byte, unix.SizeofRtMsg)
	msg := (*unix.RtMsg)(unsafe.Pointer(&payload[0]))
	msg.Family = unix.AF_INET
	msg.Dst_len = 8
	msg.Table = unix.RT_TABLE_LOCAL
	msg.Protocol = unix.RTPROT_KERNEL
	msg.Scope = unix.RT_SCOPE_HOST
	msg.Type = unix.RTN_LOCAL
	payload = appendAttr(payload, unix.RTA_DST, net.IPv4(127, 0, 0, 0).To4())
	var oif [4]byte
	binary.LittleEndian.PutUint32(oif[:], uint32(index))
	payload = appendAttr(payload, unix.RTA_OIF, oif[:])
	payload = appendAttr(payload, unix.RTA_PREFSRC, net.IPv4(127, 0, 0, 1).To4())
	return payload
}

// liftLocalNet removes the broad loopback local route and returns a function
// that puts it back. A missing route is fine: a fresh network namespace starts
// with lo down, so there may be nothing to remove.
func liftLocalNet(t *testing.T, index int) func() {
	t.Helper()
	payload := localNetRequest(index)
	err := nlRequest(unix.RTM_DELROUTE, unix.NLM_F_REQUEST|unix.NLM_F_ACK, payload)
	if err != nil && !errors.Is(err, unix.ESRCH) {
		t.Fatalf("remove the loopback local route: %v", err)
	}
	return func() {
		if err := nlRequest(unix.RTM_NEWROUTE,
			unix.NLM_F_REQUEST|unix.NLM_F_ACK|unix.NLM_F_CREATE, payload); err != nil {
			t.Errorf("restore the loopback local route: %v", err)
		}
	}
}

// permitLocalNet lets the kernel accept packets whose addresses are in
// 127.0.0.0/8 on the device. Without it a reply from the probe address is
// dropped as a martian. These are namespaced sysctls, so a private namespace
// keeps the change local to this process.
func permitLocalNet(t *testing.T, name string) {
	t.Helper()
	for _, setting := range []struct{ path, value string }{
		{"net/ipv4/conf/" + name + "/route_localnet", "1"},
		{"net/ipv4/conf/" + name + "/rp_filter", "0"},
		{"net/ipv4/conf/all/rp_filter", "0"},
	} {
		if err := os.WriteFile(filepath.Join("/proc/sys", setting.path), []byte(setting.value), 0); err != nil {
			t.Logf("sysctl %s = %s failed: %v", setting.path, setting.value, err)
		}
	}
}

// loopbackLogger is quiet unless the operator asks for the packet-level trace.
func loopbackLogger() *slog.Logger {
	if os.Getenv("MELONARC_TUN_DEBUG") != "1" {
		return testLogger()
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// TestTUNLinuxLoopback is the privileged end-to-end test: a real /dev/net/tun
// device, a real kernel TCP client and a real connected UDP socket. It is only
// run when explicitly asked for, because creating a device needs CAP_NET_ADMIN
// and the test temporarily lifts the loopback local route.
//
// On a normal Linux host, as root:
//
//	go test -c -o /tmp/inbound.test ./internal/inbound
//	MELONARC_TUN_LOOPBACK=1 /tmp/inbound.test -test.run TestTUNLinuxLoopback -test.v
//
// In a container that keeps /dev/net/tun but dropped the capability from the
// bounding set, a user plus network namespace hands it back:
//
//	unshare -Urn env MELONARC_TUN_LOOPBACK=1 /tmp/inbound.test -test.run TestTUNLinuxLoopback -test.v
//
// Add MELONARC_TUN_DEBUG=1 to the environment for a packet-level trace.
//
// Run it in a private network namespace: lifting the 127.0.0.0/8 local route
// changes host routing while the test is in flight. The route is restored by
// cleanup and the device is closed, but a fresh namespace is the safe place.
func TestTUNLinuxLoopback(t *testing.T) {
	if os.Getenv("MELONARC_TUN_LOOPBACK") != "1" {
		t.Skip("set MELONARC_TUN_LOOPBACK=1 and run inside unshare -Urn (or as root) to create a real TUN device")
	}

	// A fresh network namespace starts with lo down, so 127.0.0.1 has no local
	// route. Bringing it up is a test setup step, not something the product
	// code does to a running host.
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatalf("look up lo: %v", err)
	}
	if err := setLinkUp(lo.Index, 1500); err != nil {
		t.Fatalf("bring up lo: %v", err)
	}
	const deviceName = "melonarc0"
	t.Cleanup(liftLocalNet(t, lo.Index))

	const body = "ping\n"
	origin := startTCPServer(t, func(conn net.Conn) {
		line, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			return
		}
		_, _ = conn.Write([]byte("origin:" + line))
	})
	_, portText, err := net.SplitHostPort(origin)
	if err != nil {
		t.Fatalf("split %q: %v", origin, err)
	}

	dialer := &loopbackDialer{target: origin}
	env := newTestEnv(t, envOptions{
		rules:  []string{"FINAL,DIRECT"},
		leaves: map[string]outbound.Dialer{"DIRECT": dialer},
	})
	svc, err := NewTUN(TUNOptions{
		Name:    deviceName,
		Address: "198.18.0.1/24",
		MTU:     1500,
		Routes:  []string{loopbackProbe + "/32"},
		Handler: env.handler,
		Logger:  loopbackLogger(),
	})
	if err != nil {
		t.Fatalf("NewTUN: %v (CAP_NET_ADMIN is required; try unshare -Urn)", err)
	}
	// The per-device sysctl files only exist once the device exists.
	permitLocalNet(t, deviceName)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), testDeadline)
		defer cancel()
		if err := svc.Close(ctx); err != nil {
			t.Errorf("TUNService.Close: %v", err)
		}
	})

	// TCP: the kernel routes the SYN into the device, the userspace stack
	// completes the handshake and the rule pipeline carries the request to the
	// local origin. The reply is injected back into the device.
	destination := net.JoinHostPort(loopbackProbe, portText)
	stream, err := net.DialTimeout("tcp", destination, 5*time.Second)
	if err != nil {
		t.Fatalf("dial %s through the TUN device: %v", destination, err)
	}
	defer stream.Close()
	if err := stream.SetDeadline(time.Now().Add(testDeadline)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := stream.Write([]byte(body)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	reply, err := bufio.NewReader(stream).ReadString('\n')
	if err != nil {
		t.Fatalf("read response through the TUN device: %v", err)
	}
	if reply != "origin:"+body {
		t.Fatalf("response = %q, want %q", reply, "origin:"+body)
	}

	// UDP: a connected socket sends one datagram into the device. The session
	// table routes it through the pipeline, and a reply from the shared
	// association is written back as an IP packet the kernel delivers to the
	// socket.
	client, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.ParseIP(loopbackProbe).To4(), Port: 5300})
	if err != nil {
		t.Fatalf("dial udp through the TUN device: %v", err)
	}
	defer client.Close()
	if err := client.SetDeadline(time.Now().Add(testDeadline)); err != nil {
		t.Fatalf("set udp deadline: %v", err)
	}
	if _, err := client.Write([]byte("datagram")); err != nil {
		t.Fatalf("write udp datagram: %v", err)
	}
	var shared *memorySharedConn
	waitUntil(t, "the UDP session", func() bool {
		shared = dialer.current()
		return shared != nil && len(shared.written()) > 0
	})
	if got := shared.written()[0]; got.payload != "datagram" {
		t.Fatalf("UDP payload reaching the pipeline = %q", got.payload)
	}
	shared.respond(outbound.Target{Host: loopbackProbe, Port: 5300}, "reply")
	buf := make([]byte, 64)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("read udp reply through the TUN device: %v", err)
	}
	if string(buf[:n]) != "reply" {
		t.Fatalf("udp reply = %q, want reply", buf[:n])
	}

	// The pipeline saw the destination the kernel was trying to reach.
	found := false
	for _, address := range dialer.dialed() {
		if address == destination {
			found = true
		}
	}
	if !found {
		t.Fatalf("the rule pipeline never saw %s: %v", destination, dialer.dialed())
	}
}
