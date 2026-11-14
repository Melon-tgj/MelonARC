package outbound

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestTLSOptionsFor(t *testing.T) {
	base := TLSOptions{ServerName: "proxy.example", SkipVerify: true, ALPN: []string{"h2", "http/1.1"}}
	cfg := base.For("127.0.0.1")
	if cfg.ServerName != "proxy.example" {
		t.Fatalf("server name = %q, want the override", cfg.ServerName)
	}
	if !cfg.InsecureSkipVerify {
		t.Fatal("skip-cert-verify was not applied")
	}
	if len(cfg.NextProtos) != 2 || cfg.NextProtos[0] != "h2" {
		t.Fatalf("alpn = %v", cfg.NextProtos)
	}
	if cfg.MinVersion < tls.VersionTLS12 {
		t.Fatal("TLS 1.2 is not the minimum")
	}
	plain := TLSOptions{}.For("127.0.0.1")
	if plain.ServerName != "127.0.0.1" || plain.InsecureSkipVerify {
		t.Fatalf("default config = %+v", plain)
	}
	// A test-supplied config supplies trust roots but does not discard the
	// shared server name, verification switch or ALPN list.
	roots := x509.NewCertPool()
	withRoots := TLSOptions{
		ServerName: "other.example", SkipVerify: true, ALPN: []string{"h2"},
		Config: &tls.Config{RootCAs: roots},
	}.For("127.0.0.1")
	if withRoots.RootCAs != roots || withRoots.ServerName != "other.example" ||
		!withRoots.InsecureSkipVerify || len(withRoots.NextProtos) != 1 {
		t.Fatal("the test config overrode the shared TLS options")
	}
}

func TestTLSOptionsWrapDisabledIsIdentity(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	got, err := (TLSOptions{}).Wrap(context.Background(), left, "example.com")
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if got != left {
		t.Fatal("a disabled TLS base replaced the connection")
	}
}

func TestValidateTLSOptions(t *testing.T) {
	tests := []struct {
		name string
		typ  string
		args []string
		want string
	}{
		{name: "plaintext rejects sni", typ: "socks5",
			args: []string{"p", "1080", "sni=proxy.example"}, want: "not accepted by proxy type"},
		{name: "encrypted plaintext type rejects alpn", typ: "ss",
			args: []string{"p", "8388", "aes-128-gcm", "secret", "alpn=h2"}, want: "not accepted by proxy type"},
		{name: "tls always type rejects toggle", typ: "https",
			args: []string{"p", "443", "tls=true"}, want: "tls= is not accepted"},
		{name: "trojan rejects toggle", typ: "trojan",
			args: []string{"p", "443", "tls=false"}, want: "tls= is not accepted"},
		{name: "bad toggle", typ: "vmess",
			args: []string{"p", "443", "tls=maybe"}, want: "neither true nor false"},
		{name: "duplicate option", typ: "vmess",
			args: []string{"p", "443", "sni=a.example", "sni=b.example"}, want: "given twice"},
		{name: "bad sni", typ: "trojan",
			args: []string{"p", "443", "sni=..bad"}, want: "empty label"},
		{name: "empty alpn", typ: "trojan",
			args: []string{"p", "443", "alpn=|"}, want: "empty entry"},
		{name: "positional args are ignored", typ: "http",
			args: []string{"p", "3128", "username=a", "password=b"}},
		{name: "vmess toggle works", typ: "vmess",
			args: []string{"p", "443", "tls=true", "sni=proxy.example", "skip-cert-verify=yes", "alpn=h2|http/1.1"}},
		{name: "trojan options work", typ: "trojan",
			args: []string{"p", "443", "password=secret", "sni=proxy.example", "alpn=h2"}},
		{name: "socks5-tls options work", typ: "socks5-tls",
			args: []string{"p", "443", "sni=proxy.example", "skip-cert-verify=0"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateTLSOptions(tc.typ, tc.args)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("ValidateTLSOptions: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestParseTLSOptionsModes(t *testing.T) {
	always, err := parseTLSOptions(map[string]string{optSNI: "a.example"}, tlsAlways)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !always.Enabled || always.ServerName != "a.example" {
		t.Fatalf("always = %+v", always)
	}
	optional, err := parseTLSOptions(map[string]string{optTLS: "true"}, tlsOptional)
	if err != nil || !optional.Enabled {
		t.Fatalf("optional = %+v, %v", optional, err)
	}
	if _, err := parseTLSOptions(map[string]string{optTLS: "true"}, tlsAlways); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("tls= on an always type = %v", err)
	}
}

// startTestSOCKS5TLS wraps the loopback SOCKS5 test server in TLS, which is
// the phase 2 leftover variant completed in phase 9.
func startTestSOCKS5TLS(t *testing.T, username, password string) (*testSOCKS5, *x509.CertPool) {
	t.Helper()
	cert, pool := testCertificate(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("listen tls: %v", err)
	}
	s := &testSOCKS5{addr: ln.Addr().String(), username: username, password: password}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handle(conn)
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	})
	return s, pool
}

func TestSOCKS5TLSRoundTrip(t *testing.T) {
	echo := startTCPEcho(t)
	server, pool := startTestSOCKS5TLS(t, "alice", "secret")
	target, err := ParseTarget(server.addr)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	d, err := NewSOCKS5(SOCKS5Options{
		Server: target.Host, Port: int(target.Port),
		Username: "alice", Password: "secret",
		TLS:     TLSOptions{Enabled: true, Config: &tls.Config{RootCAs: pool}},
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewSOCKS5: %v", err)
	}
	conn := dialThrough(t, d, echo)
	payload := []byte("socks5 over tls")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo = %q", got)
	}
	requests := server.Requests()
	if len(requests) != 1 || requests[0].Command != cmdConnect {
		t.Fatalf("server requests = %+v", requests)
	}
	if user, pass := server.Credentials(); user != "alice" || pass != "secret" {
		t.Fatalf("credentials = %q/%q", user, pass)
	}
}

func TestHTTPSReusesTLSBase(t *testing.T) {
	echo := startTCPEcho(t)
	server, pool := startTestHTTPSProxy(t, "", "")
	target, err := ParseTarget(server.addr)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	d, err := NewHTTPProxy(HTTPProxyOptions{
		Server: target.Host, Port: int(target.Port), TLS: true,
		TLSBase: TLSOptions{Config: &tls.Config{RootCAs: pool}, ALPN: []string{"http/1.1"}},
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewHTTPProxy: %v", err)
	}
	conn := dialThrough(t, d, echo)
	payload := []byte("https connect through the shared tls base")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo = %q", got)
	}
}

func TestNewFromSpecSetsTLSMode(t *testing.T) {
	tests := []struct {
		typ     string
		args    []string
		enabled bool
		sni     string
	}{
		{typ: "socks5-tls", args: []string{"p", "443", "sni=a.example"}, enabled: true, sni: "a.example"},
		{typ: "https", args: []string{"p", "443", "skip-cert-verify=true"}, enabled: true},
		{typ: "trojan", args: []string{"p", "443", "password=x", "sni=b.example"}, enabled: true, sni: "b.example"},
		{typ: "vmess", args: []string{"p", "443", "uuid=" + testVMessUUID, "tls=true", "sni=c.example"}, enabled: true, sni: "c.example"},
		{typ: "vmess", args: []string{"p", "443", "uuid=" + testVMessUUID}, enabled: false},
	}
	for _, tc := range tests {
		t.Run(tc.typ+"/"+strings.Join(tc.args[2:], ","), func(t *testing.T) {
			d, err := New(Spec{Type: tc.typ, Server: "p", Port: 443, Args: tc.args})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			var got TLSOptions
			switch v := d.(type) {
			case *SOCKS5:
				got = v.tls
			case *HTTPProxy:
				got = v.tlsOptions
			case *Trojan:
				got = v.tls
			case *VMess:
				got = v.tls
			default:
				t.Fatalf("New returned %T", d)
			}
			if got.Enabled != tc.enabled || got.ServerName != tc.sni {
				t.Fatalf("TLS = %+v, want enabled=%v sni=%q", got, tc.enabled, tc.sni)
			}
		})
	}
}
