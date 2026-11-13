package outbound

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestNewSOCKS5FromSpec(t *testing.T) {
	dialer, err := New(Spec{
		Name:   "office",
		Type:   "socks5",
		Server: "127.0.0.1",
		Port:   1080,
		Args:   []string{"127.0.0.1", "1080", "username=alice", "password=p=a=s=s"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	socks, ok := dialer.(*SOCKS5)
	if !ok {
		t.Fatalf("New returned %T, want *SOCKS5", dialer)
	}
	if socks.server != "127.0.0.1:1080" {
		t.Fatalf("server = %q, want 127.0.0.1:1080", socks.server)
	}
	if socks.auth == nil || socks.auth.username != "alice" || socks.auth.password != "p=a=s=s" {
		// The tail is split at the first "=" on purpose: a password may itself
		// contain one.
		t.Fatalf("auth = %+v, want alice with password p=a=s=s", socks.auth)
	}
	if socks.timeout != DefaultTimeout {
		t.Fatalf("timeout = %v, want %v", socks.timeout, DefaultTimeout)
	}
}

func TestNewSOCKS5WithoutCredentials(t *testing.T) {
	dialer, err := New(Spec{Type: "socks5", Server: "proxy.example", Port: 1080, Args: []string{"proxy.example", "1080"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if socks := dialer.(*SOCKS5); socks.auth != nil {
		t.Fatalf("auth = %+v, want none", socks.auth)
	}
}

func TestNewHTTPVariant(t *testing.T) {
	tests := []struct {
		typ     string
		wantTLS bool
	}{
		{typ: "http", wantTLS: false},
		{typ: "https", wantTLS: true},
		{typ: "HTTPS", wantTLS: true},
	}
	for _, tc := range tests {
		t.Run(tc.typ, func(t *testing.T) {
			dialer, err := New(Spec{
				Type:   tc.typ,
				Server: "proxy.example",
				Port:   3128,
				Args:   []string{"proxy.example", "3128", "username=alice", "password=secret"},
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			proxy, ok := dialer.(*HTTPProxy)
			if !ok {
				t.Fatalf("New returned %T, want *HTTPProxy", dialer)
			}
			if proxy.useTLS != tc.wantTLS {
				t.Fatalf("useTLS = %v, want %v", proxy.useTLS, tc.wantTLS)
			}
			if proxy.auth == nil || proxy.auth.header() != "Basic YWxpY2U6c2VjcmV0" {
				t.Fatalf("auth header = %v, want the basic header for alice:secret", proxy.auth)
			}
		})
	}
}

func TestNewLeavesLaterProtocolsUnsupported(t *testing.T) {
	dialer, err := New(Spec{
		Name:   "future",
		Type:   "vmess",
		Server: "proxy.example",
		Port:   443,
		// Options of a protocol this build does not implement are not parsed,
		// so unknown keys must not fail the whole configuration.
		Args: []string{"proxy.example", "443", "cipher=whatever"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	unsupported, ok := dialer.(*Unsupported)
	if !ok {
		t.Fatalf("New returned %T, want *Unsupported", dialer)
	}
	if unsupported.Protocol != "vmess" {
		t.Fatalf("Protocol = %q, want vmess", unsupported.Protocol)
	}
}

func TestNewRejectsInvalidOptions(t *testing.T) {
	tests := []struct {
		name string
		spec Spec
	}{
		{
			name: "unknown option",
			spec: Spec{Type: "socks5", Server: "p", Port: 1080, Args: []string{"p", "1080", "tls=true"}},
		},
		{
			name: "duplicate option",
			spec: Spec{Type: "socks5", Server: "p", Port: 1080,
				Args: []string{"p", "1080", "username=a", "username=b", "password=c"}},
		},
		{
			name: "option without a value",
			spec: Spec{Type: "http", Server: "p", Port: 3128, Args: []string{"p", "3128", "username"}},
		},
		{
			name: "username without password",
			spec: Spec{Type: "socks5", Server: "p", Port: 1080, Args: []string{"p", "1080", "username=a"}},
		},
		{
			name: "password without username",
			spec: Spec{Type: "http", Server: "p", Port: 3128, Args: []string{"p", "3128", "password=a"}},
		},
		{
			name: "empty username",
			spec: Spec{Type: "socks5", Server: "p", Port: 1080, Args: []string{"p", "1080", "username=", "password=a"}},
		},
		{
			name: "credential too long",
			spec: Spec{Type: "socks5", Server: "p", Port: 1080,
				Args: []string{"p", "1080", "username=" + strings.Repeat("u", 256), "password=a"}},
		},
		{
			name: "no server",
			spec: Spec{Type: "socks5", Port: 1080},
		},
		{
			name: "port out of range",
			spec: Spec{Type: "http", Server: "p", Port: 70000},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.spec); err == nil {
				t.Fatal("New accepted an invalid spec")
			} else if !errors.Is(err, ErrInvalidOption) && !strings.Contains(err.Error(), "outbound:") {
				t.Fatalf("error = %v, want a configuration error", err)
			}
		})
	}
}

func TestNewWrapsTheProxyName(t *testing.T) {
	_, err := New(Spec{Name: "office", Type: "socks5", Server: "p", Port: 1080, Args: []string{"p", "1080", "bogus=1"}})
	if err == nil {
		t.Fatal("New accepted an unknown option")
	}
	if !strings.Contains(err.Error(), `proxy "office"`) {
		t.Fatalf("error = %v, want it to name the proxy", err)
	}
}

func TestParseOptionsSplitsAtTheFirstEquals(t *testing.T) {
	opts, err := parseOptions([]string{"host", "80", "password=a=b=c"}, authOptionKeys)
	if err != nil {
		t.Fatalf("parseOptions: %v", err)
	}
	if opts[optPassword] != "a=b=c" {
		t.Fatalf("password = %q, want a=b=c", opts[optPassword])
	}
	empty, err := parseOptions([]string{"host", "80"}, authOptionKeys)
	if err != nil {
		t.Fatalf("parseOptions: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("opts = %v, want none", empty)
	}
}

func TestTimeoutIsConfigurable(t *testing.T) {
	dialer, err := NewSOCKS5(SOCKS5Options{Server: "p", Port: 1080, Timeout: 250 * time.Millisecond})
	if err != nil {
		t.Fatalf("NewSOCKS5: %v", err)
	}
	if dialer.timeout != 250*time.Millisecond {
		t.Fatalf("timeout = %v, want 250ms", dialer.timeout)
	}
	if _, err := NewSOCKS5(SOCKS5Options{Server: "p", Port: 1080, Username: "a"}); err == nil {
		t.Fatal("NewSOCKS5 accepted half a credential pair")
	}
	if _, err := NewHTTPProxy(HTTPProxyOptions{Server: "p", Port: 3128, Password: "a"}); err == nil {
		t.Fatal("NewHTTPProxy accepted half a credential pair")
	}
}
