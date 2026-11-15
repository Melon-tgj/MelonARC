package share_test

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/melon-tgj/melonarc/internal/config"
	"github.com/melon-tgj/melonarc/internal/outbound"
	"github.com/melon-tgj/melonarc/internal/share"
)

const testUUID = "2dd61f16-2f34-4b9e-9d5e-0d3a1b4c5d6e"

// testRealityKey is a real 32-byte X25519 public key in the spelling a link
// uses; the dialer rejects anything that is not a key of that size.
var testRealityKey = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x2a}, 32))

// buildEncoder keeps the fixtures readable: links are mostly base64, and
// writing the encoding in the test means a typo shows up as a failing
// expectation rather than as a mysterious string.
func encode(text string) string { return base64.StdEncoding.EncodeToString([]byte(text)) }

func b64url(text string) string { return base64.RawURLEncoding.EncodeToString([]byte(text)) }

// TestParseBuildsEveryLink is the contract that matters: every link that parses
// must also produce a dialer. Parsing is where a provider's spelling is turned
// into our option syntax, so a link that parses but cannot be built would be a
// silent import of a node that never connects.
func TestParseBuildsEveryLink(t *testing.T) {
	cases := []struct {
		name string
		link string
		typ  string
		host string
		port int
		node string
		args map[string]string
	}{
		{
			name: "ss sip002 with encoded userinfo",
			link: "ss://" + b64url("aes-256-gcm:secret") + "@example.com:8388#Node%20A",
			typ:  "ss", host: "example.com", port: 8388, node: "Node A",
			args: map[string]string{"method": "aes-256-gcm", "password": "secret"},
		},
		{
			name: "ss sip002 with plain userinfo",
			link: "ss://chacha20-ietf-poly1305:p%40ss@example.com:8388#Node",
			typ:  "ss", host: "example.com", port: 8388, node: "Node",
			args: map[string]string{"method": "chacha20-ietf-poly1305", "password": "p@ss"},
		},
		{
			name: "ss legacy whole body",
			link: "ss://" + encode("aes-256-gcm:another-secret@example.com:8443") + "#Legacy",
			typ:  "ss", host: "example.com", port: 8443, node: "Legacy",
			args: map[string]string{"method": "aes-256-gcm", "password": "another-secret"},
		},
		{
			name: "ss ipv6",
			link: "ss://" + b64url("aes-128-gcm:pw") + "@[2001:db8::1]:8388#v6",
			typ:  "ss", host: "2001:db8::1", port: 8388, node: "v6",
			args: map[string]string{"method": "aes-128-gcm"},
		},
		{
			name: "vmess tcp tls",
			link: "vmess://" + encode(fmt.Sprintf(
				`{"v":"2","ps":"Tokyo","add":"vm.example.com","port":"443","id":%q,"aid":"0","scy":"auto","net":"tcp","type":"none","tls":"tls","sni":"vm.example.com"}`,
				testUUID)),
			typ: "vmess", host: "vm.example.com", port: 443, node: "Tokyo",
			args: map[string]string{"uuid": testUUID, "tls": "true", "sni": "vm.example.com", "security": "auto"},
		},
		{
			name: "vmess numeric port and alterid",
			link: "vmess://" + encode(fmt.Sprintf(
				`{"v":"2","ps":"Num","add":"vm.example.com","port":8080,"id":%q,"aid":64,"net":"tcp"}`,
				testUUID)),
			typ: "vmess", host: "vm.example.com", port: 8080, node: "Num",
			args: map[string]string{"alterid": "64"},
		},
		{
			name: "vless tls",
			link: "vless://" + testUUID + "@vl.example.com:443?encryption=none&security=tls&sni=front.example.com&type=tcp&alpn=h2,http/1.1#VL",
			typ:  "vless", host: "vl.example.com", port: 443, node: "VL",
			args: map[string]string{"tls": "true", "sni": "front.example.com", "alpn": "h2|http/1.1"},
		},
		{
			name: "vless reality",
			link: "vless://" + testUUID + "@vl.example.com:443?security=reality&pbk=" + testRealityKey + "&sid=ab12&sni=www.example.com&type=tcp#Reality",
			typ:  "vless", host: "vl.example.com", port: 443, node: "Reality",
			args: map[string]string{"reality": testRealityKey, "short-id": "ab12", "sni": "www.example.com"},
		},
		{
			name: "trojan with insecure",
			link: "trojan://secret@tr.example.com:443?sni=tr.example.com&allowInsecure=1#TR",
			typ:  "trojan", host: "tr.example.com", port: 443, node: "TR",
			args: map[string]string{"password": "secret", "sni": "tr.example.com", "skip-cert-verify": "true"},
		},
		{
			name: "hysteria2 with salamander",
			link: "hysteria2://auth@hy.example.com:443?insecure=1&obfs=salamander&obfs-password=obfssecret&sni=hy.example.com#HY",
			typ:  "hysteria2", host: "hy.example.com", port: 443, node: "HY",
			args: map[string]string{"password": "auth", "obfs": "salamander", "obfs-password": "obfssecret", "skip-cert-verify": "true"},
		},
		{
			name: "hysteria2 short scheme and user:password auth",
			link: "hy2://user:pass@hy.example.com:8443#HY2",
			typ:  "hysteria2", host: "hy.example.com", port: 8443, node: "HY2",
			args: map[string]string{"password": "user:pass"},
		},
		{
			name: "tuic v5",
			link: "tuic://" + testUUID + ":secret@tu.example.com:443?sni=tu.example.com&alpn=h3&congestion_control=bbr&udp_relay_mode=native#TU",
			typ:  "tuic", host: "tu.example.com", port: 443, node: "TU",
			args: map[string]string{"uuid": testUUID, "password": "secret", "sni": "tu.example.com", "alpn": "h3"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			proxy, err := share.Parse(tc.link)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if proxy.Type != tc.typ {
				t.Fatalf("type = %q, want %q", proxy.Type, tc.typ)
			}
			if proxy.Server != tc.host || proxy.Port != tc.port {
				t.Fatalf("address = %s:%d, want %s:%d", proxy.Server, proxy.Port, tc.host, tc.port)
			}
			if proxy.Name != tc.node {
				t.Fatalf("name = %q, want %q", proxy.Name, tc.node)
			}
			for key, want := range tc.args {
				if got := argValue(proxy.Args, key); got != want {
					t.Fatalf("argument %q = %q, want %q (args %v)", key, got, want, proxy.Args)
				}
			}
			// The parsed entry must be buildable through the same registry the
			// daemon uses.
			if _, err := outbound.New(specOf(proxy)); err != nil {
				t.Fatalf("build %s dialer: %v (args %v)", proxy.Type, err, proxy.Args)
			}
		})
	}
}

// argValue reads one key=value argument, the shape every option uses.
func argValue(args []string, key string) string {
	for _, arg := range args {
		if got, want, ok := strings.Cut(arg, "="); ok && got == key {
			return want
		}
	}
	return ""
}

func specOf(proxy config.Proxy) outbound.Spec {
	return outbound.Spec{
		Name: proxy.Name, Type: proxy.Type,
		Server: proxy.Server, Port: proxy.Port, Args: proxy.Args,
	}
}

// TestParseRejectsWithTheTypeAndReason covers the other half of the contract: a
// link that cannot be imported completely is reported, never silently skipped.
func TestParseRejectsWithTheTypeAndReason(t *testing.T) {
	cases := []struct {
		name   string
		link   string
		scheme string
		reason string
	}{
		{"ss plugin", "ss://" + b64url("aes-128-gcm:pw") + "@h.example.com:1/?plugin=obfs-local#x", "ss", "plugin"},
		{"ss without method", "ss://" + b64url(":pw") + "@h.example.com:1", "ss", "cipher method"},
		{"ss without password", "ss://" + b64url("aes-128-gcm:") + "@h.example.com:1", "ss", "password"},
		{"ss without port", "ss://" + b64url("aes-128-gcm:pw") + "@h.example.com", "ss", "host:port"},
		{"vmess websocket", "vmess://" + encode(fmt.Sprintf(`{"add":"h.example.com","port":"443","id":%q,"net":"ws","path":"/x"}`, testUUID)), "vmess", "transport"},
		{"vmess header obfuscation", "vmess://" + encode(fmt.Sprintf(`{"add":"h.example.com","port":"443","id":%q,"net":"tcp","type":"http"}`, testUUID)), "vmess", "obfuscation"},
		{"vmess bad port", "vmess://" + encode(fmt.Sprintf(`{"add":"h.example.com","port":"70000","id":%q}`, testUUID)), "vmess", "port"},
		{"vmess bad uuid", "vmess://" + encode(`{"add":"h.example.com","port":"443","id":"not-a-uuid"}`), "vmess", "uuid"},
		{"vmess reality", "vmess://" + encode(fmt.Sprintf(`{"add":"h.example.com","port":"443","id":%q,"tls":"reality"}`, testUUID)), "vmess", "security"},
		{"vmess not json", "vmess://" + encode("hello"), "vmess", "json"},
		{"vless without security", "vless://" + testUUID + "@h.example.com:443?encryption=none", "vless", "tls nor reality"},
		{"vless reality without pbk", "vless://" + testUUID + "@h.example.com:443?security=reality&sni=x", "vless", "pbk"},
		{"vless grpc", "vless://" + testUUID + "@h.example.com:443?security=tls&type=grpc", "vless", "transport"},
		{"vless encryption", "vless://" + testUUID + "@h.example.com:443?security=tls&encryption=aes", "vless", "encryption"},
		{"trojan websocket", "trojan://pw@h.example.com:443?type=ws", "trojan", "transport"},
		{"trojan without password", "trojan://@h.example.com:443", "trojan", "password"},
		{"hysteria2 unknown obfs", "hysteria2://pw@h.example.com:443?obfs=other", "hysteria2", "obfs"},
		{"tuic without password", "tuic://" + testUUID + "@h.example.com:443", "tuic", "password"},
		{"tuic relay mode", "tuic://" + testUUID + ":pw@h.example.com:443?udp_relay_mode=quic", "tuic", "relay mode"},
		{"unknown scheme", "wireguard://key@h.example.com:51820", "wireguard", "unsupported link type"},
		{"no scheme", "h.example.com:443", "", "starts with"},
		{"empty", "   ", "", "empty"},
		// The old ss spelling base64-decodes the whole body, so the "host" is
		// whatever those bytes happen to say. A host holding a '#' or a control
		// character can never be dialled; importing it would put a node in the
		// list that is certain to fail at connect time.
		{"ss payload with a '#' in the host", "ss://0006001A0C0j0006M0", "ss", "host"},
		{"ss payload with a control character in the host", "ss://" + b64url("aes-128-gcm:pw@exa\x00mple.com:8388"), "ss", "host"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := share.Parse(tc.link)
			if err == nil {
				t.Fatal("parse succeeded, want a rejection")
			}
			var linkErr *share.Error
			if !asError(err, &linkErr) {
				t.Fatalf("error %v is not a *share.Error", err)
			}
			if linkErr.Scheme != tc.scheme {
				t.Fatalf("scheme = %q, want %q", linkErr.Scheme, tc.scheme)
			}
			if !strings.Contains(linkErr.Reason, tc.reason) {
				t.Fatalf("reason %q does not mention %q", linkErr.Reason, tc.reason)
			}
			// The message must never quote the link: it carries credentials.
			if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "pw@") {
				t.Fatalf("error message leaks the link: %v", err)
			}
		})
	}
}

// TestParseAllReportsEveryBadLink checks that one bad line in a subscription
// does not hide the next one.
func TestParseAllReportsEveryBadLink(t *testing.T) {
	links := []string{
		"ss://" + b64url("aes-128-gcm:pw") + "@h.example.com:1#ok",
		"vmess://" + encode("not json"),
		"trojan://pw@h.example.com:443#ok2",
		"wireguard://x@h.example.com:1",
	}
	proxies, err := share.ParseAll(links)
	if err == nil {
		t.Fatal("ParseAll accepted a list with bad links")
	}
	if len(proxies) != 2 {
		t.Fatalf("parsed %d links, want 2", len(proxies))
	}
	for _, want := range []string{"item 2", "item 4", "vmess", "wireguard"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not mention %q", err, want)
		}
	}
}

// asError is errors.As without importing it for one call site.
func asError(err error, target **share.Error) bool {
	for err != nil {
		if typed, ok := err.(*share.Error); ok {
			*target = typed
			return true
		}
		unwrapper, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = unwrapper.Unwrap()
	}
	return false
}
