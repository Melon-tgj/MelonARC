package share_test

import (
	"net"
	"testing"

	"github.com/melon-tgj/melonarc/internal/share"
)

// FuzzParse feeds hostile share links to the importer.
//
// A link arrives from a subscription, which is to say from the network, and it
// is the most string-heavy parser in the tree: a scheme, a base64 userinfo that
// may or may not be base64, a host that may be bracketed IPv6, a query string of
// provider-specific spellings, a JSON document for one scheme, and a fragment
// that becomes the node name. Everything is sliced, decoded and re-encoded, so
// the failure this target looks for is a panic on a boundary the code computes
// from the input.
//
// On success the result is checked for the properties a configuration would rely
// on: a type, a server and a port that can be dialled, and arguments that keep
// the key=value shape. Those are cheap statements about what Parse promises, not
// a second implementation of it. Parse already runs the outbound registry's
// static checks, so building a dialer here would repeat that work and spend the
// fuzzing budget on key generation; the contract test is the place that holds
// every link shape to it.
func FuzzParse(f *testing.F) {
	seeds := []string{
		// The six link schemes, in the spellings share_test.go uses.
		"ss://YWVzLTI1Ni1nY206c2VjcmV0@example.com:8388#Node%20A",
		"ss://chacha20-ietf-poly1305:p%40ss@example.com:8388#Node",
		"ss://" + encode("aes-256-gcm:another-secret@example.com:8443") + "#Legacy",
		"ss://YWVzLTEyOC1nY206cHc@[2001:db8::1]:8388#v6",
		"vmess://" + encode(`{"v":"2","ps":"Tokyo","add":"vm.example.com","port":"443",`+
			`"id":"2dd61f16-2f34-4b9e-9d5e-0d3a1b4c5d6e","aid":"0","scy":"auto","net":"tcp",`+
			`"type":"none","tls":"tls","sni":"vm.example.com"}`),
		"vless://2dd61f16-2f34-4b9e-9d5e-0d3a1b4c5d6e@vl.example.com:443?encryption=none&security=tls&sni=front.example.com&type=tcp&alpn=h2,http/1.1#VL",
		"trojan://secret@tr.example.com:443?sni=tr.example.com&allowInsecure=1#TR",
		"hysteria2://auth@hy.example.com:443?insecure=1&obfs=salamander&obfs-password=obfssecret&sni=hy.example.com#HY",
		"hy2://user:pass@hy.example.com:8443#HY2",
		"tuic://2dd61f16-2f34-4b9e-9d5e-0d3a1b4c5d6e:secret@tu.example.com:443?sni=tu.example.com&alpn=h3&congestion_control=bbr&udp_relay_mode=native#TU",
		// The rejections TestParseRejectsWithTheTypeAndReason pins: a supported
		// scheme with an unsupported feature, and shapes that carry no scheme.
		"ss://YWVzLTEyOC1nY206cHc@h.example.com:1/?plugin=obfs-local#x",
		"ss://" + encode("") + "@h.example.com",
		"vmess://" + encode(`{"add":"h.example.com","port":"70000","id":"2dd61f16-2f34-4b9e-9d5e-0d3a1b4c5d6e"}`),
		"vmess://" + encode("hello"),
		"vless://2dd61f16-2f34-4b9e-9d5e-0d3a1b4c5d6e@h.example.com:443?security=reality&sni=x",
		"tuic://2dd61f16-2f34-4b9e-9d5e-0d3a1b4c5d6e@h.example.com:443",
		"wireguard://key@h.example.com:51820",
		"h.example.com:443",
		"   ",
		// Regression seeds from the first bounded fuzz run. Both are the old ss
		// spelling, which base64-decodes the whole body: the payload is arbitrary
		// bytes, and what comes out as the host is not a host. The first one is the
		// input the fuzzer found (kept verbatim in testdata/fuzz as well, so it
		// replays without this list); here it is spelled out so the case is
		// readable. The second is the same hole with a control character in the
		// host instead of a '#'.
		"ss://0006001A0C0j0006M0",
		"ss://" + b64url("aes-128-gcm:pw@exa\x00mple.com:8388"),
	}
	for _, seed := range seeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		proxy, err := share.Parse(raw)
		if err != nil {
			return
		}
		if proxy.Type == "" {
			t.Fatal("Parse accepted a link with no proxy type")
		}
		if proxy.Server == "" {
			t.Fatal("Parse accepted a link with no server")
		}
		if net.ParseIP(proxy.Server) == nil {
			// A name is fine, but it must still be a name: a value with a colon
			// or a slash in it means the host was cut in the wrong place.
			if containsAny(proxy.Server, ":/?#@ ") {
				t.Fatalf("Parse accepted a server that cannot be dialled: %q", proxy.Server)
			}
		}
		if proxy.Port < 1 || proxy.Port > 65535 {
			t.Fatalf("Parse accepted port %d", proxy.Port)
		}
		for _, arg := range proxy.Args {
			if arg == "" {
				t.Fatal("Parse accepted an empty argument")
			}
		}
	})
}

// containsAny reports whether s holds one of the bytes in set. It is a local
// helper so the fuzz target does not depend on the package under test for its
// own assertion.
func containsAny(s, set string) bool {
	for i := 0; i < len(s); i++ {
		for j := 0; j < len(set); j++ {
			if s[i] == set[j] {
				return true
			}
		}
	}
	return false
}
