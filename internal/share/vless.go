package share

import (
	"net/url"
	"strings"

	"github.com/melon-tgj/melonarc/internal/config"
)

// parseVLESS reads a vless:// link:
//
//	vless://uuid@host:port?encryption=none&security=tls&sni=...&type=tcp#name
//	vless://uuid@host:port?security=reality&pbk=...&sid=...&sni=...#name
//
// The protocol has no encryption of its own, so a link must say how the hop is
// secured. A link that says neither is rejected rather than guessed at: the two
// answers lead to different handshakes, and picking one would produce a node
// that fails at dial time.
func parseVLESS(link string) (config.Proxy, error) {
	u, err := url.Parse(strings.TrimSpace(link))
	if err != nil {
		return config.Proxy{}, fail("vless", "the link is not a valid url")
	}
	if u.User == nil {
		return config.Proxy{}, fail("vless", "the link has no uuid")
	}
	id := u.User.Username()
	if id == "" {
		return config.Proxy{}, fail("vless", "the link has no uuid")
	}
	if err := uuidOption("vless", id); err != nil {
		return config.Proxy{}, err
	}
	host, port, err := splitHostPort("vless", u.Host)
	if err != nil {
		return config.Proxy{}, err
	}
	query := u.Query()
	if err := checkTransport("vless", query.Get("type")); err != nil {
		return config.Proxy{}, err
	}
	switch encryption := strings.ToLower(query.Get("encryption")); encryption {
	case "", "none":
	default:
		return config.Proxy{}, fail("vless", "encryption %q is not supported", encryption)
	}

	args := []string{option("uuid", id)}
	security := strings.ToLower(query.Get("security"))
	sni := firstNonEmpty(query.Get("sni"), query.Get("host"))
	switch security {
	case "tls":
		args = append(args, option("tls", "true"))
		if sni != "" {
			args = append(args, option("sni", sni))
		}
	case "reality":
		publicKey := query.Get("pbk")
		if publicKey == "" {
			return config.Proxy{}, fail("vless", "reality needs the server's public key (pbk)")
		}
		args = append(args, option("reality", publicKey))
		if sni != "" {
			args = append(args, option("sni", sni))
		}
		if shortID := query.Get("sid"); shortID != "" {
			args = append(args, option("short-id", shortID))
		}
	case "":
		return config.Proxy{}, fail("vless", "the link neither sets tls nor reality")
	default:
		return config.Proxy{}, fail("vless", "security %q is not supported", security)
	}
	if flow := query.Get("flow"); flow != "" {
		args = append(args, option("flow", flow))
	}
	if alpn := alpnOption(query); alpn != "" {
		args = append(args, option("alpn", alpn))
	}
	return proxy("vless", decodeFragment(u.Fragment), host, port, args), nil
}

// parseTrojan reads a trojan:// link. The password is the whole userinfo, which
// is percent-decoded by net/url.
func parseTrojan(link string) (config.Proxy, error) {
	u, err := url.Parse(strings.TrimSpace(link))
	if err != nil {
		return config.Proxy{}, fail("trojan", "the link is not a valid url")
	}
	if u.User == nil {
		return config.Proxy{}, fail("trojan", "the link has no password")
	}
	password := u.User.Username()
	if extra, ok := u.User.Password(); ok && extra != "" {
		password += ":" + extra
	}
	if password == "" {
		return config.Proxy{}, fail("trojan", "the link has no password")
	}
	host, port, err := splitHostPort("trojan", u.Host)
	if err != nil {
		return config.Proxy{}, err
	}
	query := u.Query()
	// "type" is the transport and "headerType" the obfuscation; only the plain
	// TCP stream exists here.
	if err := checkTransport("trojan", query.Get("type")); err != nil {
		return config.Proxy{}, err
	}
	if header := query.Get("headerType"); header != "" && !strings.EqualFold(header, "none") {
		return config.Proxy{}, fail("trojan", "header obfuscation %q is not supported", header)
	}

	args := []string{option("password", password)}
	if sni := firstNonEmpty(query.Get("sni"), query.Get("peer")); sni != "" {
		args = append(args, option("sni", sni))
	}
	if boolOption(query, "allowInsecure", "allow_insecure", "insecure", "skip-cert-verify") {
		args = append(args, option("skip-cert-verify", "true"))
	}
	if alpn := alpnOption(query); alpn != "" {
		args = append(args, option("alpn", alpn))
	}
	return proxy("trojan", decodeFragment(u.Fragment), host, port, args), nil
}
