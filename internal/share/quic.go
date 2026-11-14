package share

import (
	"net/url"
	"strings"

	"github.com/melon-tgj/melonarc/internal/config"
)

// parseHysteria2 reads a hysteria2:// (or hy2://) link:
//
//	hysteria2://auth@host:port?sni=...&insecure=1&obfs=salamander&obfs-password=...#name
//
// The auth string may be "user:password"; both halves are part of the same
// credential, so they are rejoined rather than split.
func parseHysteria2(link, scheme string) (config.Proxy, error) {
	u, err := url.Parse(strings.TrimSpace(link))
	if err != nil {
		return config.Proxy{}, fail(scheme, "the link is not a valid url")
	}
	if u.User == nil {
		return config.Proxy{}, fail(scheme, "the link has no password")
	}
	auth := u.User.Username()
	if password, ok := u.User.Password(); ok && password != "" {
		auth += ":" + password
	}
	if auth == "" {
		return config.Proxy{}, fail(scheme, "the link has no password")
	}
	host, port, err := splitHostPort(scheme, u.Host)
	if err != nil {
		return config.Proxy{}, err
	}
	query := u.Query()

	args := []string{option("password", auth)}
	if sni := query.Get("sni"); sni != "" {
		args = append(args, option("sni", sni))
	}
	if boolOption(query, "insecure", "allow_insecure", "allowInsecure", "skip-cert-verify") {
		args = append(args, option("skip-cert-verify", "true"))
	}
	// Only the Salamander obfuscation exists in the protocol; anything else is
	// a different wire format, not a setting to reinterpret.
	if obfs := strings.ToLower(strings.TrimSpace(query.Get("obfs"))); obfs != "" {
		if obfs != "salamander" {
			return config.Proxy{}, fail(scheme, "obfs %q is not supported", obfs)
		}
		args = append(args, option("obfs", obfs))
		if secret := query.Get("obfs-password"); secret != "" {
			args = append(args, option("obfs-password", secret))
		}
	}
	if alpn := alpnOption(query); alpn != "" {
		args = append(args, option("alpn", alpn))
	}
	if up := query.Get("up"); up != "" {
		args = append(args, option("up", up))
	}
	if down := query.Get("down"); down != "" {
		args = append(args, option("down", down))
	}
	return proxy("hysteria2", decodeFragment(u.Fragment), host, port, args), nil
}

// parseTUIC reads a tuic:// link:
//
//	tuic://uuid:password@host:port?sni=...&alpn=h3&congestion_control=bbr#name
//
// The authentication is a uuid and a password, both required. The congestion
// control and the udp relay mode are tuning hints: the first is decided by the
// QUIC stack here, and the second is checked because a non-native relay mode
// would describe a different wire format.
func parseTUIC(link string) (config.Proxy, error) {
	u, err := url.Parse(strings.TrimSpace(link))
	if err != nil {
		return config.Proxy{}, fail("tuic", "the link is not a valid url")
	}
	if u.User == nil {
		return config.Proxy{}, fail("tuic", "the link has no uuid and password")
	}
	id := u.User.Username()
	password, hasPassword := u.User.Password()
	if id == "" {
		return config.Proxy{}, fail("tuic", "the link has no uuid")
	}
	if err := uuidOption("tuic", id); err != nil {
		return config.Proxy{}, err
	}
	if !hasPassword || password == "" {
		return config.Proxy{}, fail("tuic", "the link has no password")
	}
	host, port, err := splitHostPort("tuic", u.Host)
	if err != nil {
		return config.Proxy{}, err
	}
	query := u.Query()
	if mode := strings.ToLower(strings.TrimSpace(query.Get("udp_relay_mode"))); mode != "" && mode != "native" {
		return config.Proxy{}, fail("tuic", "udp relay mode %q is not supported", mode)
	}

	args := []string{option("uuid", id), option("password", password)}
	if sni := query.Get("sni"); sni != "" {
		args = append(args, option("sni", sni))
	}
	if boolOption(query, "allow_insecure", "allowInsecure", "insecure", "skip-cert-verify") {
		args = append(args, option("skip-cert-verify", "true"))
	}
	if alpn := alpnOption(query); alpn != "" {
		args = append(args, option("alpn", alpn))
	}
	return proxy("tuic", decodeFragment(u.Fragment), host, port, args), nil
}
