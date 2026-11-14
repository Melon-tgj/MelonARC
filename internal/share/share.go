// Package share turns share links into [Proxy] entries.
//
// A share link is the compact form a provider hands out: ss://, vmess://,
// vless://, trojan://, hysteria2:// and tuic://. Parsing one produces exactly
// the shape a [Proxy] line has, so an imported node and a hand-written node are
// built by the same code and cannot drift apart.
//
// Two rules shape every function here. A link is either understood completely or
// rejected with the reason, because a node that silently loses its transport or
// its TLS setting would fail much later, at dial time, looking like a server
// problem. And an error never quotes the link: links carry passwords, and these
// messages end up in logs and in the local API.
package share

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/melon-tgj/melonarc/internal/config"
)

// Error is one rejected link: the type it claimed to be and why it was
// rejected. The link itself is not kept, so a password cannot leak through an
// error message.
type Error struct {
	Scheme string
	Reason string
}

// Error implements error.
func (e *Error) Error() string {
	if e.Scheme == "" {
		return "share link: " + e.Reason
	}
	return e.Scheme + " link: " + e.Reason
}

func fail(scheme, format string, args ...interface{}) error {
	return &Error{Scheme: scheme, Reason: fmt.Sprintf(format, args...)}
}

// Parse turns one share link into a [Proxy] entry. The returned entry has no
// line number: it did not come from a file.
func Parse(raw string) (config.Proxy, error) {
	link := strings.TrimSpace(raw)
	if link == "" {
		return config.Proxy{}, fail("", "the link is empty")
	}
	scheme, rest, ok := strings.Cut(link, "://")
	if !ok {
		return config.Proxy{}, fail("", "a share link starts with <type>://")
	}
	scheme = strings.ToLower(strings.TrimSpace(scheme))
	switch scheme {
	case "ss":
		return parseShadowsocks(rest)
	case "vmess":
		return parseVMess(rest)
	case "vless":
		return parseVLESS(link)
	case "trojan":
		return parseTrojan(link)
	case "hysteria2", "hy2":
		return parseHysteria2(link, scheme)
	case "tuic":
		return parseTUIC(link)
	default:
		return config.Proxy{}, fail(scheme, "unsupported link type")
	}
}

// ParseAll parses a list of links and reports every rejection instead of
// stopping at the first one. The indexes in the error let the caller point at
// the offending line.
func ParseAll(links []string) ([]config.Proxy, error) {
	proxies := make([]config.Proxy, 0, len(links))
	var issues []error
	for i, link := range links {
		proxy, err := Parse(link)
		if err != nil {
			issues = append(issues, fmt.Errorf("item %d: %w", i+1, err))
			continue
		}
		proxies = append(proxies, proxy)
	}
	if len(issues) > 0 {
		return proxies, errors.Join(issues...)
	}
	return proxies, nil
}

// splitFragment separates the #name suffix, which is the only part of a link
// that is free text. Every scheme uses it for the display name.
func splitFragment(body string) (rest, name string) {
	if i := strings.IndexByte(body, '#'); i >= 0 {
		return body[:i], decodeFragment(body[i+1:])
	}
	return body, ""
}

func decodeFragment(text string) string {
	if name, err := url.PathUnescape(text); err == nil {
		return strings.TrimSpace(name)
	}
	return strings.TrimSpace(text)
}

// proxy assembles a [Proxy] entry: the server and port go into their own
// fields, everything after the port is kept as the raw argument list the
// outbound registry interprets.
func proxy(typ, name, host string, port int, args []string) config.Proxy {
	if name == "" {
		name = fmt.Sprintf("%s %s:%d", typ, host, port)
	}
	return config.Proxy{
		Name:   name,
		Type:   typ,
		Server: host,
		Port:   port,
		Args:   append([]string{host, strconv.Itoa(port)}, args...),
	}
}

// splitHostPort reads "host:port" and returns the two parts. An IPv6 literal
// has to be bracketed, which is what every client writes.
func splitHostPort(scheme, hostport string) (string, int, error) {
	host, portText, err := net.SplitHostPort(hostport)
	if err != nil {
		return "", 0, fail(scheme, "the address %q is not host:port", hostport)
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return "", 0, fail(scheme, "the address has no host")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fail(scheme, "port %q is outside 1-65535", portText)
	}
	return host, port, nil
}

// decodeBase64 accepts every spelling providers use: standard or URL-safe
// alphabet, with or without padding.
func decodeBase64(text string) ([]byte, error) {
	text = strings.TrimSpace(text)
	// A percent-encoded '=' is common in links that went through a form.
	text = strings.ReplaceAll(text, "%3D", "=")
	text = strings.ReplaceAll(text, "%3d", "=")
	encodings := []*base64.Encoding{
		base64.RawURLEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.StdEncoding,
	}
	var lastErr error
	for _, enc := range encodings {
		decoded, err := enc.DecodeString(text)
		if err == nil {
			return decoded, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// option renders one "key=value" argument. The registry splits at the first
// '=', so a value may contain '=' itself.
func option(key, value string) string { return key + "=" + value }

// boolOption reports whether a query parameter is set to a true value. The
// spellings differ per client, so all of the ones in the wild are accepted.
func boolOption(values url.Values, keys ...string) bool {
	for _, key := range keys {
		value := strings.ToLower(strings.TrimSpace(values.Get(key)))
		switch value {
		case "1", "true", "yes", "on":
			return true
		}
	}
	return false
}

// alpnOption joins the comma separated alpn list of a link into the "|"
// separated form the [Proxy] syntax uses.
func alpnOption(values url.Values) string {
	raw := strings.TrimSpace(values.Get("alpn"))
	if raw == "" {
		return ""
	}
	parts := strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == '|' })
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return strings.Join(parts, "|")
}

// checkTransport rejects a link that asks for a transport this build does not
// implement. Both VMess and VLESS can be wrapped in WebSocket, gRPC or HTTP/2;
// none of those exist here, and dropping the setting would make the node look
// like a plain TCP one and fail with a confusing handshake error.
func checkTransport(scheme, network string) error {
	switch strings.ToLower(strings.TrimSpace(network)) {
	case "", "tcp", "raw", "none":
		return nil
	default:
		return fail(scheme, "transport %q is not supported", network)
	}
}

// uuidOption validates the shape of a 16-byte identifier. The outbound parses
// it again; checking here means a malformed link is reported by the importer
// with the link in hand, not by a dialer at startup.
func uuidOption(scheme, id string) error {
	compact := strings.ReplaceAll(strings.TrimSpace(id), "-", "")
	if len(compact) != 32 {
		return fail(scheme, "the account identifier is not a uuid")
	}
	for _, r := range compact {
		if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
			return fail(scheme, "the account identifier is not a uuid")
		}
	}
	return nil
}
