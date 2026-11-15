// Package share turns share links into [Proxy] entries.
//
// A share link is the compact form a provider hands out: ss://, vmess://,
// vless://, trojan://, hysteria2:// and tuic://. Parsing one produces exactly
// the shape a [Proxy] line has, so an imported node and a hand-written node are
// built by the same code and cannot drift apart.
//
// Three rules shape every function here. A link is either understood completely
// or rejected with the reason, because a node that silently loses its transport
// or its TLS setting would fail much later, at dial time, looking like a server
// problem. Parse also runs the outbound registry's static checks, so "this link
// parses" and "this entry can be built" are the same statement: an unknown
// cipher, an unsupported flow or a malformed account identifier is rejected at
// the importer's boundary rather than at startup. And an error never quotes the
// link: links carry passwords, and these messages end up in logs and in the
// local API.
package share

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/melon-tgj/melonarc/internal/config"
	"github.com/melon-tgj/melonarc/internal/outbound"
)

// Error is one rejected link: the type it claimed to be and why it was
// rejected. The link itself is not kept, so a password cannot leak through an
// error message.
type Error struct {
	Scheme string
	Reason string
	// cause is the underlying registry error when the rejection came from a
	// static parameter check. It is kept only so errors.Is can classify the
	// failure; Error.Error never renders it.
	cause error
}

// Error implements error.
func (e *Error) Error() string {
	if e.Scheme == "" {
		return "share link: " + e.Reason
	}
	return e.Scheme + " link: " + e.Reason
}

// Unwrap returns the cause of a static rejection, if it had one.
func (e *Error) Unwrap() error { return e.cause }

func fail(scheme, format string, args ...interface{}) error {
	return &Error{Scheme: scheme, Reason: fmt.Sprintf(format, args...)}
}

// failCause reports a rejection that came from the outbound registry. The
// reason is this package's own wording; the cause is kept out of the message.
func failCause(scheme string, cause error, reason string) error {
	return &Error{Scheme: scheme, Reason: reason, cause: cause}
}

// Parse turns one share link into a [Proxy] entry. The returned entry has no
// line number: it did not come from a file.
//
// A link that parses is a link the outbound registry can build: the last step
// runs the same static checks the daemon will run, so a bad parameter is
// reported against the link instead of failing a startup build.
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
	var (
		entry config.Proxy
		err   error
	)
	switch scheme {
	case "ss":
		entry, err = parseShadowsocks(rest)
	case "vmess":
		entry, err = parseVMess(rest)
	case "vless":
		entry, err = parseVLESS(link)
	case "trojan":
		entry, err = parseTrojan(link)
	case "hysteria2", "hy2":
		entry, err = parseHysteria2(link, scheme)
	case "tuic":
		entry, err = parseTUIC(link)
	default:
		return config.Proxy{}, fail(scheme, "unsupported link type")
	}
	if err != nil {
		return config.Proxy{}, err
	}
	if err := validateStaticParameters(scheme, entry); err != nil {
		return config.Proxy{}, err
	}
	return entry, nil
}

// validateStaticParameters is where the importer and the dialer builder meet.
// Both produce the same [Proxy] entry, so the registry that will build the
// dialer is the only place that knows what each protocol accepts; running it
// here keeps a bad link out of a subscription instead of leaving it for
// startup to refuse with a line number.
func validateStaticParameters(scheme string, entry config.Proxy) error {
	spec := outbound.Spec{
		Type: entry.Type, Server: entry.Server, Port: entry.Port, Args: entry.Args,
	}
	if err := outbound.Validate(spec); err != nil {
		return failCause(scheme, err, registryReason(entry.Type, err))
	}
	return nil
}

// registryReason keeps the registry's explanation — it names the option and the
// value that was refused — while dropping the prefixes that would otherwise
// repeat the protocol and the package sentinel in a share error ("ss link: ss:
// outbound: invalid proxy option: ..."). Every option the parser writes is a
// key=value pair, so the values a static rejection quotes are protocol
// parameters (a cipher name, a server name, a rate), never a positional secret.
func registryReason(typ string, err error) string {
	text := err.Error()
	for _, prefix := range []string{typ + ": ", "outbound: invalid proxy option: ", "outbound: "} {
		text = strings.TrimPrefix(text, prefix)
	}
	return text
}

// Rejection is one link in a list that could not be imported.
//
// Item is the 1-based position in the list, so a caller can point at the line a
// provider served. Reason is the *Error the parser produced and never quotes
// the link.
type Rejection struct {
	Item   int
	Reason error
}

// ParseAll parses a list of links and reports every rejection instead of
// stopping at the first one. The returned entries are the ones that were
// understood completely.
//
// A rejection is never silently dropped: the caller decides whether a partly
// good list is usable and reports each bad item by its position. One bad node
// in a subscription must not take the other fifty away, while a list with
// nothing good in it is still a failure to the caller that asked for nodes.
func ParseAll(links []string) ([]config.Proxy, []Rejection) {
	proxies := make([]config.Proxy, 0, len(links))
	var rejections []Rejection
	for i, link := range links {
		entry, err := Parse(link)
		if err != nil {
			rejections = append(rejections, Rejection{Item: i + 1, Reason: err})
			continue
		}
		proxies = append(proxies, entry)
	}
	return proxies, rejections
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
	if err := validateHost(scheme, host); err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fail(scheme, "port %q is outside 1-65535", portText)
	}
	return host, port, nil
}

// maxHostLen bounds a host name: a DNS name is at most 253 bytes, and anything
// longer is not a host this product could ever dial.
const maxHostLen = 253

// validateHost rejects a host that could not be dialled: the bytes that separate
// the parts of a URL, whitespace, and control characters.
//
// A link is written by someone else and arrives over the network, so reaching the
// parser is not evidence that a string is a host. The check earns its place on the
// old ss spelling, which base64-decodes a whole "method:password@host:port" and
// therefore hands the parser a host no URL parser has looked at: a payload of
// arbitrary bytes decodes into a host holding '#' or a control character, and the
// imported node could never connect.
//
// An address literal is taken as it is, because a colon belongs in one. An
// internationalised name passes through unchanged as well: this rejects the
// impossible shapes, not the unfamiliar ones.
func validateHost(scheme, host string) error {
	if len(host) > maxHostLen {
		return fail(scheme, "the host is longer than %d bytes", maxHostLen)
	}
	if net.ParseIP(host) != nil {
		return nil
	}
	for i := 0; i < len(host); i++ {
		switch c := host[i]; {
		case c < 0x20 || c == 0x7f:
			return fail(scheme, "the host holds a control character")
		case c == ' ' || c == ':' || c == '/' || c == '\\' || c == '?' || c == '#' || c == '@' || c == '[' || c == ']':
			return fail(scheme, "the host holds %q", c)
		}
	}
	return nil
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
