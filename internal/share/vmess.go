package share

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/melon-tgj/melonarc/internal/config"
)

// parseVMess reads a vmess:// link. The body is base64 of a small JSON object,
// which is why this scheme looks different from the others: the fields are
// named rather than positional, and any of them may arrive as a string or as a
// number.
//
// The transport fields are the interesting ones. This build speaks the AEAD
// protocol over a plain TCP stream, optionally wrapped in TLS, so a link that
// asks for WebSocket, gRPC or a header obfuscation is rejected instead of being
// imported as a node that looks right and cannot connect.
func parseVMess(rest string) (config.Proxy, error) {
	body, fragment := splitFragment(rest)
	raw, err := decodeBase64(body)
	if err != nil {
		return config.Proxy{}, fail("vmess", "the link is not base64 encoded json")
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return config.Proxy{}, fail("vmess", "the link is not a json object")
	}

	host := jsonText(doc, "add")
	if host == "" {
		return config.Proxy{}, fail("vmess", "the link has no server address")
	}
	port, err := jsonPort(doc, "port")
	if err != nil {
		return config.Proxy{}, err
	}
	id := jsonText(doc, "id")
	if id == "" {
		return config.Proxy{}, fail("vmess", "the link has no uuid")
	}
	if err := uuidOption("vmess", id); err != nil {
		return config.Proxy{}, err
	}
	if err := checkTransport("vmess", jsonText(doc, "net")); err != nil {
		return config.Proxy{}, err
	}
	switch header := strings.ToLower(jsonText(doc, "type")); header {
	case "", "none":
	default:
		return config.Proxy{}, fail("vmess", "header obfuscation %q is not supported", header)
	}

	args := []string{option("uuid", id)}
	if security := jsonText(doc, "scy"); security != "" {
		args = append(args, option("security", security))
	}
	// alterid is meaningless in the AEAD header this build speaks, but it is
	// part of every link a provider hands out, so it is carried through and
	// ignored by the dialer rather than dropped here.
	if alterID := jsonText(doc, "aid"); alterID != "" && alterID != "0" {
		args = append(args, option("alterid", alterID))
	}
	switch tlsMode := strings.ToLower(jsonText(doc, "tls")); tlsMode {
	case "", "none":
	case "tls":
		args = append(args, option("tls", "true"))
		// A link may carry the SNI in "sni" or, more often, in "host"; the
		// latter is also the WebSocket host header, which is why it is only
		// consulted once the transport is known to be plain TCP.
		if sni := firstNonEmpty(jsonText(doc, "sni"), jsonText(doc, "host")); sni != "" {
			args = append(args, option("sni", sni))
		}
	default:
		return config.Proxy{}, fail("vmess", "security %q is not supported", tlsMode)
	}
	if alpn := alpnOptionFromText(jsonText(doc, "alpn")); alpn != "" {
		args = append(args, option("alpn", alpn))
	}
	name := firstNonEmpty(jsonText(doc, "ps"), fragment)
	return proxy("vmess", name, host, port, args), nil
}

// jsonText reads a field that may be a string, a number or a boolean. Links are
// written by many tools and the JSON types are not consistent between them.
func jsonText(doc map[string]interface{}, key string) string {
	value, ok := doc[key]
	if !ok {
		return ""
	}
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v)
	case float64:
		if v == float64(int64(v)) {
			return strconv.FormatInt(int64(v), 10)
		}
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		if v {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}

// jsonPort reads the port field, which is a string in most links and a number
// in some.
func jsonPort(doc map[string]interface{}, key string) (int, error) {
	text := jsonText(doc, key)
	if text == "" {
		return 0, fail("vmess", "the link has no port")
	}
	port, err := strconv.Atoi(text)
	if err != nil || port < 1 || port > 65535 {
		return 0, fail("vmess", "port %q is outside 1-65535", text)
	}
	return port, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// alpnOptionFromText normalises the two spellings of an alpn list found in
// links: a comma separated string, or a JSON array flattened to text by
// jsonText.
func alpnOptionFromText(text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	fields := strings.FieldsFunc(text, func(r rune) bool {
		return r == ',' || r == '|' || r == '[' || r == ']' || r == '"' || r == ' '
	})
	parts := make([]string, 0, len(fields))
	for _, field := range fields {
		if field = strings.TrimSpace(field); field != "" {
			parts = append(parts, field)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, "|")
}
