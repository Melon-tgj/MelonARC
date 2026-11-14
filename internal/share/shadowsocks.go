package share

import (
	"bytes"
	"net/url"
	"strings"

	"github.com/melon-tgj/melonarc/internal/config"
)

// parseShadowsocks reads an ss:// link. Three spellings are in use and all of
// them have to work:
//
//	ss://base64(method:password)@host:port#name      SIP002, the common form
//	ss://method:password@host:port#name              the same, not encoded
//	ss://base64(method:password@host:port)#name      the original form
//
// The fragment is the display name. A plugin would change the wire format
// completely, so a link that asks for one is rejected rather than imported as a
// node that cannot connect.
func parseShadowsocks(rest string) (config.Proxy, error) {
	body, name := splitFragment(rest)
	body, query, _ := strings.Cut(body, "?")
	if params, err := url.ParseQuery(query); err == nil {
		if params.Get("plugin") != "" {
			return config.Proxy{}, fail("ss", "plugin links are not supported")
		}
	}

	var userinfo, hostport string
	if i := strings.LastIndexByte(body, '@'); i >= 0 {
		userinfo, hostport = body[:i], body[i+1:]
	} else {
		// No '@': the whole body is base64 of "method:password@host:port".
		decoded, err := decodeBase64(body)
		if err != nil {
			return config.Proxy{}, fail("ss", "the link is neither base64 nor method:password@host:port")
		}
		text := string(decoded)
		i := strings.LastIndexByte(text, '@')
		if i < 0 {
			return config.Proxy{}, fail("ss", "the link has no host:port")
		}
		userinfo, hostport = text[:i], text[i+1:]
	}

	method, password, err := ssCredentials(userinfo)
	if err != nil {
		return config.Proxy{}, err
	}
	host, port, err := splitHostPort("ss", hostport)
	if err != nil {
		return config.Proxy{}, err
	}
	return proxy("ss", name, host, port, []string{
		option("method", method),
		option("password", password),
	}), nil
}

// ssCredentials reads "method:password" from userinfo, which may be base64 or
// percent-encoded plain text. Base64 is tried first and accepted only when it
// decodes to something with a colon in it, so an unencoded pair is never
// mistaken for an encoded one.
func ssCredentials(userinfo string) (method, password string, err error) {
	text := userinfo
	if decoded, derr := decodeBase64(userinfo); derr == nil && bytes.ContainsRune(decoded, ':') {
		text = string(decoded)
	} else if unescaped, uerr := url.PathUnescape(userinfo); uerr == nil {
		text = unescaped
	}
	method, password, ok := strings.Cut(text, ":")
	if !ok {
		return "", "", fail("ss", "the link has no method:password pair")
	}
	if method = strings.TrimSpace(method); method == "" {
		return "", "", fail("ss", "the link has no cipher method")
	}
	if password == "" {
		return "", "", fail("ss", "the link has no password")
	}
	return method, password, nil
}
