package outbound

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Spec is one [Proxy] entry as the configuration layer keeps it.
//
// Args is the tail of the line after the type, verbatim: the first two entries
// are the server and the port, the rest are protocol options of the form
// key=value (or, for the encrypted protocols that follow that convention,
// positional method and password entries). The configuration layer keeps that
// tail raw on purpose, because a password may itself contain "=", so
// interpreting it is this package's job.
type Spec struct {
	Name   string
	Type   string
	Server string
	Port   int
	Args   []string
	// TLSConfig overrides the trust roots of the QUIC transports. It is a
	// test escape hatch: the QUIC types compile their TLS options into a
	// *tls.Config when they are built, so a fixture that wants to trust a
	// locally issued certificate has to supply it here rather than changing
	// the dialer afterwards. The configuration layer never sets this field.
	TLSConfig *tls.Config
}

// optionSkip is how many leading entries of Args are not options.
const optionSkip = 2

// Option keys shared by the protocols that authenticate with a username and a
// password.
const (
	optUsername = "username"
	optPassword = "password"
)

// Option keys of the encrypted protocols.
const (
	optMethod   = "method"
	optCipher   = "cipher"
	optPSK      = "psk"
	optUUID     = "uuid"
	optAlterID  = "alterid"
	optSecurity = "security"
	optVersion  = "version"
	optFlow     = "flow"
	optReality  = "reality"
	optShortID  = "short-id"

	// Option keys of the QUIC protocols.
	optUp           = "up"
	optDown         = "down"
	optObfs         = "obfs"
	optObfsPassword = "obfs-password"
)

// authOptionKeys is the option set of the username and password protocols.
var authOptionKeys = map[string]bool{optUsername: true, optPassword: true}

// optionSet unions the keys a protocol accepts. Every key has exactly one
// meaning across the package; a key that is not in a protocol's set is an
// error rather than a silently ignored setting.
func optionSet(groups ...map[string]bool) map[string]bool {
	out := make(map[string]bool)
	for _, group := range groups {
		for key := range group {
			out[key] = true
		}
	}
	return out
}

// New builds the dialer a spec describes.
//
// A type of a later stage yields an Unsupported dialer rather than an error: a
// configuration may list protocols this build does not implement yet. A
// malformed option of a type that is implemented is an error, since that is a
// configuration mistake and ignoring it would silently dial without the
// authentication or encryption the user asked for.
func New(spec Spec) (Dialer, error) {
	typ := strings.ToLower(strings.TrimSpace(spec.Type))
	var (
		dialer Dialer
		err    error
	)
	switch typ {
	case "socks5", "socks5-tls":
		dialer, err = newSOCKS5FromSpec(spec, typ == "socks5-tls")
	case "http", "https":
		dialer, err = newHTTPFromSpec(spec, typ == "https")
	case "ss":
		dialer, err = newShadowsocksFromSpec(spec)
	case "vmess":
		dialer, err = newVMessFromSpec(spec)
	case "trojan":
		dialer, err = newTrojanFromSpec(spec)
	case "snell":
		dialer, err = newSnellFromSpec(spec)
	case "vless":
		dialer, err = newVLESSFromSpec(spec)
	case "hysteria2":
		dialer, err = newHysteria2FromSpec(spec)
	case "tuic":
		dialer, err = newTUICFromSpec(spec)
	default:
		return &Unsupported{Protocol: typ}, nil
	}
	if err != nil {
		if spec.Name == "" {
			return nil, err
		}
		return nil, fmt.Errorf("proxy %q: %w", spec.Name, err)
	}
	return dialer, nil
}

// newSOCKS5FromSpec builds the SOCKS5 dialer of a [Proxy] entry. The variant
// whose type names TLS wraps the control connection with the shared TLS base.
func newSOCKS5FromSpec(spec Spec, useTLS bool) (Dialer, error) {
	mode := tlsNone
	if useTLS {
		mode = tlsAlways
	}
	allowed := optionSet(authOptionKeys)
	if mode != tlsNone {
		allowed = optionSet(authOptionKeys, tlsOptionKeys)
	}
	opts, err := parseOptions(spec.Args, allowed)
	if err != nil {
		return nil, err
	}
	user, pass, err := credentials(opts)
	if err != nil {
		return nil, err
	}
	tlsOpts, err := parseTLSOptions(opts, mode)
	if err != nil {
		return nil, err
	}
	return NewSOCKS5(SOCKS5Options{
		Server:   spec.Server,
		Port:     spec.Port,
		Username: user,
		Password: pass,
		TLS:      tlsOpts,
	})
}

// newHTTPFromSpec builds the HTTP or HTTPS CONNECT dialer of a [Proxy] entry.
func newHTTPFromSpec(spec Spec, useTLS bool) (Dialer, error) {
	mode := tlsNone
	if useTLS {
		mode = tlsAlways
	}
	allowed := optionSet(authOptionKeys)
	if mode != tlsNone {
		allowed = optionSet(authOptionKeys, tlsOptionKeys)
	}
	opts, err := parseOptions(spec.Args, allowed)
	if err != nil {
		return nil, err
	}
	user, pass, err := credentials(opts)
	if err != nil {
		return nil, err
	}
	tlsOpts, err := parseTLSOptions(opts, mode)
	if err != nil {
		return nil, err
	}
	return NewHTTPProxy(HTTPProxyOptions{
		Server:   spec.Server,
		Port:     spec.Port,
		Username: user,
		Password: pass,
		TLS:      useTLS,
		TLSBase:  tlsOpts,
	})
}

// parseOptions reads the option tail of a [Proxy] line. The first two entries
// are the server and the port and are skipped; every later entry must be a
// known key=value pair. The value may contain "=" because the pair is split at
// the first one, which is what keeps a base64 password intact.
func parseOptions(args []string, allowed map[string]bool) (map[string]string, error) {
	opts := make(map[string]string, len(args))
	if len(args) <= optionSkip {
		return opts, nil
	}
	for _, arg := range args[optionSkip:] {
		key, value, ok := strings.Cut(arg, "=")
		key = strings.ToLower(strings.TrimSpace(key))
		if !ok || key == "" {
			return nil, fmt.Errorf("%w: %q is not key=value", ErrInvalidOption, arg)
		}
		if !allowed[key] {
			return nil, fmt.Errorf("%w: unknown option %q", ErrInvalidOption, key)
		}
		if _, dup := opts[key]; dup {
			return nil, fmt.Errorf("%w: option %q is given twice", ErrInvalidOption, key)
		}
		opts[key] = strings.TrimSpace(value)
	}
	return opts, nil
}

// parseArgs is the option parser for protocols that also accept positional
// arguments (a cipher name and a password written without keys, as in the
// sample configuration). key=value entries must use a known key; entries
// without one are returned in order as positional values.
func parseArgs(args []string, allowed map[string]bool) (opts map[string]string, positional []string, err error) {
	opts = make(map[string]string, len(args))
	if len(args) <= optionSkip {
		return opts, nil, nil
	}
	for _, arg := range args[optionSkip:] {
		key, value, ok := strings.Cut(arg, "=")
		key = strings.ToLower(strings.TrimSpace(key))
		if !ok || key == "" {
			positional = append(positional, strings.TrimSpace(arg))
			continue
		}
		if !allowed[key] {
			return nil, nil, fmt.Errorf("%w: unknown option %q", ErrInvalidOption, key)
		}
		if _, dup := opts[key]; dup {
			return nil, nil, fmt.Errorf("%w: option %q is given twice", ErrInvalidOption, key)
		}
		opts[key] = strings.TrimSpace(value)
	}
	return opts, positional, nil
}

// credentials reads the optional username and password. Both or neither must be
// present: half a pair is a mistake, not a silent fallback to no
// authentication.
func credentials(opts map[string]string) (user, pass string, err error) {
	user, hasUser := opts[optUsername]
	pass, hasPass := opts[optPassword]
	switch {
	case hasUser && !hasPass:
		return "", "", fmt.Errorf("%w: username needs a password", ErrInvalidOption)
	case !hasUser && hasPass:
		return "", "", fmt.Errorf("%w: password without a username", ErrInvalidOption)
	case !hasUser:
		return "", "", nil
	}
	if user == "" {
		return "", "", fmt.Errorf("%w: username is empty", ErrInvalidOption)
	}
	// SOCKS5 carries both lengths in one byte each; HTTP Basic has no such
	// limit, but a credential that cannot be used by every protocol is not
	// worth accepting quietly.
	if len(user) > 255 || len(pass) > 255 {
		return "", "", fmt.Errorf("%w: username and password are limited to 255 bytes each", ErrInvalidOption)
	}
	return user, pass, nil
}

// positionalCredential reads a protocol secret that may be written either as a
// key=value option or as the first positional entry after the server and port.
func positionalCredential(opts map[string]string, positional []string, key string) (string, error) {
	if value, ok := opts[key]; ok {
		if value == "" {
			return "", fmt.Errorf("%w: %s is empty", ErrInvalidOption, key)
		}
		return value, nil
	}
	if len(positional) > 0 && positional[0] != "" {
		return positional[0], nil
	}
	return "", fmt.Errorf("%w: %s is required", ErrInvalidOption, key)
}

// basicAuth is a username and password pair, framed the way each protocol
// expects: RFC 1929 for SOCKS5, RFC 7617 for HTTP.
type basicAuth struct {
	username string
	password string
}

// header is the value of an HTTP Proxy-Authorization header.
func (a *basicAuth) header() string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(a.username+":"+a.password))
}

// Set maps the names rules and groups use to the dialer that handles them. The
// assembly layer registers the built-in DIRECT and REJECT actions here along
// with every [Proxy] entry.
type Set struct {
	dialers map[string]Dialer
}

// NewSet returns an empty dialer set.
func NewSet() *Set {
	return &Set{dialers: make(map[string]Dialer)}
}

// Add registers a dialer under a name.
func (s *Set) Add(name string, d Dialer) error {
	if name == "" {
		return errors.New("outbound: dialer name is empty")
	}
	if d == nil {
		return fmt.Errorf("outbound: dialer %q is nil", name)
	}
	if _, dup := s.dialers[name]; dup {
		return fmt.Errorf("outbound: dialer %q is already registered", name)
	}
	s.dialers[name] = d
	return nil
}

// Dialer returns the dialer registered under a name.
func (s *Set) Dialer(name string) (Dialer, error) {
	d, ok := s.dialers[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownDialer, name)
	}
	return d, nil
}

// Names lists the registered names, sorted.
func (s *Set) Names() []string {
	out := make([]string, 0, len(s.dialers))
	for name := range s.dialers {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// disownable is the optional interface of a dialer that holds something beyond
// the connections it carries. A QUIC outbound keeps one connection for every
// peer it has dialled, and that connection has no owner to close it once the
// configuration that named the outbound is gone.
type disownable interface {
	// Disown stops the dialer from being used again and releases its
	// resources as soon as nothing is using them. Nothing in flight is cut.
	Disown()
}

// Disown releases the resources of every dialer that keeps state between
// connections. The assembly layer calls it on the set a reload replaced, after
// the swap, so a replaced outbound stops holding a socket.
func (s *Set) Disown() {
	for _, d := range s.dialers {
		if r, ok := d.(disownable); ok {
			r.Disown()
		}
	}
}
