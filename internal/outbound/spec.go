package outbound

import (
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
// key=value. The configuration layer keeps that tail raw on purpose, because a
// password may itself contain "=", so interpreting it is this package's job.
type Spec struct {
	Name   string
	Type   string
	Server string
	Port   int
	Args   []string
}

// optionSkip is how many leading entries of Args are not options.
const optionSkip = 2

// Option keys shared by the protocols that authenticate with a username and a
// password.
const (
	optUsername = "username"
	optPassword = "password"
)

// authOptionKeys is the option set of the username and password protocols.
var authOptionKeys = map[string]bool{optUsername: true, optPassword: true}

// New builds the dialer a spec describes.
//
// A type of a later stage yields an Unsupported dialer rather than an error: a
// configuration may list protocols this build does not implement yet. A
// malformed option of a type that is implemented is an error, since that is a
// configuration mistake and ignoring it would silently dial without the
// authentication the user asked for.
func New(spec Spec) (Dialer, error) {
	typ := strings.ToLower(strings.TrimSpace(spec.Type))
	var (
		dialer Dialer
		err    error
	)
	switch typ {
	case "socks5":
		dialer, err = newSOCKS5FromSpec(spec)
	case "http", "https":
		dialer, err = newHTTPFromSpec(spec, typ == "https")
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

// newSOCKS5FromSpec builds the SOCKS5 dialer of a [Proxy] entry.
func newSOCKS5FromSpec(spec Spec) (Dialer, error) {
	opts, err := parseOptions(spec.Args, authOptionKeys)
	if err != nil {
		return nil, err
	}
	user, pass, err := credentials(opts)
	if err != nil {
		return nil, err
	}
	return NewSOCKS5(SOCKS5Options{
		Server:   spec.Server,
		Port:     spec.Port,
		Username: user,
		Password: pass,
	})
}

// newHTTPFromSpec builds the HTTP or HTTPS CONNECT dialer of a [Proxy] entry.
func newHTTPFromSpec(spec Spec, useTLS bool) (Dialer, error) {
	opts, err := parseOptions(spec.Args, authOptionKeys)
	if err != nil {
		return nil, err
	}
	user, pass, err := credentials(opts)
	if err != nil {
		return nil, err
	}
	return NewHTTPProxy(HTTPProxyOptions{
		Server:   spec.Server,
		Port:     spec.Port,
		Username: user,
		Password: pass,
		TLS:      useTLS,
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
