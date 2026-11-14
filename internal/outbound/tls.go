package outbound

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
)

// TLS option keys of a [Proxy] line. They are shared by every outbound that
// secures its hop, so "sni" means the same thing for a TLS-wrapped SOCKS5
// server, an HTTPS CONNECT proxy, an AEAD VMess endpoint and a Trojan server.
// Whether TLS is used is decided by the type (socks5-tls, https, trojan) or,
// where the protocol makes it optional, by tls=true (vmess).
const (
	optTLS            = "tls"
	optSNI            = "sni"
	optSkipCertVerify = "skip-cert-verify"
	optALPN           = "alpn"
)

var tlsOptionKeys = map[string]bool{
	optTLS: true, optSNI: true, optSkipCertVerify: true, optALPN: true,
}

// tlsMode describes how a [Proxy] type relates to the TLS base.
type tlsMode uint8

const (
	tlsNone     tlsMode = iota // the type never uses TLS
	tlsAlways                  // the type is TLS by definition (a TLS variant, or QUIC)
	tlsOptional                // the protocol has a tls= switch
)

// tlsModeFor maps a type to its TLS behaviour. Keeping this as one table makes
// it impossible for the config validator and the dialer builder to disagree
// about which keys a type accepts.
func tlsModeFor(typ string) tlsMode {
	switch strings.ToLower(strings.TrimSpace(typ)) {
	case "socks5-tls", "https", "trojan":
		return tlsAlways
	case "hysteria2", "tuic":
		// QUIC is TLS 1.3 by definition, so these types are always secured
		// and tls= would have nothing to turn off.
		return tlsAlways
	case "vmess", "vless":
		return tlsOptional
	default:
		return tlsNone
	}
}

// TLSOptions is the one TLS dial configuration every secured outbound uses.
// ServerName overrides the certificate name (SNI); SkipVerify disables
// certificate verification; ALPN is offered only when a protocol needs it.
//
// Config is a test escape hatch: supplying a *tls.Config replaces the built
// ones, so a test can trust a local certificate. The configuration layer
// never sets it.
type TLSOptions struct {
	Enabled    bool
	ServerName string
	SkipVerify bool
	ALPN       []string
	Config     *tls.Config
}

// For builds the *tls.Config for a handshake with host. The host is the server
// name by default, including when it is an IP literal (Go verifies the IP SAN
// in that case); an explicit ServerName overrides it.
func (o TLSOptions) For(host string) *tls.Config {
	var cfg *tls.Config
	if o.Config != nil {
		// Config is the test escape hatch for trust roots and certificates.
		// The shared options still apply on top of it, so a test can check an
		// overridden server name or an ALPN list without losing its own pool.
		cfg = o.Config.Clone()
		if cfg.ServerName == "" {
			cfg.ServerName = host
		}
		if cfg.MinVersion == 0 {
			cfg.MinVersion = tls.VersionTLS12
		}
	} else {
		cfg = &tls.Config{
			MinVersion:         tls.VersionTLS12,
			ServerName:         host,
			InsecureSkipVerify: o.SkipVerify,
		}
	}
	if o.ServerName != "" {
		cfg.ServerName = o.ServerName
	}
	if o.SkipVerify {
		cfg.InsecureSkipVerify = true
	}
	if len(o.ALPN) > 0 {
		cfg.NextProtos = append([]string(nil), o.ALPN...)
	}
	return cfg
}

// Wrap secures an already dialled connection. The caller owns the deadline and
// the cancellation guard, exactly as it does for a plaintext handshake.
func (o TLSOptions) Wrap(ctx context.Context, conn net.Conn, host string) (net.Conn, error) {
	if !o.Enabled {
		return conn, nil
	}
	secured := tls.Client(conn, o.For(host))
	if err := secured.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("tls handshake with %s: %w", host, err)
	}
	return secured, nil
}

// parseTLSOptions reads the TLS keys of a parsed option map. allowToggle says
// whether tls= is meaningful for this type.
func parseTLSOptions(opts map[string]string, mode tlsMode) (TLSOptions, error) {
	o := TLSOptions{Enabled: mode == tlsAlways}
	for key, value := range opts {
		switch key {
		case optTLS:
			on, err := parseToggleOption(value)
			if err != nil {
				return TLSOptions{}, fmt.Errorf("%w: tls: %v", ErrInvalidOption, err)
			}
			if mode != tlsOptional {
				return TLSOptions{}, fmt.Errorf("%w: tls= is not accepted here; the proxy type decides whether TLS is used", ErrInvalidOption)
			}
			o.Enabled = on
		case optSNI:
			if err := validateSNI(value); err != nil {
				return TLSOptions{}, fmt.Errorf("%w: sni: %v", ErrInvalidOption, err)
			}
			o.ServerName = value
		case optSkipCertVerify:
			on, err := parseToggleOption(value)
			if err != nil {
				return TLSOptions{}, fmt.Errorf("%w: skip-cert-verify: %v", ErrInvalidOption, err)
			}
			o.SkipVerify = on
		case optALPN:
			list, err := parseALPN(value)
			if err != nil {
				return TLSOptions{}, fmt.Errorf("%w: alpn: %v", ErrInvalidOption, err)
			}
			o.ALPN = list
		}
	}
	return o, nil
}

// ValidateTLSOptions checks the TLS keys of a raw [Proxy] argument tail. The
// configuration layer calls it so a bad sni, a typo in skip-cert-verify or a
// TLS option on a plaintext type is reported as "[Proxy] line N: ..." before
// the daemon starts. Other protocol options are interpreted by New, which is
// the assembly-time check; this function deliberately ignores them.
func ValidateTLSOptions(typ string, args []string) error {
	mode := tlsModeFor(typ)
	seen := make(map[string]bool)
	for _, arg := range args[min(len(args), optionSkip):] {
		key, value, ok := strings.Cut(arg, "=")
		key = strings.ToLower(strings.TrimSpace(key))
		if !ok || key == "" || !tlsOptionKeys[key] {
			continue // positional argument or a protocol-specific option
		}
		value = strings.TrimSpace(value)
		if seen[key] {
			return fmt.Errorf("%w: tls option %q is given twice", ErrInvalidOption, key)
		}
		seen[key] = true
		if mode == tlsNone {
			return fmt.Errorf("%w: tls option %q is not accepted by proxy type %q", ErrInvalidOption, key, typ)
		}
		if key == optTLS && mode != tlsOptional {
			return fmt.Errorf("%w: tls= is not accepted by proxy type %q; its type already decides whether TLS is used", ErrInvalidOption, typ)
		}
		var err error
		switch key {
		case optTLS, optSkipCertVerify:
			_, err = parseToggleOption(value)
		case optSNI:
			err = validateSNI(value)
		case optALPN:
			_, err = parseALPN(value)
		}
		if err != nil {
			return fmt.Errorf("%w: tls option %q: %v", ErrInvalidOption, key, err)
		}
	}
	return nil
}

func parseToggleOption(value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "on", "yes", "1":
		return true, nil
	case "false", "off", "no", "0":
		return false, nil
	default:
		return false, fmt.Errorf("%q is neither true nor false", value)
	}
}

func validateSNI(value string) error {
	if value == "" {
		return fmt.Errorf("server name is empty")
	}
	if len(value) > 253 {
		return fmt.Errorf("server name is longer than 253 bytes")
	}
	if net.ParseIP(value) != nil {
		return nil
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-' || c == '.':
		default:
			return fmt.Errorf("server name %q contains an unsupported character %q", value, c)
		}
	}
	if strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") || strings.Contains(value, "..") {
		return fmt.Errorf("server name %q has an empty label", value)
	}
	return nil
}

// parseALPN reads a list separated by "|": the native format splits [Proxy]
// arguments on commas, so ALPN protocols cannot be comma separated.
func parseALPN(value string) ([]string, error) {
	if value == "" {
		return nil, fmt.Errorf("protocol list is empty")
	}
	parts := strings.Split(value, "|")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("protocol list has an empty entry")
		}
		if len(part) > 255 {
			return nil, fmt.Errorf("protocol %q is too long", part)
		}
		for i := 0; i < len(part); i++ {
			if part[i] < 0x20 || part[i] == 0x7f {
				return nil, fmt.Errorf("protocol %q contains a control character", part)
			}
		}
	}
	if len(parts) > 16 {
		return nil, fmt.Errorf("protocol list has more than 16 entries")
	}
	return parts, nil
}
