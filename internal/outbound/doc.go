// Package outbound holds the per-protocol outbound implementations and the
// dialer interface they share.
//
// A Dialer opens streams and datagram associations to a destination; the
// protocol behind it decides how those reach the network. DIRECT opens them from
// the local host, SOCKS5 and HTTP tunnel them through a proxy server, and the
// encrypted protocols arrive in a later stage.
//
//	dialer, err := outbound.New(outbound.Spec{Type: "socks5", Server: "…", Port: 1080, Args: args})
//	conn, err := dialer.DialContext(ctx, "example.com:443")
//	packet, err := dialer.DialPacket(ctx, "example.com:53")
//
// A tunnelling dialer does not resolve a name itself: the name is handed to the
// proxy, which resolves it. That keeps a proxied lookup out of the local
// resolver and is what makes the rule engine and the DNS layer independent of
// the protocol in use.
//
// Parameters of a [Proxy] line are interpreted here, not in the configuration
// layer. New takes a Spec holding the type, the server and the raw argument
// tail, and each protocol parses the tail it understands; a key it does not
// understand is an error rather than a silently ignored setting.
//
// Prober measures a policy group member through its own dialer, so URL-Test and
// Fallback probe the path they would actually use.
package outbound
