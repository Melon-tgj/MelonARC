// Package inbound implements the local proxy listeners and the pipeline that
// turns an accepted connection into an outbound one.
//
// The package adds the two things the layers below it cannot provide: the wire
// protocols a client speaks (HTTP proxying, SOCKS5 with its authentication and
// UDP association) and the bidirectional relay that carries a stream once it is
// open. Everything else is delegated: rules classify a destination, the policy
// registry resolves the name a rule chose to a dialer, and the outbound layer
// speaks the protocol that reaches the destination.
//
// A destination that arrives as a name is resolved before matching only when the
// compiled rules contain an address rule that can use the answer. A rule carrying
// no-resolve asks for the opposite, and the engine enforces it per rule, so a
// name never gains an address rule on the back of a lookup another rule needed.
//
// A failed dial is reported back to the policy groups along the resolution
// path, which is what lets a Fallback or URL-Test group move on immediately
// instead of waiting for its next probe round.
//
// The TUN listener belongs to a later stage; it will hand its connections to
// the same Handler.
package inbound
