package inbound

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/melon-tgj/melonarc/internal/dns"
	"github.com/melon-tgj/melonarc/internal/outbound"
	"github.com/melon-tgj/melonarc/internal/policy"
	"github.com/melon-tgj/melonarc/internal/rules"
)

// Transports a request can arrive on. The two values are what a PROTOCOL rule
// and a rules.Query expect.
const (
	networkTCP = "tcp"
	networkUDP = "udp"
)

// Request is one destination an inbound listener accepted, reduced to what
// routing needs: where it goes and over which transport.
type Request struct {
	// Target is the destination the client asked for. A name stays a name so
	// that the outbound can hand it to whoever can resolve it.
	Target outbound.Target
	// Network is "tcp" or "udp".
	Network string
}

// Selection is the outcome of routing a request.
type Selection struct {
	// Rule is the rule that classified the destination.
	Rule *rules.Rule
	// Target is the policy, policy group or built-in action the rule named.
	Target string
	// Path runs from Target to the outbound that carried the request, for
	// example ["auto", "proxy-a"]. It is the order a failure travels back in.
	Path []string
}

// Matcher classifies a destination. rules.Program implements it.
type Matcher interface {
	Match(q rules.Query) (rules.Decision, bool)
}

// resolutionNamer is implemented by a matcher that can say whether a name has
// to be resolved before matching; rules.Program implements it. A matcher that
// cannot answer is resolved, because skipping a lookup it might need would
// silently disable its address rules.
type resolutionNamer interface {
	NeedsResolution() bool
}

// explainer is implemented by a matcher that can report how it reached a
// decision; rules.Program implements it.
type explainer interface {
	Explain(q rules.Query) rules.Explanation
}

// Resolver turns a destination name into addresses. *dns.Resolver implements
// it; the pipeline needs nothing else, so a test can count lookups in a few
// lines.
type Resolver interface {
	Resolve(ctx context.Context, host string) (dns.Result, error)
}

// Router resolves a rule target to the outbound that must carry the request.
type Router interface {
	// Route returns the dialer for a target together with the names that
	// selected it.
	Route(target string) (outbound.Dialer, []string, error)
	// Failed tells the policy groups along path that the member they selected
	// could not carry a request, so a Fallback or URL-Test group can move on
	// before its next probe round.
	Failed(path []string)
}

// handlerState is one routing configuration: the matcher, the router and the
// resolver a request is served with.
//
// A reload builds a whole new state and stores it with one pointer write, so a
// request sees either the old configuration or the new one. Passing the state
// down the call chain instead of reading the pointer twice is what keeps a
// single request on a single configuration.
type handlerState struct {
	// id changes on every replacement. A shared datagram association is keyed
	// by the state it was opened under, so a reload cannot hand a TUN session
	// an association built with the old outbound set.
	id       uint64
	matcher  Matcher
	router   Router
	resolver Resolver
}

// datagramKey identifies a shared UDP association. The path is the policy path
// that selected the outbound, and source is the client endpoint that owns it:
// destinations from one source reaching the same leaf share one association,
// which is both "one association, many destinations" and the reason a reply can
// be matched back to exactly one client.
type datagramKey struct {
	state  *handlerState
	path   string
	source string
}

// DatagramAssociation is one shared outbound datagram association. Several TUN
// UDP sessions hold a reference to it; Release gives one reference back and the
// association is closed with the last one.
type DatagramAssociation struct {
	Conn       outbound.SharedPacketConn
	Selection  Selection
	Generation uint64

	h    *Handler
	key  datagramKey
	refs int // guarded by h.poolMu
}

// Release gives back one reference. The caller must not use Conn afterwards.
func (a *DatagramAssociation) Release() {
	if a == nil || a.h == nil {
		return
	}
	h := a.h
	h.poolMu.Lock()
	shared := h.pool[a.key]
	if shared == nil || shared != a {
		h.poolMu.Unlock()
		return
	}
	a.refs--
	if a.refs > 0 {
		h.poolMu.Unlock()
		return
	}
	delete(h.pool, a.key)
	h.poolMu.Unlock()
	_ = a.Conn.Close()
}

// Handler routes one request and opens the connection it asks for. It is safe
// for concurrent use, and its routing configuration can be replaced while
// connections are being served.
type Handler struct {
	state   atomic.Pointer[handlerState]
	metrics *Metrics
	logger  *slog.Logger

	nextID atomic.Uint64
	poolMu sync.Mutex
	pool   map[datagramKey]*DatagramAssociation
}

// HandlerOptions configures a Handler.
type HandlerOptions struct {
	// Matcher is the compiled rule program.
	Matcher Matcher
	// Router resolves rule targets, normally a *PolicyRouter.
	Router Router
	// Resolver turns name destinations into addresses for the rules that need
	// one. Nil disables local resolution: a name stays a name, no address rule
	// can match it, and only the outbound decides how to resolve.
	Resolver Resolver
	// Metrics receives one record per request that was not carried. Nil keeps
	// no record, which is what a test that only cares about routing wants.
	// It is taken from the options NewHandler received: a replacement keeps
	// the observer the process was built with.
	Metrics *Metrics
	// Logger receives the routing and failure lines. Nil discards them. Like
	// Metrics it is fixed at construction.
	Logger *slog.Logger
}

// NewHandler builds the routing pipeline shared by every inbound listener.
func NewHandler(opts HandlerOptions) (*Handler, error) {
	h := &Handler{
		metrics: opts.Metrics,
		logger:  loggerOrDiscard(opts.Logger),
		pool:    make(map[datagramKey]*DatagramAssociation),
	}
	if err := h.Replace(opts); err != nil {
		return nil, err
	}
	return h, nil
}

// Replace installs a new routing configuration.
//
// It is the whole point of a reload: the listeners keep the handler they were
// started with, and the next request is classified and routed by the new rules,
// groups and resolver. Metrics and Logger are not replaced — they describe the
// process, not the configuration — and the caller keeps ownership of whatever
// the previous configuration had running.
func (h *Handler) Replace(opts HandlerOptions) error {
	if opts.Matcher == nil {
		return errors.New("inbound: a rule matcher is required")
	}
	if opts.Router == nil {
		return errors.New("inbound: a router is required")
	}
	h.state.Store(&handlerState{
		id:       h.nextID.Add(1),
		matcher:  opts.Matcher,
		router:   opts.Router,
		resolver: opts.Resolver,
	})
	// An association with no sessions left is safe to close now. One that is
	// still in use keeps its own outbound until its last session releases it;
	// no new association will be opened under this state, because the key
	// includes the state pointer.
	h.poolMu.Lock()
	for key, shared := range h.pool {
		if shared.refs == 0 {
			delete(h.pool, key)
			_ = shared.Conn.Close()
		}
	}
	h.poolMu.Unlock()
	return nil
}

// load returns the configuration a request is served with.
func (h *Handler) load() *handlerState { return h.state.Load() }

// Stream opens the stream a request describes.
//
// The selection is returned even when the dial fails, so a caller can report
// which rule and which policy were involved.
func (h *Handler) Stream(ctx context.Context, req Request) (net.Conn, Selection, error) {
	st := h.load()
	sel, dialer, err := h.route(ctx, st, req)
	if err != nil {
		h.record(req, sel, StageRoute, err)
		return nil, sel, err
	}
	conn, err := dialer.DialContext(ctx, req.Target.String())
	if err != nil {
		h.failed(st, req, sel, err)
		return nil, sel, err
	}
	return conn, sel, nil
}

// Packet opens the datagram association a request describes.
func (h *Handler) Packet(ctx context.Context, req Request) (outbound.PacketConn, Selection, error) {
	st := h.load()
	sel, dialer, err := h.route(ctx, st, req)
	if err != nil {
		h.record(req, sel, StageRoute, err)
		return nil, sel, err
	}
	conn, err := dialer.DialPacket(ctx, req.Target.String())
	if err != nil {
		h.failed(st, req, sel, err)
		return nil, sel, err
	}
	return conn, sel, nil
}

// Datagrams routes a datagram destination and returns the shared association
// that will carry it.
//
// The TUN path sees many destinations with no per-destination header, so it
// needs one association that can carry them all. An association is pooled by
// the source endpoint and the policy path that selected the outbound: the
// destinations of one client reaching the same leaf reuse it, while a different
// client or a different path gets a separate association. Keeping the source in
// the key is what makes a reply unambiguous: a shared connection reports who
// answered, not which client asked, and two clients may ask the same server.
// The pool key includes the handler state, so a reload never mixes an
// association built with the old outbound set into a new configuration.
//
// Every call takes one reference. The caller releases it with
// DatagramAssociation.Release when the UDP session that used it ends.
func (h *Handler) Datagrams(ctx context.Context, req Request, source string) (*DatagramAssociation, error) {
	st := h.load()
	sel, dialer, err := h.route(ctx, st, req)
	if err != nil {
		h.record(req, sel, StageRoute, err)
		return nil, err
	}
	key := datagramKey{state: st, path: strings.Join(sel.Path, "\x1f"), source: source}
	h.poolMu.Lock()
	if shared := h.pool[key]; shared != nil {
		shared.refs++
		h.poolMu.Unlock()
		return shared, nil
	}
	h.poolMu.Unlock()

	conn, err := openSharedDatagram(ctx, dialer, req.Target)
	if err != nil {
		h.failed(st, req, sel, err)
		return nil, err
	}
	h.poolMu.Lock()
	if shared := h.pool[key]; shared != nil {
		shared.refs++
		h.poolMu.Unlock()
		_ = conn.Close() // another session won the race to open it
		return shared, nil
	}
	shared := &DatagramAssociation{
		Conn:       conn,
		Selection:  sel,
		Generation: st.id,
		h:          h,
		key:        key,
		refs:       1,
	}
	h.pool[key] = shared
	h.poolMu.Unlock()
	return shared, nil
}

// openSharedDatagram uses a dialer's own shared association when it has one and
// wraps a single-destination PacketConn otherwise. The wrapper is what keeps
// dialers that only implement DialPacket usable from the TUN path.
func openSharedDatagram(ctx context.Context, dialer outbound.Dialer, dest outbound.Target) (outbound.SharedPacketConn, error) {
	if shared, ok := dialer.(outbound.SharedDialer); ok {
		return shared.DialSharedUDP(ctx)
	}
	conn, err := dialer.DialPacket(ctx, dest.String())
	if err != nil {
		return nil, err
	}
	return &singleDestinationDatagram{conn: conn, dest: dest}, nil
}

// singleDestinationDatagram presents a one-destination PacketConn in the shared
// shape. Writing to another destination is refused instead of silently sending
// the payload to the wrong peer.
type singleDestinationDatagram struct {
	conn outbound.PacketConn
	dest outbound.Target
}

func (c *singleDestinationDatagram) ReadFrom(p []byte) (int, outbound.Target, error) {
	n, err := c.conn.Read(p)
	if err != nil {
		return 0, outbound.Target{}, err
	}
	return n, c.dest, nil
}

func (c *singleDestinationDatagram) WriteTo(payload []byte, destination outbound.Target) (int, error) {
	if destination.String() != c.dest.String() {
		return 0, fmt.Errorf("inbound: datagram association is bound to %s, not %s", c.dest, destination)
	}
	return c.conn.Write(payload)
}

func (c *singleDestinationDatagram) Close() error { return c.conn.Close() }

// Explain classifies a query the way a request would be classified, lookup
// included, and reports every step. The local API answers with it, so what an
// operator reads is what a connection goes through.
func (h *Handler) Explain(ctx context.Context, q rules.Query) (rules.Explanation, error) {
	st := h.load()
	stepwise, ok := st.matcher.(explainer)
	if !ok {
		return rules.Explanation{}, errors.New("inbound: this matcher cannot explain a query")
	}
	q, resolution := h.prepare(ctx, st, q)
	exp := stepwise.Explain(q)
	if q.Name != "" {
		exp.Resolution = &resolution
	}
	return exp, nil
}

// prepare adds an address to a query that carries a name, when the rule program
// has an address rule that could match it.
//
// A rule carrying no-resolve asks for the opposite: the name must not become an
// address on its behalf. The engine enforces that rule by rule, but the
// cheapest guarantee is to not look up at all when no address rule can use the
// answer, which is what NeedsResolution reports.
func (h *Handler) prepare(ctx context.Context, st *handlerState, q rules.Query) (rules.Query, rules.Resolution) {
	switch {
	case q.Name == "":
		return q, rules.Resolution{}
	case len(q.Addr) > 0:
		return q, rules.Resolution{Note: "the query already carries an address"}
	case st.resolver == nil:
		return q, rules.Resolution{Note: "no resolver is configured"}
	}
	if namer, ok := st.matcher.(resolutionNamer); ok && !namer.NeedsResolution() {
		return q, rules.Resolution{Note: "no address rule can use a resolved address"}
	}
	res, err := st.resolver.Resolve(ctx, q.Name)
	if err != nil {
		// A failed lookup is not a failed request: domain rules still apply and
		// an outbound that resolves remotely may still reach the destination.
		// The dial decides, and the dial has its own error mapping.
		return q, rules.Resolution{Err: err.Error()}
	}
	if len(res.IPs) == 0 {
		return q, rules.Resolution{Err: "the resolver returned no address"}
	}
	q.Addr = res.IPs[0]
	q.Resolved = true
	return q, rules.Resolution{Source: string(res.Source), Addrs: res.IPs}
}

// route classifies the destination and resolves the target the rule chose.
func (h *Handler) route(ctx context.Context, st *handlerState, req Request) (Selection, outbound.Dialer, error) {
	var sel Selection
	if req.Network != networkTCP && req.Network != networkUDP {
		return sel, nil, fmt.Errorf("inbound: %q is neither tcp nor udp", req.Network)
	}
	query := rules.Query{Port: int(req.Target.Port), Network: req.Network}
	if ip := net.ParseIP(req.Target.Host); ip != nil {
		query.Addr = ip
	} else {
		query.Name = req.Target.Host
		var resolution rules.Resolution
		query, resolution = h.prepare(ctx, st, query)
		if resolution.Source != "" || resolution.Err != "" {
			h.logger.Debug("destination name resolved",
				"host", req.Target.Host, "source", resolution.Source,
				"addresses", len(resolution.Addrs), "error", resolution.Err)
		}
	}
	decision, ok := st.matcher.Match(query)
	if !ok {
		// Only a program without FINAL can get here, and a program without
		// FINAL does not compile in the daemon. Refusing beats guessing.
		return sel, nil, fmt.Errorf("inbound: no rule matched %s", req.Target)
	}
	sel = Selection{Rule: decision.Rule, Target: decision.Target}

	dialer, path, err := st.router.Route(decision.Target)
	sel.Path = path
	if err != nil {
		return sel, nil, err
	}
	h.logger.Debug("request routed",
		"target", req.Target.String(), "network", req.Network,
		"rule", decision.Rule.String(), "policy", decision.Target, "path", path)
	return sel, dialer, nil
}

// failed reports a dial failure to the groups that chose the member.
//
// A rejected destination is not a failure: the rule did its job, and marking
// the member down for it would make a REJECT rule look like a broken proxy. It
// is still recorded, because an operator chasing a client has to be able to see
// that a rule was the reason the connection did not happen.
//
// The failure goes to the router of the configuration the request was routed
// with, not to whichever configuration is current by the time the dial times
// out: the path names members of the old registry, and reporting them to a
// freshly loaded one would blame the wrong group.
func (h *Handler) failed(st *handlerState, req Request, sel Selection, err error) {
	h.record(req, sel, StageDial, err)
	if errors.Is(err, outbound.ErrRejected) {
		h.logger.Debug("request rejected by rule",
			"target", req.Target.String(), "rule", sel.Rule.String())
		return
	}
	h.logger.Warn("outbound failed",
		"target", req.Target.String(), "network", req.Network,
		"policy", sel.Target, "path", sel.Path, "error", err)
	st.router.Failed(sel.Path)
}

// record keeps one failure for the local API.
//
// Only the destination, the stage, the category and the policy are stored: this
// layer never touches the payload of a connection, and the error itself is
// reduced to a category so a record cannot grow with a message a peer chose.
func (h *Handler) record(req Request, sel Selection, stage string, err error) {
	if h.metrics == nil {
		return
	}
	h.metrics.Record(Failure{
		Time:     time.Now(),
		Target:   req.Target.String(),
		Network:  req.Network,
		Stage:    stage,
		Category: categorize(stage, err),
		Policy:   sel.Target,
	})
}

// PolicyRouter connects the pipeline to the policy registry and the outbound
// dialers the daemon assembled.
type PolicyRouter struct {
	registry *policy.Registry
	dialers  *outbound.Set
}

// NewPolicyRouter builds the router the daemon hands to a Handler.
func NewPolicyRouter(registry *policy.Registry, dialers *outbound.Set) (*PolicyRouter, error) {
	if registry == nil {
		return nil, errors.New("inbound: a policy registry is required")
	}
	if dialers == nil {
		return nil, errors.New("inbound: an outbound set is required")
	}
	return &PolicyRouter{registry: registry, dialers: dialers}, nil
}

// Route implements Router. The resolution follows nested groups to their
// current member, so the path it returns is what a failure has to travel back
// along.
func (r *PolicyRouter) Route(target string) (outbound.Dialer, []string, error) {
	resolution, err := r.registry.Resolve(target)
	if err != nil {
		return nil, nil, err
	}
	dialer, err := r.dialers.Dialer(resolution.Leaf)
	if err != nil {
		return nil, resolution.Path, err
	}
	return dialer, resolution.Path, nil
}

// Failed implements Router: every group on the path is told that the member it
// selected could not carry the request.
func (r *PolicyRouter) Failed(path []string) {
	for i := 0; i+1 < len(path); i++ {
		if group, ok := r.registry.Group(path[i]); ok {
			group.NotifyFailure(path[i+1])
		}
	}
}
