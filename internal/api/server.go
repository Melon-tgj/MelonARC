package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// DefaultAddr is the address the local API binds to when none is configured.
const DefaultAddr = "127.0.0.1:7946"

// tokenBytes is the amount of randomness in a generated token. 32 bytes carry
// 256 bits, which makes guessing pointless.
const tokenBytes = 32

// handlerTimeout bounds how long a provider call may take.
const handlerTimeout = 10 * time.Second

// maxRulePage bounds the number of rules a single response carries.
const maxRulePage = 5000

// Options configures a Server.
type Options struct {
	// Addr is the listen address. It must be a loopback address; empty means
	// DefaultAddr.
	Addr string
	// Token is the shared secret clients must present. Empty means a random
	// token is generated.
	Token string
	// Provider supplies the state the endpoints serve.
	Provider Provider
	// Version is reported by the status and health endpoints.
	Version string
}

// Server is the loopback-only HTTP API. It is created with New, which binds the
// listener, and started with Start.
type Server struct {
	provider Provider
	version  string
	token    string
	listener net.Listener
	http     *http.Server
	started  time.Time
}

// New validates the options, binds the listener and returns a server that is
// ready to Start.
func New(opts Options) (*Server, error) {
	if opts.Provider == nil {
		return nil, errors.New("api: a provider is required")
	}
	addr := opts.Addr
	if addr == "" {
		addr = DefaultAddr
	}
	if err := checkLoopback(addr); err != nil {
		return nil, err
	}
	token := opts.Token
	if token == "" {
		var err error
		if token, err = newToken(); err != nil {
			return nil, err
		}
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("api: listen on %s: %w", addr, err)
	}
	s := &Server{
		provider: opts.Provider,
		version:  opts.Version,
		token:    token,
		listener: ln,
		started:  time.Now(),
	}
	s.http = &http.Server{
		Handler:           s.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          nil,
	}
	return s, nil
}

// checkLoopback rejects anything but a loopback listen address, which is the
// property that keeps the API off the network.
func checkLoopback(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("api: %q is not a host:port address: %w", addr, err)
	}
	if port == "" {
		return fmt.Errorf("api: %q has no port", addr)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 0 || n > 65535 {
		return fmt.Errorf("api: %q has an invalid port", addr)
	}
	if host == "" {
		return fmt.Errorf("api: %q would listen on every interface; a loopback address is required", addr)
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("api: %q is not an IP address", host)
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("api: %q is not a loopback address", host)
	}
	return nil
}

// newToken returns a fresh random token.
func newToken() (string, error) {
	buf := make([]byte, tokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("api: generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// Token returns the token clients must present.
func (s *Server) Token() string { return s.token }

// Addr returns the address the server is bound to, with the real port when the
// requested port was 0.
func (s *Server) Addr() string { return s.listener.Addr().String() }

// URL returns the base URL of the API.
func (s *Server) URL() string { return "http://" + s.Addr() }

// Start serves requests in the background. The returned channel is closed when
// the server stops.
func (s *Server) Start() <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = s.http.Serve(s.listener)
	}()
	return done
}

// Serve serves requests and blocks until the server stops.
func (s *Server) Serve() error {
	err := s.http.Serve(s.listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Close stops the server and releases the listener.
func (s *Server) Close(ctx context.Context) error {
	err := s.http.Shutdown(ctx)
	if cerr := s.listener.Close(); cerr != nil && !errors.Is(cerr, net.ErrClosed) && err == nil {
		err = cerr
	}
	return err
}

// routes builds the HTTP handler tree.
func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.only(http.MethodGet, s.handleHealth))
	mux.HandleFunc("/v1/status", s.only(http.MethodGet, s.handleStatus))
	mux.HandleFunc("/v1/config", s.only(http.MethodGet, s.handleConfig))
	mux.HandleFunc("/v1/rules", s.only(http.MethodGet, s.handleRules))
	mux.HandleFunc("/v1/rules/explain", s.only(http.MethodGet, s.handleExplain))
	mux.HandleFunc("/v1/policies", s.only(http.MethodGet, s.handlePolicies))
	mux.HandleFunc("/", s.handleNotFound)
	return s.withAuth(mux)
}

// withAuth rejects any request that does not carry the token.
func (s *Server) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.authorised(r) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="melonarc"`)
			writeError(w, http.StatusUnauthorized, "unauthorized", "a valid bearer token is required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// authorised compares the presented token in constant time.
func (s *Server) authorised(r *http.Request) bool {
	header := r.Header.Get("Authorization")
	const prefix = "bearer "
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return false
	}
	token := strings.TrimSpace(header[len(prefix):])
	return subtle.ConstantTimeCompare([]byte(token), []byte(s.token)) == 1
}

// only wraps a handler so that other methods get a JSON 405 instead of the
// plain text one the mux would produce.
func (s *Server) only(method string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			w.Header().Set("Allow", method)
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed",
				fmt.Sprintf("%s expects %s", r.URL.Path, method))
			return
		}
		next(w, r)
	}
}

func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotFound, "not_found", "no such endpoint: "+r.URL.Path)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, HealthView{
		Status:        "ok",
		Version:       s.version,
		UptimeSeconds: time.Since(s.started).Seconds(),
	})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), handlerTimeout)
	defer cancel()
	st := s.provider.Status(ctx)
	if st.Version == "" {
		st.Version = s.version
	}
	if st.StartedAt.IsZero() {
		st.StartedAt = s.started
	}
	if st.UptimeSeconds == 0 {
		st.UptimeSeconds = time.Since(s.started).Seconds()
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), handlerTimeout)
	defer cancel()
	writeJSON(w, http.StatusOK, s.provider.Config(ctx))
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	limit, err := parseLimit(r.URL.Query().Get("limit"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), handlerTimeout)
	defer cancel()
	writeJSON(w, http.StatusOK, s.provider.Rules(ctx, limit))
}

func (s *Server) handlePolicies(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), handlerTimeout)
	defer cancel()
	policies := s.provider.Policies(ctx)
	if policies == nil {
		policies = []PolicyView{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"policies": policies})
}

func (s *Server) handleExplain(w http.ResponseWriter, r *http.Request) {
	req, err := parseExplainRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), handlerTimeout)
	defer cancel()
	view, err := s.provider.Explain(ctx, req)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "explain_failed", err.Error())
		return
	}
	if view.Steps == nil {
		view.Steps = []StepView{}
	}
	writeJSON(w, http.StatusOK, view)
}

// parseLimit reads the optional limit parameter.
func parseLimit(raw string) (int, error) {
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("limit %q is not a non-negative number", raw)
	}
	if n > maxRulePage {
		return 0, fmt.Errorf("limit %d is above the maximum of %d", n, maxRulePage)
	}
	return n, nil
}

// parseExplainRequest validates the classifier inputs.
func parseExplainRequest(r *http.Request) (ExplainRequest, error) {
	q := r.URL.Query()
	req := ExplainRequest{
		Name:    strings.TrimSpace(q.Get("name")),
		Addr:    strings.TrimSpace(q.Get("addr")),
		Network: strings.ToLower(strings.TrimSpace(q.Get("network"))),
	}
	if raw := strings.TrimSpace(q.Get("port")); raw != "" {
		port, err := strconv.Atoi(raw)
		if err != nil || port < 1 || port > 65535 {
			return req, fmt.Errorf("port %q is outside 1-65535", raw)
		}
		req.Port = port
	}
	if req.Addr != "" && net.ParseIP(req.Addr) == nil {
		return req, fmt.Errorf("addr %q is not an IP address", req.Addr)
	}
	switch req.Network {
	case "", "tcp", "udp":
	default:
		return req, fmt.Errorf("network %q is neither tcp nor udp", req.Network)
	}
	if req.Name == "" && req.Addr == "" && req.Port == 0 && req.Network == "" {
		return req, errors.New("give at least one of name, addr, port or network")
	}
	return req, nil
}

// writeJSON writes a JSON response.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

// errorView is the shape of every error response.
type errorView struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, code, message string) {
	var body errorView
	body.Error.Code = code
	body.Error.Message = message
	writeJSON(w, status, body)
}
