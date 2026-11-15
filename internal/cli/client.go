package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/melon-tgj/melonarc/internal/api"
	"github.com/melon-tgj/melonarc/internal/datadir"
)

// Environment variables that override a flag, for a shell that talks to a core
// started with a non-default address.
const (
	envAPI   = "MELONARC_API"
	envToken = "MELONARC_TOKEN"
)

// maxErrorBody bounds the body of an error answer that is repeated to the user.
const maxErrorBody = 64 << 10

// APIError is an error answer from the core: the status it answered with and the
// JSON error body, when there was one.
type APIError struct {
	Status  int
	Code    string
	Message string
}

// Error implements error.
func (e *APIError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("the core answered %d: %s", e.Status, e.Message)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// client talks to the local API of one core.
type client struct {
	base string
	// tokenPath is where the token came from, empty when it came from a flag or
	// the environment. It is only used to make an authentication failure
	// actionable.
	tokenPath string
	token     string
	http      *http.Client
}

// apiTarget is a fully validated local API address. base is the only URL the
// client builds requests against; dial is the one socket address the transport
// may open. Both name a canonical IP literal, so no host name is resolved (or
// re-resolved) after validation and the bearer token cannot be steered off
// this machine by a DNS answer that changes between check and connect.
type apiTarget struct {
	base string
	dial string
}

// lookupHost resolves localhost. It is a variable so a test can pin the answer
// and prove that a non-loopback result is refused.
var lookupHost = func(ctx context.Context, host string) ([]net.IPAddr, error) {
	return net.DefaultResolver.LookupIPAddr(ctx, host)
}

// apiBase resolves the base URL of the core: the flag, then the environment,
// then the address the core listens on by default. A bare host:port is accepted
// because that is what the startup line of the daemon prints.
func apiBase(raw string) (string, error) {
	target, err := resolveAPITarget(raw)
	if err != nil {
		return "", err
	}
	return target.base, nil
}

// resolveAPITarget accepts only a plaintext HTTP origin on a loopback IP.
// User information, paths, queries and other schemes are refused, as are host
// names other than localhost: a request carrying the bearer token must not be
// steerable to another listener. IPv6 is written in its canonical bracket form.
func resolveAPITarget(raw string) (apiTarget, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		value = strings.TrimSpace(os.Getenv(envAPI))
	}
	if value == "" {
		value = api.DefaultAddr
	}
	if !strings.Contains(value, "://") {
		value = "http://" + value
	}
	u, err := url.Parse(value)
	if err != nil || u.Host == "" {
		return apiTarget{}, fmt.Errorf("%q is neither a URL nor a host:port address of the core", value)
	}
	if u.Scheme != "http" {
		return apiTarget{}, fmt.Errorf("%q uses %q, the local API answers over plain http", value, u.Scheme)
	}
	if u.User != nil {
		return apiTarget{}, fmt.Errorf("%q must not carry user information", value)
	}
	if u.Path != "" && u.Path != "/" {
		return apiTarget{}, fmt.Errorf("%q must be a bare origin, without a path", value)
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return apiTarget{}, fmt.Errorf("%q must be a bare origin, without a query or fragment", value)
	}
	port := u.Port()
	if port == "" {
		return apiTarget{}, fmt.Errorf("%q has no port", value)
	}
	ip, err := loopbackIP(u.Hostname())
	if err != nil {
		return apiTarget{}, err
	}
	// JoinHostPort brackets an IPv6 literal, so the URL and the socket address
	// share one canonical form.
	authority := net.JoinHostPort(ip.String(), port)
	return apiTarget{base: "http://" + authority, dial: authority}, nil
}

// loopbackIP validates a host by IP type, not by a textual prefix. An IP
// literal must be loopback; localhost is resolved and every answer must be
// loopback before one is chosen; every other name could resolve remotely and
// is refused.
func loopbackIP(host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if !ip.IsLoopback() {
			return nil, fmt.Errorf("%q is not a loopback address; the API token never leaves this machine", host)
		}
		return ip, nil
	}
	if !strings.EqualFold(host, "localhost") {
		return nil, fmt.Errorf("%q is neither a loopback IP nor localhost; the API token never leaves this machine", host)
	}
	answers, err := lookupHost(context.Background(), "localhost")
	if err != nil {
		return nil, fmt.Errorf("resolve localhost: %w", err)
	}
	var chosen net.IP
	for _, answer := range answers {
		if !answer.IP.IsLoopback() {
			return nil, fmt.Errorf("localhost resolved to %s, which is not loopback; refusing to send the API token", answer.IP)
		}
		// Prefer IPv4: the core binds 127.0.0.1 by default.
		if chosen == nil || (chosen.To4() == nil && answer.IP.To4() != nil) {
			chosen = answer.IP
		}
	}
	if chosen == nil {
		return nil, fmt.Errorf("localhost resolved to no address")
	}
	return chosen, nil
}

// dataDirPath resolves the data directory of the core: the flag, then the
// default. A relative value is resolved against the working directory, which is
// what a user typing it expects.
func dataDirPath(explicit string) (string, error) {
	base, err := os.Getwd()
	if err != nil {
		base = ""
	}
	return datadir.Resolve(base, explicit)
}

// tokenFileFor returns the token file a client should read.
func tokenFileFor(explicitFile, dataDir string) (string, error) {
	if file := strings.TrimSpace(explicitFile); file != "" {
		abs, err := filepath.Abs(file)
		if err != nil {
			return "", fmt.Errorf("resolve %s: %w", file, err)
		}
		return abs, nil
	}
	dir, err := dataDirPath(dataDir)
	if err != nil {
		return "", err
	}
	return datadir.TokenPath(dir), nil
}

// newClient builds a client, reading the token from the flag, the environment or
// the token file in that order.
func newClient(o *options) (*client, error) {
	target, err := resolveAPITarget(o.api)
	if err != nil {
		return nil, err
	}
	// A credentialed request must not be redirected or relayed: either could
	// carry the bearer token to a listener we never validated. Pin the dial to
	// the verified address, disable the environment proxy and refuse redirects.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, network, target.dial)
	}
	c := &client{
		base: target.base,
		http: &http.Client{
			Timeout:   o.timeout,
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
	if token := strings.TrimSpace(o.token); token != "" {
		c.token = token
		return c, nil
	}
	if token := strings.TrimSpace(os.Getenv(envToken)); token != "" {
		c.token = token
		return c, nil
	}
	path, err := tokenFileFor(o.tokenFile, o.dataDir)
	if err != nil {
		return nil, err
	}
	token, err := datadir.ReadTokenFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("no API token at %s\n"+
				"start melonarc-core first (it writes the token when it starts), or pass -token / -token-file", path)
		}
		return nil, fmt.Errorf("cannot read the API token: %w", err)
	}
	c.token, c.tokenPath = token, path
	return c, nil
}

// get reads one endpoint into out.
func (c *client) get(ctx context.Context, path string, out any) error {
	return c.do(ctx, http.MethodGet, path, nil, out)
}

// post sends one write request and decodes the answer into out.
func (c *client) post(ctx context.Context, path string, body, out any) error {
	return c.do(ctx, http.MethodPost, path, body, out)
}

// do performs one request. Every failure is turned into a message a user can act
// on: the core is not running, the token is stale, or the core refused the
// request for a reason it named.
func (c *client) do(ctx context.Context, method, path string, body, out any) error {
	var payload io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode the request: %w", err)
		}
		payload = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, payload)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return c.transportError(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return c.unauthorised()
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return decodeAPIError(resp)
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("the core answered %d with a body this client does not understand: %w", resp.StatusCode, err)
	}
	return nil
}

// transportError explains why the core could not be reached.
func (c *client) transportError(err error) error {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("the core at %s did not answer in time", c.base)
	case errors.Is(err, context.Canceled):
		return errors.New("the request was cancelled")
	case errors.Is(err, os.ErrDeadlineExceeded):
		return fmt.Errorf("the core at %s did not answer in time", c.base)
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "dial" {
		return fmt.Errorf("no core is listening at %s\n"+
			"start it with: melonarc-core -config <path to the configuration>", c.base)
	}
	return fmt.Errorf("cannot talk to the core at %s: %w", c.base, err)
}

// unauthorised explains a rejected token. The daemon generates a new token on
// every start, so a stale file is the most likely cause and the message says so.
func (c *client) unauthorised() error {
	if c.tokenPath == "" {
		return errors.New("the core rejected the token\n" +
			"it generates a new one on every start; read it from the API token of the core, or pass -token")
	}
	return fmt.Errorf("the core rejected the token at %s\n"+
		"it generates a new one on every start, so that file is from a previous run; "+
		"restart the CLI after the core writes the current one, or pass -token", c.tokenPath)
}

// decodeAPIError reads the JSON error body of a failed request.
func decodeAPIError(resp *http.Response) error {
	data, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(data, &body); err == nil && body.Error.Message != "" {
		return &APIError{Status: resp.StatusCode, Code: body.Error.Code, Message: body.Error.Message}
	}
	text := strings.TrimSpace(string(data))
	if text == "" {
		text = http.StatusText(resp.StatusCode)
	}
	return &APIError{Status: resp.StatusCode, Message: text}
}
