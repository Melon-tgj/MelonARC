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

// apiBase resolves the base URL of the core: the flag, then the environment,
// then the address the core listens on by default. A bare host:port is accepted
// because that is what the startup line of the daemon prints.
func apiBase(raw string) (string, error) {
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
		return "", fmt.Errorf("%q is neither a URL nor a host:port address of the core", value)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("%q uses %q, the core answers over http", value, u.Scheme)
	}
	return strings.TrimSuffix(u.String(), "/"), nil
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
	base, err := apiBase(o.api)
	if err != nil {
		return nil, err
	}
	c := &client{
		base: base,
		http: &http.Client{Timeout: o.timeout},
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
