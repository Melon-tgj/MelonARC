package subscription

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// maxBodySize bounds what a subscription may return. Providers send a few
// kilobytes of base64; four megabytes is far above any real list and low enough
// that a wrong URL pointing at a file cannot exhaust memory.
const maxBodySize = 4 << 20

// userAgent identifies this client to a provider. It is the product name and
// nothing else: a subscription server is entitled to know what is asking.
const userAgent = "melonarc"

// newHTTPClient builds the client used for fetches. The timeout covers the whole
// request, and the transport keeps connections alive between refreshes so a
// scheduled update does not pay for a handshake it does not need.
func newHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 15 * time.Second,
			IdleConnTimeout:       90 * time.Second,
			MaxIdleConnsPerHost:   2,
		},
	}
}

// fetch downloads one subscription body.
func (m *Manager) fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("the url cannot be requested: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "*/*")

	resp, err := m.opts.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// The body of an error response is not read: it is not a node list, and
		// a provider's error page can be large.
		return nil, fmt.Errorf("the server answered %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize+1))
	if err != nil {
		return nil, fmt.Errorf("reading the body: %w", err)
	}
	if len(body) > maxBodySize {
		return nil, fmt.Errorf("the body is larger than %d bytes", maxBodySize)
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		return nil, fmt.Errorf("the body is empty")
	}
	return body, nil
}

// decodeSubscription returns the link list as text. Providers serve it either
// base64 encoded (the original convention) or as plain text, so the body is
// decoded when it decodes to something that looks like links and used as-is
// otherwise.
func decodeSubscription(body []byte) string {
	text := strings.TrimSpace(string(body))
	if text == "" {
		return ""
	}
	if decoded, err := decodeBase64Text(text); err == nil && strings.Contains(string(decoded), "://") {
		return string(decoded)
	}
	return text
}

// decodeBase64Text accepts the alphabets and paddings seen in the wild. Line
// breaks inside the body are removed first: a wrapped base64 list is common.
func decodeBase64Text(text string) ([]byte, error) {
	compact := strings.Map(func(r rune) rune {
		switch r {
		case '\r', '\n', ' ', '\t':
			return -1
		}
		return r
	}, text)
	for _, encoding := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if decoded, err := encoding.DecodeString(compact); err == nil {
			return decoded, nil
		}
	}
	return nil, fmt.Errorf("the body is not base64")
}

// splitLines splits a body into lines, tolerating both line endings.
func splitLines(text string) []string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	return strings.Split(text, "\n")
}

// trimLine removes the surrounding space a provider may have added.
func trimLine(line string) string {
	return strings.TrimSpace(strings.TrimPrefix(line, "\ufeff"))
}

// isComment reports whether a line is a comment. Both spellings are used by
// subscription servers to carry a title or a quota notice.
func isComment(line string) bool {
	return strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//")
}
