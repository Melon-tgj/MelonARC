package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/melon-tgj/melonarc/internal/config"
	"github.com/melon-tgj/melonarc/internal/geoip"
	"github.com/melon-tgj/melonarc/internal/geoip/geoiptest"
	"github.com/melon-tgj/melonarc/internal/rules"
)

// testDNSServer answers A questions for one name over TCP. The datagram side is
// left unbound on purpose: the client's datagram attempt is refused at once and
// the answer has to arrive over the stream, which is the transport fallback in
// action.
type testDNSServer struct {
	addr  string
	mu    sync.Mutex
	asked []string
}

// startTestDNSServer starts the server. An empty answer makes every question
// negative, which is how a resolver that knows nothing behaves.
func startTestDNSServer(t *testing.T, name string, answer net.IP) *testDNSServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen dns: %v", err)
	}
	server := &testDNSServer{addr: listener.Addr().String()}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				var length uint16
				if err := binary.Read(io.LimitReader(c, 2), binary.BigEndian, &length); err != nil {
					return
				}
				query := make([]byte, length)
				if _, err := io.ReadFull(c, query); err != nil {
					return
				}
				reply, asked, ok := buildDNSReply(query, name, answer)
				if !ok {
					return
				}
				server.mu.Lock()
				server.asked = append(server.asked, asked)
				server.mu.Unlock()
				header := make([]byte, 2, 2+len(reply))
				binary.BigEndian.PutUint16(header, uint16(len(reply)))
				_, _ = c.Write(append(header, reply...))
			}(conn)
		}
	}()
	return server
}

// questions returns the names the server was asked for.
func (s *testDNSServer) questions() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.asked...)
}

// buildDNSReply answers one question with a single A record, or with no record
// at all when the name or the record type does not match.
func buildDNSReply(query []byte, name string, answer net.IP) ([]byte, string, bool) {
	if len(query) < 12 {
		return nil, "", false
	}
	off := 12
	var labels []string
	for off < len(query) && query[off] != 0 {
		length := int(query[off])
		if off+1+length > len(query) {
			return nil, "", false
		}
		labels = append(labels, string(query[off+1:off+1+length]))
		off += 1 + length
	}
	if off+5 > len(query) {
		return nil, "", false
	}
	questionEnd := off + 5
	asked := strings.Join(labels, ".")
	qtype := binary.BigEndian.Uint16(query[off+1 : off+3])

	reply := make([]byte, 12, 12+questionEnd-12+16)
	copy(reply[0:2], query[0:2])
	binary.BigEndian.PutUint16(reply[2:4], 0x8180) // response, recursion available
	binary.BigEndian.PutUint16(reply[4:6], 1)
	answerCount := 0
	if asked == name && qtype == 1 && answer != nil {
		answerCount = 1
	}
	binary.BigEndian.PutUint16(reply[6:8], uint16(answerCount))
	reply = append(reply, query[12:questionEnd]...)
	if answerCount == 1 {
		reply = append(reply, 0xc0, 0x0c)
		reply = binary.BigEndian.AppendUint16(reply, 1) // A
		reply = binary.BigEndian.AppendUint16(reply, 1) // IN
		reply = binary.BigEndian.AppendUint32(reply, 60)
		reply = binary.BigEndian.AppendUint16(reply, 4)
		reply = append(reply, answer.To4()...)
	}
	return reply, asked, true
}

// mustConfig parses and validates a configuration or fails the test.
func mustConfig(t *testing.T, raw string) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	return cfg
}

// compileTestRules compiles a configuration and releases the data set handles it
// opened when the test ends. A database file stays mapped while its handle is
// open, and a mapped file cannot be removed on every platform, so leaving the
// handles to the end of the process would make the temporary directory cleanup
// fail on Windows.
func compileTestRules(t *testing.T, cfg *config.Config) *rules.Program {
	t.Helper()
	datasets := geoip.NewCache()
	t.Cleanup(datasets.Close)
	program, err := compileRules(cfg, datasets, testLogger())
	if err != nil {
		t.Fatalf("compileRules: %v", err)
	}
	return program
}

// TestPipelineResolvesThroughTheConfiguredUpstream is the end to end check of the
// plaintext upstream: a name that exists only in the test server is resolved
// through the configured server, the address it answered matches an IP rule, and
// the connection reaches the origin. Without the upstream the name would stay a
// name, fall through to the final rule and be rejected.
func TestPipelineResolvesThroughTheConfiguredUpstream(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "resolved through the upstream")
	}))
	defer origin.Close()
	originPort := portOf(t, strings.TrimPrefix(origin.URL, "http://"))

	dnsServer := startTestDNSServer(t, "routed.test", net.IPv4(127, 0, 0, 1))
	httpPort := freePort(t)
	raw := fmt.Sprintf(`[General]
log-level = error
http-listen = 127.0.0.1:%d
socks5-listen = off
dns-nameserver = %s
dns-fallback = none

[Rule]
IP-CIDR,127.0.0.1/32,DIRECT
FINAL,REJECT
`, httpPort, dnsServer.addr)
	cfg := mustConfig(t, raw)

	resolver, err := buildResolver(cfg)
	if err != nil {
		t.Fatalf("buildResolver: %v", err)
	}
	program := compileTestRules(t, cfg)
	dialers, err := buildDialers(cfg, resolver, testLogger())
	if err != nil {
		t.Fatalf("buildDialers: %v", err)
	}
	registry, err := buildRegistry(cfg, dialers)
	if err != nil {
		t.Fatalf("buildRegistry: %v", err)
	}
	t.Cleanup(registry.Close)
	handler, err := buildHandler(program, registry, dialers, resolver, nil, testLogger())
	if err != nil {
		t.Fatalf("buildHandler: %v", err)
	}
	services, err := startInbounds(cfg.General, handler, nil, testLogger())
	if err != nil {
		t.Fatalf("startInbounds: %v", err)
	}
	t.Cleanup(func() { closeInbounds(services, testLogger()) })

	proxyURL, err := url.Parse("http://" + services[0].Addr())
	if err != nil {
		t.Fatalf("proxy url: %v", err)
	}
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   10 * time.Second,
	}
	resp, err := client.Get("http://routed.test:" + strconv.Itoa(originPort) + "/")
	if err != nil {
		t.Fatalf("get through the proxy: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200: the name did not resolve through the upstream", resp.StatusCode)
	}
	if !strings.Contains(string(body), "resolved through the upstream") {
		t.Fatalf("body = %q, want the origin text", body)
	}
	if asked := dnsServer.questions(); len(asked) == 0 {
		t.Fatal("the upstream was never asked")
	}

	// The answer is cached, so a second request does not ask again.
	before := len(dnsServer.questions())
	if _, err := client.Get("http://routed.test:" + strconv.Itoa(originPort) + "/"); err != nil {
		t.Fatalf("second get: %v", err)
	}
	if after := len(dnsServer.questions()); after != before {
		t.Fatalf("questions = %d after a second request, want %d: the answer was not reused", after, before)
	}
}

// TestGeoIPRuleMatchesTheConfiguredDatabase is the end to end check of the mmdb
// loader: the same rule routes differently depending on what the data file says
// about the destination, which is the only way to tell the database apart from a
// rule that always or never matches.
func TestGeoIPRuleMatchesTheConfiguredDatabase(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "origin")
	}))
	defer origin.Close()
	target := "127.0.0.1:" + strconv.Itoa(portOf(t, strings.TrimPrefix(origin.URL, "http://")))

	tests := []struct {
		name       string
		country    string
		wantStatus int
	}{
		{name: "database says the country matches", country: "ZZ", wantStatus: http.StatusForbidden},
		{name: "database says another country", country: "YY", wantStatus: http.StatusOK},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data, err := geoiptest.Country(map[string][]string{tc.country: {"127.0.0.0/8"}})
			if err != nil {
				t.Fatalf("build fixture: %v", err)
			}
			path := filepath.Join(t.TempDir(), "country.mmdb")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatalf("write fixture: %v", err)
			}
			raw := fmt.Sprintf(`[General]
log-level = error
http-listen = 127.0.0.1:%d
socks5-listen = off
geoip-db = %s

[Rule]
GEOIP,ZZ,REJECT
FINAL,DIRECT
`, freePort(t), path)
			_, services := wireDaemon(t, mustConfig(t, raw))
			if status := connectThrough(t, services[0].Addr(), target); status != tc.wantStatus {
				t.Fatalf("status = %d, want %d", status, tc.wantStatus)
			}
		})
	}
}

// TestCompileRulesReportsAnUnusableDatabase checks that a data file which cannot
// be used stops the configuration with a message that names the setting and the
// file, instead of leaving a rule that silently matches nothing.
func TestCompileRulesReportsAnUnusableDatabase(t *testing.T) {
	dir := t.TempDir()
	broken := filepath.Join(dir, "broken.mmdb")
	if err := os.WriteFile(broken, []byte("not a database"), 0o600); err != nil {
		t.Fatalf("write broken file: %v", err)
	}
	tests := []struct {
		name string
		path string
		want string
	}{
		{name: "missing", path: filepath.Join(dir, "absent.mmdb"), want: "does not exist"},
		{name: "corrupt", path: broken, want: "not usable"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := fmt.Sprintf(`[General]
log-level = error
geoip-db = %s

[Rule]
GEOIP,ZZ,DIRECT
FINAL,DIRECT
`, tc.path)
			cfg := mustConfig(t, raw)
			_, err := compileRules(cfg, geoip.NewCache(), testLogger())
			if err == nil {
				t.Fatal("compileRules accepted the data file")
			}
			if !strings.Contains(err.Error(), "geoip-db") || !strings.Contains(err.Error(), tc.path) {
				t.Fatalf("error = %v, want the setting and the path in it", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q in it", err, tc.want)
			}
		})
	}
}

// TestConfigViewReportsTheDataSources checks what the API says about the new
// settings: the upstream servers, the fallback, and where the data files are.
func TestConfigViewReportsTheDataSources(t *testing.T) {
	dir := t.TempDir()
	raw := fmt.Sprintf(`[General]
log-level = error
dns-nameserver = 1.1.1.1, 9.9.9.9:5353
dns-fallback = none
geoip-db = %s
asn-db = ./asn.mmdb

[Rule]
FINAL,DIRECT
`, filepath.Join(dir, "country.mmdb"))
	cfg := mustConfig(t, raw)
	cfg.BaseDir = dir
	state := &daemonState{cfg: cfg, startedAt: time.Now()}
	view := state.Config(t.Context())
	if len(view.NameServers) != 2 || view.NameServers[0] != "1.1.1.1" || view.NameServers[1] != "9.9.9.9:5353" {
		t.Fatalf("nameservers = %v", view.NameServers)
	}
	if view.DNSFallback != config.DNSFallbackNone {
		t.Fatalf("fallback = %q, want %q", view.DNSFallback, config.DNSFallbackNone)
	}
	if view.GeoIPDB != filepath.Join(dir, "country.mmdb") {
		t.Fatalf("geoip db = %q, want the configured path", view.GeoIPDB)
	}
	if view.ASNDB != filepath.Join(dir, "asn.mmdb") {
		t.Fatalf("asn db = %q, want the path resolved against the configuration directory", view.ASNDB)
	}
}
