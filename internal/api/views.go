package api

import (
	"context"
	"time"
)

// The view types below are the wire format of the local API. They are defined
// here rather than reusing the internal structs so that the JSON contract can
// stay stable while the daemon internals change, and so that no field that was
// not meant to leave the process is ever marshalled.

// StatusView is the daemon status.
type StatusView struct {
	Version       string    `json:"version"`
	StartedAt     time.Time `json:"started_at"`
	UptimeSeconds float64   `json:"uptime_seconds"`
	ConfigPath    string    `json:"config_path,omitempty"`
	RuleCount     int       `json:"rule_count"`
	PolicyCount   int       `json:"policy_count"`
}

// HealthView answers the health check.
type HealthView struct {
	Status        string  `json:"status"`
	Version       string  `json:"version"`
	UptimeSeconds float64 `json:"uptime_seconds"`
}

// ConfigView is the configuration as the API exposes it. Credentials are not
// part of it: a proxy is reduced to its name, type, server and port. The [Host]
// table is reduced to its size for the same reason: a local name mapping says
// which internal service the machine talks to, and the API is readable by any
// process that holds the token.
type ConfigView struct {
	Path         string        `json:"path,omitempty"`
	LogLevel     string        `json:"log_level"`
	APIListen    string        `json:"api_listen,omitempty"`
	HTTPListen   string        `json:"http_listen,omitempty"`
	SOCKS5Listen string        `json:"socks5_listen,omitempty"`
	Proxies      []ProxyView   `json:"proxies"`
	Groups       []GroupView   `json:"groups"`
	RuleSets     []RuleSetView `json:"rule_sets"`
	HostCount    int           `json:"host_count"`
	// NameServers are the configured plaintext DNS servers, in the order they
	// are asked. An empty list means the system resolver answers.
	NameServers []string `json:"dns_nameserver"`
	// DNSFallback says what happens when every server failed: "system" asks the
	// system resolver, "none" fails the lookup. It is always reported spelled
	// out, so a client does not have to know the default.
	DNSFallback string `json:"dns_fallback,omitempty"`
	// GeoIPDB and ASNDB are the data files the address rules read. They are
	// paths, not secrets; the records inside them are not part of the view.
	GeoIPDB string `json:"geoip_db,omitempty"`
	ASNDB   string `json:"asn_db,omitempty"`
}

// ProxyView is one outbound as exposed by the API.
type ProxyView struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Server string `json:"server"`
	Port   int    `json:"port"`
}

// GroupView is one policy group as declared in the configuration.
type GroupView struct {
	Name            string   `json:"name"`
	Type            string   `json:"type"`
	Members         []string `json:"members"`
	URL             string   `json:"url,omitempty"`
	IntervalSeconds int      `json:"interval_seconds,omitempty"`
}

// RuleSetView is one declared external rule set.
type RuleSetView struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

// RuleView is one compiled rule.
type RuleView struct {
	Index     int    `json:"index"`
	Type      string `json:"type"`
	Payload   string `json:"payload,omitempty"`
	Target    string `json:"target"`
	Source    string `json:"source,omitempty"`
	Line      int    `json:"line,omitempty"`
	NoResolve bool   `json:"no_resolve,omitempty"`
}

// RuleListView is a page of compiled rules.
type RuleListView struct {
	Total int        `json:"total"`
	Limit int        `json:"limit"`
	Rules []RuleView `json:"rules"`
}

// PolicyView is one policy group with its current selection and health.
type PolicyView struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Active  string `json:"active"`
	Checked string `json:"checked,omitempty"`
	// HealthyMembers counts the members that are not known to be down. A
	// member that has not been probed counts as healthy, which is how the
	// group treats it.
	HealthyMembers int `json:"healthy_members"`
	// AllUnhealthy reports that every member failed its last probe. This is
	// the state where the group has nowhere to move to, and it is what makes a
	// misconfigured probe URL visible instead of looking like slow traffic.
	AllUnhealthy bool         `json:"all_unhealthy"`
	Members      []MemberView `json:"members"`
}

// MemberView is the health of one group member.
type MemberView struct {
	Name      string  `json:"name"`
	Healthy   bool    `json:"healthy"`
	Checked   bool    `json:"checked"`
	LatencyMS float64 `json:"latency_ms"`
	// CheckedAt is when the member was last probed or last failed in use.
	CheckedAt string `json:"checked_at,omitempty"`
	// Failures is the number of consecutive failures.
	Failures int `json:"failures"`
	// Error is the most recent failure, shortened by the daemon.
	Error string `json:"error,omitempty"`
}

// InboundView is the runtime picture of the inbound listeners: how many
// connections they carry, how many UDP associations are open, and how the
// requests that were not carried break down.
type InboundView struct {
	// Inbounds lists the bound listeners, one entry per protocol.
	Inbounds []InboundStatsView `json:"inbounds"`
	// Open and Accepted are the totals across the listeners.
	Open     int64  `json:"open"`
	Accepted uint64 `json:"accepted"`
	// Failures counts the requests that failed for an operational reason;
	// Rejected counts the ones a rule blocked on purpose.
	Failures uint64 `json:"failures"`
	Rejected uint64 `json:"rejected"`
	// FailureLogCapacity and FailureLogCount describe the failure record, not
	// its content: the records themselves are served by /v1/failures.
	FailureLogCapacity int `json:"failure_log_capacity"`
	FailureLogCount    int `json:"failure_log_count"`
}

// InboundStatsView is one listener's counters.
type InboundStatsView struct {
	Protocol string `json:"protocol"`
	// Open is the number of connections being served right now, Accepted the
	// number accepted since startup.
	Open     int64  `json:"open"`
	Accepted uint64 `json:"accepted"`
	// Datagrams is the number of open UDP associations and DatagramTotal the
	// number opened since startup. Only the SOCKS5 listener has them.
	Datagrams      int64  `json:"datagram_associations"`
	DatagramsTotal uint64 `json:"datagram_associations_total"`
}

// FailureListView is the recent connection failures, oldest first.
type FailureListView struct {
	// Capacity is how many records are retained; Count is how many there are
	// now, which is what a limit parameter narrows.
	Capacity int           `json:"capacity"`
	Count    int           `json:"count"`
	Failures []FailureView `json:"failures"`
}

// FailureView is one connection that was not carried.
//
// It carries the destination and a category, never anything the connection
// transmitted: there is no payload, no header and no remote message here.
type FailureView struct {
	Time     string `json:"time"`
	Target   string `json:"target"`
	Network  string `json:"network,omitempty"`
	Stage    string `json:"stage"`
	Category string `json:"category"`
	Policy   string `json:"policy,omitempty"`
}

// DNSView is what the resolver has done since startup. It reports counts only:
// the [Host] table names internal services, so its content is never exposed.
type DNSView struct {
	CacheHits   uint64 `json:"cache_hits"`
	CacheMisses uint64 `json:"cache_misses"`
	Entries     int    `json:"entries"`
	MaxEntries  int    `json:"max_entries"`
	Succeeded   uint64 `json:"resolutions_succeeded"`
	Failed      uint64 `json:"resolutions_failed"`
}

// ExplainRequest is a classification request built from query parameters.
type ExplainRequest struct {
	Name    string
	Addr    string
	Port    int
	Network string
}

// ExplainView is a match explanation.
type ExplainView struct {
	Query      QueryView       `json:"query"`
	Matched    bool            `json:"matched"`
	Rule       *RuleView       `json:"rule,omitempty"`
	Target     string          `json:"target,omitempty"`
	Resolution *ResolutionView `json:"resolution,omitempty"`
	Steps      []StepView      `json:"steps"`
	Report     string          `json:"report,omitempty"`
}

// ResolutionView describes the lookup a query name went through before
// matching: where the address came from, or why there is none.
type ResolutionView struct {
	Source string   `json:"source,omitempty"`
	Addrs  []string `json:"addrs,omitempty"`
	Error  string   `json:"error,omitempty"`
	Note   string   `json:"note,omitempty"`
}

// QueryView echoes the inputs of an explanation.
type QueryView struct {
	Name    string `json:"name,omitempty"`
	Addr    string `json:"addr,omitempty"`
	Port    int    `json:"port,omitempty"`
	Network string `json:"network,omitempty"`
}

// StepView is one step of a decision path.
type StepView struct {
	Type   string `json:"type"`
	Index  int    `json:"index"`
	Rule   string `json:"rule,omitempty"`
	Match  bool   `json:"match"`
	Detail string `json:"detail"`
}

// SelectView is the outcome of pinning a manual group to a member.
type SelectView struct {
	Group string `json:"group"`
	// Previous is the member the group routed to before the request, so a
	// client can show what changed without a second call.
	Previous string `json:"previous,omitempty"`
	// Active is the member the group routes to now.
	Active string `json:"active"`
}

// ReloadView is the outcome of re-reading the configuration file.
type ReloadView struct {
	OK   bool   `json:"ok"`
	Path string `json:"path,omitempty"`
	// RuleCount, ProxyCount, GroupCount and HostCount describe what is in
	// force after the reload.
	RuleCount  int `json:"rule_count"`
	ProxyCount int `json:"proxy_count"`
	GroupCount int `json:"group_count"`
	HostCount  int `json:"host_count"`
	// RestartRequired lists the settings whose new value is read but cannot
	// take effect in a running process: a listener that is already bound, the
	// credentials it was built with, the API address, the data directory.
	// Everything else in the file applies immediately.
	RestartRequired []string `json:"restart_required"`
	ElapsedMS       float64  `json:"elapsed_ms"`
}

// AuditListView is the write operations the API carried out, oldest first.
type AuditListView struct {
	// Capacity is how many entries are retained; Count is how many there are
	// now, which is what a limit parameter narrows.
	Capacity int         `json:"capacity"`
	Count    int         `json:"count"`
	Entries  []AuditView `json:"entries"`
}

// AuditView is one write operation.
//
// It records what was asked and whether it took effect, never a credential: the
// detail repeats a group and a member name, or a configuration problem, both of
// which the caller already knows.
type AuditView struct {
	Time   string `json:"time"`
	Action string `json:"action"`
	Result string `json:"result"`
	Detail string `json:"detail,omitempty"`
	Remote string `json:"remote,omitempty"`
}

// Provider supplies the daemon state the API serves. Every method must be safe
// for concurrent use. The read methods never mutate anything; the two write
// methods are the operations the local API accepts, and each of them either
// takes full effect or leaves the daemon exactly as it was.
type Provider interface {
	Status(ctx context.Context) StatusView
	Config(ctx context.Context) ConfigView
	// Rules returns at most limit rules. A limit of zero lets the provider pick
	// a page size, which keeps a large rule set from being serialised by
	// accident.
	Rules(ctx context.Context, limit int) RuleListView
	Policies(ctx context.Context) []PolicyView
	Explain(ctx context.Context, req ExplainRequest) (ExplainView, error)
	// Inbound reports the counters of the local listeners and of the failure
	// record.
	Inbound(ctx context.Context) InboundView
	// Failures returns at most limit recent failures, oldest first. A limit of
	// zero returns everything the daemon retains.
	Failures(ctx context.Context, limit int) FailureListView
	// DNS reports the resolver counters.
	DNS(ctx context.Context) DNSView
	// SelectPolicy pins a manual policy group to one of its members. A group
	// that decides on its own reports a Conflict.
	SelectPolicy(ctx context.Context, group, member string) (SelectView, error)
	// ReloadConfig re-reads the configuration file and installs it. A
	// configuration that does not validate is reported as Unprocessable and
	// leaves the running one in force.
	ReloadConfig(ctx context.Context) (ReloadView, error)
}
