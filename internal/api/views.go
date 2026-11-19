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
	// TUNEnable is reported even when false, so a client can tell that the
	// device is off rather than missing the setting entirely. The device
	// details are omitted when it is off.
	TUNEnable  bool     `json:"tun_enable"`
	TUNName    string   `json:"tun_name,omitempty"`
	TUNAddress string   `json:"tun_address,omitempty"`
	TUNMTU     int      `json:"tun_mtu,omitempty"`
	TUNRoutes  []string `json:"tun_routes,omitempty"`
	// SystemProxy reports whether the daemon points the desktop proxy at its
	// listeners, and which hosts it leaves alone. It is reported even when
	// false, because "the machine is proxied by the daemon" is the one thing a
	// user has to be able to check from a client.
	SystemProxy       bool     `json:"system_proxy"`
	SystemProxyBypass []string `json:"system_proxy_bypass,omitempty"`
	// SystemProxyState is the four-state takeover report: configured,
	// pending_restart, applied and recovery_failed, collapsed into one display
	// state plus the facts behind it. The booleans above remain for clients that
	// only need the configured value.
	SystemProxyState SystemProxyView `json:"system_proxy_state"`
	// PendingRestart lists the settings whose value in the loaded
	// configuration is not in force because applying it needs a restart. It
	// is empty when the running process and the file agree, and it stays
	// until a restart, however many reloads happened in between.
	PendingRestart []string `json:"pending_restart"`
}

// SystemProxyState is the display state of the desktop proxy takeover. The
// strings are stable wire values; a client switches on them rather than on the
// raw booleans so that precedence between the facts is decided in one place.
const (
	// SystemProxyOff: nothing configured and nothing taken over.
	SystemProxyOff = "off"
	// SystemProxyConfigured: the configuration asks for a takeover, but the
	// running process has not made one.
	SystemProxyConfigured = "configured"
	// SystemProxyPendingRestart: the configuration changed the desktop proxy
	// setting and the change cannot take effect without a restart.
	SystemProxyPendingRestart = "pending_restart"
	// SystemProxyApplied: this process currently owns the takeover.
	SystemProxyApplied = "applied"
	// SystemProxyRecoveryFailed: a takeover record could not be fully put back
	// and was retained for the next start. It wins over every other state.
	SystemProxyRecoveryFailed = "recovery_failed"
)

// SystemProxyView is the four-state outlet the desktop shell needs. The raw
// facts are carried beside the single display state so a client can explain
// *why* it is showing a state without reading the configuration file itself.
// It is always present in ConfigView (never a pointer), so an older core that
// does not send it decodes to SystemProxyOff with every fact false.
type SystemProxyView struct {
	// State is one of the SystemProxy* constants, chosen by
	// systemProxyState in the core so precedence is decided there.
	State string `json:"state"`
	// Configured mirrors [General] system-proxy in the loaded configuration.
	Configured bool `json:"configured"`
	// PendingRestart is true when "system-proxy" is in pending_restart.
	PendingRestart bool `json:"pending_restart"`
	// Applied is true when this process owns the current takeover.
	Applied bool `json:"applied"`
	// RecoveryFailed is true when a takeover record could not be fully put
	// back and was retained; Detail then carries the short reason.
	RecoveryFailed bool   `json:"recovery_failed"`
	Detail         string `json:"detail,omitempty"`
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
	// FakeIPPoolExhaustedQueriesTotal counts the TUN DNS questions that were
	// answered with SERVFAIL because every name address was leased or still in
	// use. It is always reported, so a client reads a number rather than a
	// missing field: zero means "none yet", and it is also what a client of an
	// older core gets, since a field the core does not send decodes as zero.
	FakeIPPoolExhaustedQueriesTotal uint64 `json:"fake_ip_pool_exhausted_queries_total"`
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

// HistoryView describes the observation history the daemon keeps: how much it
// holds, how large the file is and whether the last write succeeded.
//
// It carries no record of its own. The endpoints below serve those, and a
// summary that repeated them would be a second copy to keep consistent.
type HistoryView struct {
	// Enabled reports whether a history is kept at all. When it is false the
	// other fields are zero and the record endpoints answer with empty lists
	// rather than an error: "there is no history" is not a failure.
	Enabled     bool                `json:"enabled"`
	Path        string              `json:"path,omitempty"`
	Bytes       int64               `json:"bytes"`
	Connections int                 `json:"connections"`
	Events      int                 `json:"events"`
	Samples     int                 `json:"samples"`
	Capacity    HistoryCapacityView `json:"capacity"`
	Flushes     uint64              `json:"flushes"`
	LastFlush   string              `json:"last_flush,omitempty"`
	// LastError is the most recent write failure, empty while writes succeed.
	// The records are still held in memory when it is set, so the next write
	// can still put them on disk.
	LastError string `json:"last_error,omitempty"`
	// Notice explains a history that could not be loaded, so a daemon that
	// started on an unreadable file says so instead of reporting an empty
	// history as if nothing had ever happened.
	Notice string `json:"notice,omitempty"`
	// Up and Down are the bytes carried since startup as the live counters
	// see them. The samples are deltas of these, so the two are not the same
	// number: one is a total, the other a series.
	Up   int64 `json:"up"`
	Down int64 `json:"down"`
}

// HistoryCapacityView is how many records each table keeps.
type HistoryCapacityView struct {
	Connections int `json:"connections"`
	Events      int `json:"events"`
	Samples     int `json:"samples"`
}

// ConnectionListView is a page of the carried connections, oldest first.
type ConnectionListView struct {
	Count       int              `json:"count"`
	Connections []ConnectionView `json:"connections"`
}

// ConnectionView is one carried connection.
//
// It describes where the connection went and what carried it, never what it
// transmitted: there is no payload, no header and no request path here.
type ConnectionView struct {
	Time     string `json:"time"`
	Protocol string `json:"protocol"`
	Target   string `json:"target"`
	Network  string `json:"network"`
	Rule     string `json:"rule,omitempty"`
	Policy   string `json:"policy,omitempty"`
	Outbound string `json:"outbound,omitempty"`
	Up       int64  `json:"up"`
	Down     int64  `json:"down"`
	// DurationMS is how long the connection was served, in milliseconds.
	DurationMS float64 `json:"duration_ms"`
}

// EventListView is a page of the events, oldest first.
type EventListView struct {
	Count  int         `json:"count"`
	Events []EventView `json:"events"`
}

// EventView is one thing that happened to the daemon rather than to a
// connection: a request that could not be carried, a reload, a subscription
// refresh or a policy selection.
type EventView struct {
	Time   string `json:"time"`
	Kind   string `json:"kind"`
	Name   string `json:"name,omitempty"`
	Detail string `json:"detail,omitempty"`
	// OK reports whether the event succeeded. A refused reload and a failed
	// refresh are both recorded: "it happened" and "it worked" are different
	// questions.
	OK bool `json:"ok"`
}

// TrafficListView is the traffic history, one entry per sampling interval.
type TrafficListView struct {
	Count int `json:"count"`
	// Up and Down are the totals of the returned window.
	Up      int64         `json:"up"`
	Down    int64         `json:"down"`
	Samples []TrafficView `json:"samples"`
}

// TrafficView is the traffic one interval carried. Up and Down are deltas
// rather than running totals, so a restart does not look like a negative spike.
type TrafficView struct {
	Time string `json:"time"`
	Up   int64  `json:"up"`
	Down int64  `json:"down"`
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
	// PendingRestart is the cumulative answer: every setting that still waits
	// for a restart, including ones an earlier reload could not apply.
	PendingRestart []string `json:"pending_restart"`
	// SelectionDropped names the manual groups whose pinned member no longer
	// exists, so a refresh that removed the node the user picked is visible
	// instead of leaving the group on a different member without a word.
	SelectionDropped []string `json:"selection_dropped"`
	ElapsedMS        float64  `json:"elapsed_ms"`
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

// SubscriptionView is one subscription's refresh state.
//
// It is a summary on purpose: how many nodes the last refresh produced, how
// many entries it skipped and how the attempt ended — never the skipped entries
// themselves. Those are a page of their own, served by
// /v1/subscriptions/{name}/skipped, so a client that only wants the list does
// not pay for a detail it never shows and the ordinary answer stays small.
type SubscriptionView struct {
	Name string `json:"name"`
	// Nodes is how many nodes the subscription contributes, and Skipped how
	// many entries of that same body were rejected. Both describe the last
	// refresh that completed; a failed refresh leaves them as they were.
	Nodes   int `json:"nodes"`
	Skipped int `json:"skipped"`
	// FetchedAt is when that refresh finished, absent when none ever did.
	FetchedAt string `json:"fetched_at,omitempty"`
	// NextAt is when the next attempt is due, including a backoff after a
	// failure.
	NextAt string `json:"next_at,omitempty"`
	// Attempts counts the failed refreshes since the last success, and Error
	// carries the most recent failure.
	Attempts int    `json:"attempts"`
	Error    string `json:"error,omitempty"`
}

// SubscriptionListView is every subscription the loaded configuration declares,
// in the order the file declares them.
type SubscriptionListView struct {
	Subscriptions []SubscriptionView `json:"subscriptions"`
}

// SkippedListView is one page of a subscription's skip detail.
//
// Refreshed separates "nothing was skipped" from "no refresh has completed
// yet": both carry an empty list, and only one of them means the configuration
// is clean.
type SkippedListView struct {
	Subscription string `json:"subscription"`
	Refreshed    bool   `json:"refreshed"`
	// FetchedAt is when the refresh that produced this detail finished.
	FetchedAt string `json:"fetched_at,omitempty"`
	// Total is how many entries that refresh skipped, over the whole list;
	// Offset and Limit describe the window that Skipped holds.
	Total  int `json:"total"`
	Offset int `json:"offset"`
	Limit  int `json:"limit"`
	// Skipped is the page itself, in the order the body carried the entries.
	// The item number is the 1-based position among the links of that body, so
	// a page keeps the positions the log used.
	Skipped []SkippedEntryView `json:"skipped"`
}

// SkippedEntryView is one entry of a subscription body that was not imported.
// It carries the position and the reason, never the link.
type SkippedEntryView struct {
	Item   int    `json:"item"`
	Reason string `json:"reason"`
}

// SubscriptionRefreshView is the outcome of a forced subscription refresh.
// A refresh that could not fetch still answers with a view: the previous nodes
// were kept, and Error carries the reason — the same policy as a scheduled
// refresh. Reloaded says whether the node list changed enough to rebuild the
// routing artefacts.
type SubscriptionRefreshView struct {
	Subscription string `json:"subscription"`
	// Refreshed is true when the fetch and parse completed. A failed attempt
	// that kept the previous nodes reports false with Error set.
	Refreshed bool `json:"refreshed"`
	// Reloaded is true when the new nodes were installed by a reload. It is
	// false both when nothing changed and when the refresh failed.
	Reloaded bool `json:"reloaded"`
	Nodes    int  `json:"nodes"`
	Skipped  int  `json:"skipped"`
	// FetchedAt is when the refresh that produced these nodes finished, absent
	// when the last refresh never completed.
	FetchedAt string `json:"fetched_at,omitempty"`
	Attempts  int    `json:"attempts"`
	Error     string `json:"error,omitempty"`
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
	// Subscriptions reports every subscription the configuration declares, with
	// the outcome of its last refresh. The skipped entries are not part of it:
	// a list that carried them would be large exactly when a provider is
	// broken, which is when the list is read most.
	Subscriptions(ctx context.Context) SubscriptionListView
	// SubscriptionSkipped returns one page of the skip detail of a
	// subscription's last completed refresh. A name the configuration does not
	// declare is reported as NotFound; a subscription that has never completed
	// a refresh answers an empty page with Refreshed false, which is not an
	// error.
	SubscriptionSkipped(ctx context.Context, name string, offset, limit int) (SkippedListView, error)
	// RefreshSubscription forces one declared subscription to refresh now,
	// rebuilding the routing artefacts if its nodes changed. A name the
	// configuration does not declare is reported as NotFound. A failed fetch
	// keeps the previous nodes and is reported in the view, not as an error.
	RefreshSubscription(ctx context.Context, name string) (SubscriptionRefreshView, error)
	// History describes the observation history: how much it holds and
	// whether its last write succeeded.
	History(ctx context.Context) HistoryView
	// HistoryConnections returns at most limit carried connections, oldest
	// first, keeping only the ones at or after since when it is not zero. A
	// limit of zero returns everything the daemon keeps.
	HistoryConnections(ctx context.Context, limit int, since time.Time) ConnectionListView
	// HistoryEvents returns at most limit events, oldest first, keeping only
	// the ones of that kind when kind is not empty and the ones at or after
	// since when it is not zero.
	HistoryEvents(ctx context.Context, limit int, kind string, since time.Time) EventListView
	// HistoryTraffic returns at most limit traffic samples, oldest first,
	// keeping only the ones at or after since when it is not zero.
	HistoryTraffic(ctx context.Context, limit int, since time.Time) TrafficListView
	// SelectPolicy pins a manual policy group to one of its members. A group
	// that decides on its own reports a Conflict.
	SelectPolicy(ctx context.Context, group, member string) (SelectView, error)
	// ReloadConfig re-reads the configuration file and installs it. A
	// configuration that does not validate is reported as Unprocessable and
	// leaves the running one in force.
	ReloadConfig(ctx context.Context) (ReloadView, error)
	// UpdateConfig writes the settings the local shell owns to the
	// configuration file. It does not reload: the caller then uses ReloadConfig
	// and reports the state the daemon actually reached. A malformed patch is a
	// BadRequest; a file that would no longer validate is Unprocessable and
	// leaves the old file in place.
	UpdateConfig(ctx context.Context, req ConfigUpdateRequest) (ConfigUpdateView, error)
}

// ConfigUpdateRequest is the body of POST /v1/config/update. Pointers keep an
// omitted field distinct from an explicit false, which matters for the desktop
// proxy switch.
type ConfigUpdateRequest struct {
	LogLevel    *string `json:"log_level,omitempty"`
	SystemProxy *bool   `json:"system_proxy,omitempty"`
}

// ConfigUpdateView reports what was written and what still needs a restart.
type ConfigUpdateView struct {
	Path            string   `json:"path,omitempty"`
	LogLevel        string   `json:"log_level,omitempty"`
	SystemProxy     bool     `json:"system_proxy"`
	RestartRequired []string `json:"restart_required"`
}
