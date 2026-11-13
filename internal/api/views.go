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
// part of it: a proxy is reduced to its name, type, server and port.
type ConfigView struct {
	Path      string        `json:"path,omitempty"`
	LogLevel  string        `json:"log_level"`
	APIListen string        `json:"api_listen,omitempty"`
	Proxies   []ProxyView   `json:"proxies"`
	Groups    []GroupView   `json:"groups"`
	RuleSets  []RuleSetView `json:"rule_sets"`
	Hosts     []HostView    `json:"hosts"`
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

// HostView is one local name mapping.
type HostView struct {
	Name  string   `json:"name"`
	Addrs []string `json:"addrs"`
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
	Name    string       `json:"name"`
	Type    string       `json:"type"`
	Active  string       `json:"active"`
	Checked string       `json:"checked,omitempty"`
	Members []MemberView `json:"members"`
}

// MemberView is the health of one group member.
type MemberView struct {
	Name      string  `json:"name"`
	Healthy   bool    `json:"healthy"`
	Checked   bool    `json:"checked"`
	LatencyMS float64 `json:"latency_ms"`
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
	Query   QueryView  `json:"query"`
	Matched bool       `json:"matched"`
	Rule    *RuleView  `json:"rule,omitempty"`
	Target  string     `json:"target,omitempty"`
	Steps   []StepView `json:"steps"`
	Report  string     `json:"report,omitempty"`
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

// Provider supplies the daemon state the API serves. Every method must be safe
// for concurrent use. The API never mutates anything: this stage is read only,
// and write endpoints are added on top of the same provider in a later stage.
type Provider interface {
	Status(ctx context.Context) StatusView
	Config(ctx context.Context) ConfigView
	// Rules returns at most limit rules. A limit of zero lets the provider pick
	// a page size, which keeps a large rule set from being serialised by
	// accident.
	Rules(ctx context.Context, limit int) RuleListView
	Policies(ctx context.Context) []PolicyView
	Explain(ctx context.Context, req ExplainRequest) (ExplainView, error)
}
