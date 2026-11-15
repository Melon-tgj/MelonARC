// Package cli implements the command line client of MelonARC.
//
// It is a thin layer over the local API: every command reads or writes the
// daemon through the same endpoints the desktop UI will use, and nothing here
// performs privileged work or edits the configuration file itself. A reload asks
// the daemon to re-read the file, which is the only way a change is applied.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/melon-tgj/melonarc/internal/api"
	"github.com/melon-tgj/melonarc/internal/version"
)

// Exit codes. A usage error is kept apart from a failure so a script can tell a
// mistyped command from a core that refuses to answer.
const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
)

// usage is printed for help and for a mistyped command.
const usage = `melonarc-cli talks to a running MelonARC core over its local API.

usage:
  melonarc-cli [flags] <command> [arguments]

commands:
  status                       summarize the daemon: health, counters, resolver
  policies                     list policy groups and the health of their members
  select <group> <member>      pin a manual (select) group to a member
  reload                       re-read the configuration file and apply it
  explain <host[:port]>        show how the rules classify a destination
  audit [limit]                list the write operations the core carried out
  history [what] [limit]       read what the core kept: what is "summary",
                               "connections", "events" or "traffic"
  version                      print the client version
  help                         print this text

flags:
  -api <url|host:port>   base address of the core (default $MELONARC_API,
                         then http://127.0.0.1:7946)
  -token <token>         bearer token (default $MELONARC_TOKEN, then the
                         token file of the data directory)
  -token-file <path>     read the token from this file instead
  -data-dir <path>       data directory of the core, where the token file is
                         (default the platform configuration directory)
  -network <tcp|udp>     transport used by explain (default tcp)
  -since <duration>      how far back history looks, for example 1h or 30m
                         (default everything the core keeps)
  -timeout <duration>    how long to wait for the core (default 15s)
  -json                  print the raw answer of the core

flags come before the command:
  melonarc-cli -json status
  melonarc-cli select manual proxy-b
  melonarc-cli explain example.com:443
  melonarc-cli -since 2h history connections 50
`

// options is the parsed command line.
type options struct {
	api       string
	token     string
	tokenFile string
	dataDir   string
	network   string
	since     time.Duration
	timeout   time.Duration
	json      bool

	stdout io.Writer
	stderr io.Writer
}

// Run parses the arguments, runs the command and returns the exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	o := &options{stdout: stdout, stderr: stderr}
	fs := flag.NewFlagSet("melonarc-cli", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { _, _ = io.WriteString(stderr, usage) }
	fs.StringVar(&o.api, "api", "", "base address of the core")
	fs.StringVar(&o.token, "token", "", "bearer token")
	fs.StringVar(&o.tokenFile, "token-file", "", "path of the token file")
	fs.StringVar(&o.dataDir, "data-dir", "", "data directory of the core")
	fs.StringVar(&o.network, "network", "tcp", "transport used by explain")
	fs.DurationVar(&o.since, "since", 0, "how far back history looks")
	fs.DurationVar(&o.timeout, "timeout", 15*time.Second, "how long to wait for the core")
	fs.BoolVar(&o.json, "json", false, "print the raw answer of the core")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if o.timeout <= 0 {
		fmt.Fprintln(stderr, "melonarc-cli: -timeout must be positive")
		return exitUsage
	}
	if o.since < 0 {
		fmt.Fprintln(stderr, "melonarc-cli: -since must not be negative")
		return exitUsage
	}
	rest := fs.Args()
	if len(rest) == 0 {
		_, _ = io.WriteString(stderr, usage)
		return exitUsage
	}
	return o.dispatch(rest[0], rest[1:])
}

// dispatch runs one command.
func (o *options) dispatch(name string, args []string) int {
	switch name {
	case "help", "-h", "--help":
		_, _ = io.WriteString(o.stdout, usage)
		return exitOK
	case "version":
		fmt.Fprintf(o.stdout, "melonarc-cli %s\n", version.Version)
		return exitOK
	case "status":
		return o.status(args)
	case "policies":
		return o.policies(args)
	case "select":
		return o.selectPolicy(args)
	case "reload":
		return o.reload(args)
	case "explain":
		return o.explain(args)
	case "audit":
		return o.audit(args)
	case "history":
		return o.history(args)
	}
	fmt.Fprintf(o.stderr, "unknown command %q\n\n%s", name, usage)
	return exitUsage
}

// status summarizes the daemon from the read-only endpoints.
func (o *options) status(args []string) int {
	if len(args) > 0 {
		return o.usageError("status takes no arguments")
	}
	c, code := o.client()
	if c == nil {
		return code
	}
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()

	report := statusReport{}
	if err := c.get(ctx, "/healthz", &report.Health); err != nil {
		return o.fail(err)
	}
	if err := c.get(ctx, "/v1/status", &report.Status); err != nil {
		return o.fail(err)
	}
	if err := c.get(ctx, "/v1/inbound", &report.Inbound); err != nil {
		return o.fail(err)
	}
	if err := c.get(ctx, "/v1/dns", &report.DNS); err != nil {
		return o.fail(err)
	}
	if o.json {
		return o.printJSON(report)
	}

	w := o.table()
	fmt.Fprintf(w, "core\t%s\n", report.Health.Version)
	fmt.Fprintf(w, "api\t%s\n", c.base)
	fmt.Fprintf(w, "uptime\t%s\n", formatUptime(report.Health.UptimeSeconds))
	if path := report.Status.ConfigPath; path != "" {
		fmt.Fprintf(w, "config\t%s\n", path)
	}
	fmt.Fprintf(w, "rules\t%d\n", report.Status.RuleCount)
	fmt.Fprintf(w, "policies\t%d\n", report.Status.PolicyCount)
	fmt.Fprintf(w, "inbound\t%s\n", describeInbound(report.Inbound))
	fmt.Fprintf(w, "dns\t%d resolved, %d cache hits, %d misses, %d entries\n",
		report.DNS.Succeeded, report.DNS.CacheHits, report.DNS.CacheMisses, report.DNS.Entries)
	return o.flush(w)
}

// statusReport is the answer of "status", one field per endpoint.
type statusReport struct {
	Health  api.HealthView  `json:"health"`
	Status  api.StatusView  `json:"status"`
	Inbound api.InboundView `json:"inbound"`
	DNS     api.DNSView     `json:"dns"`
}

// describeInbound renders the listener counters in one line.
//
// The last number is the TUN name address pool: how many DNS questions were
// answered with SERVFAIL because every fake address was leased. It is printed
// even when it is zero, and it reads as zero against a core that predates the
// field, because that is what a missing field decodes to.
func describeInbound(view api.InboundView) string {
	protocols := make([]string, 0, len(view.Inbounds))
	for _, in := range view.Inbounds {
		protocols = append(protocols, in.Protocol)
	}
	if len(protocols) == 0 {
		protocols = append(protocols, "none")
	}
	return fmt.Sprintf("%s; %d open, %d accepted, %d failed, %d rejected, %d fake-IP pool exhausted",
		strings.Join(protocols, " + "), view.Open, view.Accepted, view.Failures, view.Rejected,
		view.FakeIPPoolExhaustedQueriesTotal)
}

// policies lists the groups and their members.
func (o *options) policies(args []string) int {
	if len(args) > 0 {
		return o.usageError("policies takes no arguments")
	}
	c, code := o.client()
	if c == nil {
		return code
	}
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()

	var body struct {
		Policies []api.PolicyView `json:"policies"`
	}
	if err := c.get(ctx, "/v1/policies", &body); err != nil {
		return o.fail(err)
	}
	if o.json {
		return o.printJSON(body.Policies)
	}
	if len(body.Policies) == 0 {
		fmt.Fprintln(o.stdout, "no policy groups are configured")
		return exitOK
	}

	groups := o.table()
	fmt.Fprintln(groups, "NAME\tTYPE\tACTIVE\tHEALTHY\tALL UNHEALTHY")
	for _, g := range body.Policies {
		fmt.Fprintf(groups, "%s\t%s\t%s\t%d/%d\t%s\n",
			g.Name, g.Type, orDash(g.Active), g.HealthyMembers, len(g.Members), yesNo(g.AllUnhealthy))
	}
	if code := o.flush(groups); code != exitOK {
		return code
	}

	members := o.table()
	fmt.Fprintln(members, "GROUP\tMEMBER\tSTATE\tLATENCY\tFAILURES\tLAST CHECK\tERROR")
	for _, g := range body.Policies {
		for _, m := range g.Members {
			fmt.Fprintf(members, "%s\t%s\t%s\t%s\t%d\t%s\t%s\n",
				g.Name, m.Name, memberState(g, m), memberLatency(m), m.Failures,
				orDash(m.CheckedAt), m.Error)
		}
	}
	return o.flush(members)
}

// memberState names what a member is doing right now.
func memberState(g api.PolicyView, m api.MemberView) string {
	switch {
	case !m.Checked:
		return "unprobed"
	case !m.Healthy:
		return "down"
	case m.Name == g.Active:
		return "active"
	default:
		return "idle"
	}
}

// memberLatency renders the last measured latency, which only exists for a
// member that answered a probe.
func memberLatency(m api.MemberView) string {
	if !m.Checked || !m.Healthy {
		return "-"
	}
	return fmt.Sprintf("%.1fms", m.LatencyMS)
}

// selectPolicy pins a manual group to a member.
func (o *options) selectPolicy(args []string) int {
	if len(args) != 2 {
		return o.usageError("select needs a group and a member: melonarc-cli select <group> <member>")
	}
	c, code := o.client()
	if c == nil {
		return code
	}
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()

	var view api.SelectView
	body := map[string]string{"group": args[0], "member": args[1]}
	if err := c.post(ctx, "/v1/policies/select", body, &view); err != nil {
		return o.fail(err)
	}
	if o.json {
		return o.printJSON(view)
	}
	if view.Previous != "" && view.Previous != view.Active {
		fmt.Fprintf(o.stdout, "%s: %s -> %s\n", view.Group, view.Previous, view.Active)
		return exitOK
	}
	fmt.Fprintf(o.stdout, "%s: %s\n", view.Group, view.Active)
	return exitOK
}

// reload asks the core to re-read its configuration file.
func (o *options) reload(args []string) int {
	if len(args) > 0 {
		return o.usageError("reload takes no arguments")
	}
	c, code := o.client()
	if c == nil {
		return code
	}
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()

	var view api.ReloadView
	if err := c.post(ctx, "/v1/config/reload", nil, &view); err != nil {
		return o.fail(err)
	}
	if o.json {
		return o.printJSON(view)
	}
	fmt.Fprintf(o.stdout, "reloaded %s in %s\n", view.Path, time.Duration(view.ElapsedMS*float64(time.Millisecond)).Round(time.Millisecond))
	fmt.Fprintf(o.stdout, "rules %d, proxies %d, groups %d, hosts %d\n",
		view.RuleCount, view.ProxyCount, view.GroupCount, view.HostCount)
	if len(view.RestartRequired) > 0 {
		fmt.Fprintf(o.stdout, "restart required for: %s\n", strings.Join(view.RestartRequired, ", "))
	}
	// The cumulative set only needs a line of its own when this reload did not
	// already name all of it: otherwise it repeats the line above.
	if len(view.PendingRestart) > 0 && !slices.Equal(view.PendingRestart, view.RestartRequired) {
		fmt.Fprintf(o.stdout, "still waiting for a restart: %s\n", strings.Join(view.PendingRestart, ", "))
	}
	for _, dropped := range view.SelectionDropped {
		fmt.Fprintf(o.stdout, "selection not restored: %s\n", dropped)
	}
	return exitOK
}

// explain shows how the rules classify a destination.
func (o *options) explain(args []string) int {
	if len(args) != 1 {
		return o.usageError("explain needs one destination: melonarc-cli explain <host[:port]>")
	}
	network := strings.ToLower(strings.TrimSpace(o.network))
	switch network {
	case "tcp", "udp":
	default:
		return o.usageError(fmt.Sprintf("network %q is neither tcp nor udp", o.network))
	}
	host, port, err := splitTarget(args[0])
	if err != nil {
		return o.usageError(err.Error())
	}
	c, code := o.client()
	if c == nil {
		return code
	}
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()

	query := url.Values{}
	if ip := net.ParseIP(host); ip != nil {
		query.Set("addr", ip.String())
	} else {
		query.Set("name", host)
	}
	if port > 0 {
		query.Set("port", strconv.Itoa(port))
	}
	query.Set("network", network)

	var view api.ExplainView
	if err := c.get(ctx, "/v1/rules/explain?"+query.Encode(), &view); err != nil {
		return o.fail(err)
	}
	if o.json {
		return o.printJSON(view)
	}
	fmt.Fprintln(o.stdout, view.Report)
	if !view.Matched {
		fmt.Fprintln(o.stdout, "no rule matched this destination")
	}
	return exitOK
}

// audit lists the write operations the core carried out.
func (o *options) audit(args []string) int {
	path := "/v1/audit"
	if len(args) > 1 {
		return o.usageError("audit takes at most one limit: melonarc-cli audit [limit]")
	}
	if len(args) == 1 {
		n, err := strconv.Atoi(args[0])
		if err != nil || n < 0 {
			return o.usageError(fmt.Sprintf("%q is not a non-negative number", args[0]))
		}
		path += "?limit=" + strconv.Itoa(n)
	}
	c, code := o.client()
	if c == nil {
		return code
	}
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()

	var view api.AuditListView
	if err := c.get(ctx, path, &view); err != nil {
		return o.fail(err)
	}
	if o.json {
		return o.printJSON(view)
	}
	if len(view.Entries) == 0 {
		fmt.Fprintln(o.stdout, "no write operation has been recorded yet")
		return exitOK
	}
	w := o.table()
	fmt.Fprintln(w, "TIME\tACTION\tRESULT\tREMOTE\tDETAIL")
	for _, entry := range view.Entries {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			entry.Time, entry.Action, entry.Result, orDash(entry.Remote), oneLine(entry.Detail))
	}
	return o.flush(w)
}

// historyWhat lists the parts of the history a command can ask for.
const historyWhat = "summary, connections, events or traffic"

// history reads what the core kept about the past.
//
// The summary describes the file itself — how much it holds, how large it is and
// whether the last write succeeded — while the other three are windows of it.
// All of them share the limit argument, and -since narrows them to a period
// rather than a count.
func (o *options) history(args []string) int {
	what, rest := "summary", args
	if len(rest) > 0 {
		switch rest[0] {
		case "summary", "connections", "events", "traffic":
			what, rest = rest[0], rest[1:]
		}
	}
	if len(rest) > 1 {
		return o.usageError("history takes at most one limit: melonarc-cli history [" + historyWhat + "] [limit]")
	}
	query := url.Values{}
	if len(rest) == 1 {
		n, err := strconv.Atoi(rest[0])
		if err != nil || n < 0 {
			return o.usageError(fmt.Sprintf("%q is not a non-negative number", rest[0]))
		}
		query.Set("limit", strconv.Itoa(n))
	}
	// The summary describes the store, not a window of it, so a period would
	// mean nothing there.
	if o.since > 0 {
		if what == "summary" {
			return o.usageError("-since narrows connections, events or traffic; the summary describes the whole file")
		}
		query.Set("since", o.since.String())
	}
	c, code := o.client()
	if c == nil {
		return code
	}
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()

	switch what {
	case "connections":
		return o.historyConnections(ctx, c, query)
	case "events":
		return o.historyEvents(ctx, c, query)
	case "traffic":
		return o.historyTraffic(ctx, c, query)
	default:
		return o.historySummary(ctx, c)
	}
}

// historySummary prints what the store holds.
func (o *options) historySummary(ctx context.Context, c *client) int {
	var view api.HistoryView
	if err := c.get(ctx, "/v1/history", &view); err != nil {
		return o.fail(err)
	}
	if o.json {
		return o.printJSON(view)
	}
	if !view.Enabled {
		fmt.Fprintln(o.stdout, "this core keeps no history")
		return exitOK
	}
	w := o.table()
	fmt.Fprintf(w, "file\t%s\n", view.Path)
	fmt.Fprintf(w, "size\t%s\n", humanBytes(view.Bytes))
	fmt.Fprintf(w, "connections\t%d of %d\n", view.Connections, view.Capacity.Connections)
	fmt.Fprintf(w, "events\t%d of %d\n", view.Events, view.Capacity.Events)
	fmt.Fprintf(w, "samples\t%d of %d\n", view.Samples, view.Capacity.Samples)
	fmt.Fprintf(w, "writes\t%d, last %s\n", view.Flushes, orDash(view.LastFlush))
	if code := o.flush(w); code != exitOK {
		return code
	}
	fmt.Fprintf(o.stdout, "carried since start: %s up, %s down\n",
		humanBytes(view.Up), humanBytes(view.Down))
	// A write failure and an unreadable previous file are the two states a
	// reader would otherwise mistake for "the history is simply empty".
	if view.LastError != "" {
		fmt.Fprintf(o.stdout, "last write failed: %s\n", oneLine(view.LastError))
	}
	if view.Notice != "" {
		fmt.Fprintf(o.stdout, "note: %s\n", oneLine(view.Notice))
	}
	return exitOK
}

// historyConnections prints the carried connections.
func (o *options) historyConnections(ctx context.Context, c *client, query url.Values) int {
	var view api.ConnectionListView
	if err := c.get(ctx, "/v1/history/connections"+querySuffix(query), &view); err != nil {
		return o.fail(err)
	}
	if o.json {
		return o.printJSON(view)
	}
	if len(view.Connections) == 0 {
		fmt.Fprintln(o.stdout, "no connection has been recorded in that window")
		return exitOK
	}
	w := o.table()
	fmt.Fprintln(w, "TIME\tPROTO\tTARGET\tNET\tPOLICY\tOUTBOUND\tUP\tDOWN\tDURATION")
	for _, conn := range view.Connections {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			conn.Time, conn.Protocol, conn.Target, conn.Network, orDash(conn.Policy),
			orDash(conn.Outbound), humanBytes(conn.Up), humanBytes(conn.Down),
			time.Duration(conn.DurationMS*float64(time.Millisecond)).Round(time.Millisecond))
	}
	return o.flush(w)
}

// historyEvents prints the events.
func (o *options) historyEvents(ctx context.Context, c *client, query url.Values) int {
	var view api.EventListView
	if err := c.get(ctx, "/v1/history/events"+querySuffix(query), &view); err != nil {
		return o.fail(err)
	}
	if o.json {
		return o.printJSON(view)
	}
	if len(view.Events) == 0 {
		fmt.Fprintln(o.stdout, "no event has been recorded in that window")
		return exitOK
	}
	w := o.table()
	fmt.Fprintln(w, "TIME\tKIND\tOK\tNAME\tDETAIL")
	for _, event := range view.Events {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			event.Time, event.Kind, yesNo(event.OK), orDash(event.Name), oneLine(event.Detail))
	}
	return o.flush(w)
}

// historyTraffic prints the traffic samples, one row per interval.
func (o *options) historyTraffic(ctx context.Context, c *client, query url.Values) int {
	var view api.TrafficListView
	if err := c.get(ctx, "/v1/history/traffic"+querySuffix(query), &view); err != nil {
		return o.fail(err)
	}
	if o.json {
		return o.printJSON(view)
	}
	if len(view.Samples) == 0 {
		fmt.Fprintln(o.stdout, "no traffic sample has been recorded in that window")
		return exitOK
	}
	w := o.table()
	fmt.Fprintln(w, "TIME\tUP\tDOWN")
	for _, sample := range view.Samples {
		fmt.Fprintf(w, "%s\t%s\t%s\n", sample.Time, humanBytes(sample.Up), humanBytes(sample.Down))
	}
	if code := o.flush(w); code != exitOK {
		return code
	}
	fmt.Fprintf(o.stdout, "total: %s up, %s down over %d intervals\n",
		humanBytes(view.Up), humanBytes(view.Down), view.Count)
	return exitOK
}

// querySuffix renders a query for a URL, empty when nothing is set.
func querySuffix(values url.Values) string {
	if len(values) == 0 {
		return ""
	}
	return "?" + values.Encode()
}

// humanBytes renders a byte count in the units a person reads. It is bounded to
// one decimal so a table column stays aligned.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return strconv.FormatInt(n, 10) + "B"
	}
	value := float64(n)
	for _, suffix := range []string{"K", "M", "G", "T"} {
		value /= unit
		if value < unit {
			return strconv.FormatFloat(value, 'f', 1, 64) + suffix + "B"
		}
	}
	return strconv.FormatFloat(value, 'f', 1, 64) + "PB"
}

// splitTarget turns "host:port", "[addr]:port", "host" or an address into a host// and a port. A destination without a port reports port 0, which the API accepts
// as "no port constraint".
func splitTarget(raw string) (string, int, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", 0, errors.New("a destination is required")
	}
	if host, port, err := net.SplitHostPort(value); err == nil {
		n, convErr := strconv.Atoi(port)
		if convErr != nil || n < 1 || n > 65535 {
			return "", 0, fmt.Errorf("port %q is outside 1-65535", port)
		}
		return strings.Trim(host, "[]"), n, nil
	}
	// Without a port the brackets of an address literal are punctuation, not
	// part of the address.
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		return value[1 : len(value)-1], 0, nil
	}
	return value, 0, nil
}

// client builds the client of a command, or reports why it cannot.
func (o *options) client() (*client, int) {
	c, err := newClient(o)
	if err != nil {
		return nil, o.fail(err)
	}
	return c, exitOK
}

// fail prints a failure and returns the exit code for it.
func (o *options) fail(err error) int {
	fmt.Fprintf(o.stderr, "melonarc-cli: %v\n", err)
	return exitFailure
}

// usageError reports a malformed command line.
func (o *options) usageError(message string) int {
	fmt.Fprintf(o.stderr, "melonarc-cli: %s\n", message)
	return exitUsage
}

// table returns a writer that aligns columns.
func (o *options) table() *tabwriter.Writer {
	return tabwriter.NewWriter(o.stdout, 0, 0, 2, ' ', 0)
}

// flush commits a table.
func (o *options) flush(w *tabwriter.Writer) int {
	if err := w.Flush(); err != nil {
		return o.fail(err)
	}
	return exitOK
}

// printJSON writes a view as indented JSON, which is what -json asks for.
func (o *options) printJSON(v any) int {
	enc := json.NewEncoder(o.stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return o.fail(err)
	}
	return exitOK
}

// formatUptime renders the uptime the core reports.
func formatUptime(seconds float64) string {
	if seconds < 1 {
		return "just started"
	}
	return time.Duration(seconds * float64(time.Second)).Round(time.Second).String()
}

// orDash renders an empty value as a dash so a column stays readable.
func orDash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

// oneLine collapses the line breaks of a detail, which a refused reload puts in
// its message, so one record stays one table row.
func oneLine(text string) string {
	return strings.Join(strings.Fields(text), " ")
}

// yesNo renders a flag for a table.
func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}
