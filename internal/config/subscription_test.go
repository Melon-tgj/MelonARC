package config

import (
	"strings"
	"testing"
	"time"
)

// parseAndValidate is the path the daemon takes: syntax first, then the
// semantic checks.
func parseAndValidate(t *testing.T, text string) (*Config, error) {
	t.Helper()
	cfg, perr := Parse([]byte(text))
	if perr != nil {
		return cfg, perr
	}
	return cfg, cfg.Validate()
}

func TestSubscriptionIsParsed(t *testing.T) {
	cfg, err := parseAndValidate(t, `[General]

[Subscription]
airport = https://example.com/sub?token=abc interval=12h

[Rule]
FINAL,DIRECT
`)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if len(cfg.Subscriptions) != 1 {
		t.Fatalf("subscriptions = %d, want 1", len(cfg.Subscriptions))
	}
	sub := cfg.Subscriptions[0]
	if sub.Name != "airport" {
		t.Fatalf("name = %q, want airport", sub.Name)
	}
	if sub.URL != "https://example.com/sub?token=abc" {
		t.Fatalf("url = %q", sub.URL)
	}
	if sub.Interval != 12*time.Hour {
		t.Fatalf("interval = %s, want 12h", sub.Interval)
	}
}

func TestSubscriptionIntervalDefaultsToSixHours(t *testing.T) {
	cfg, err := parseAndValidate(t, `[General]
[Subscription]
airport = https://example.com/sub
[Rule]
FINAL,DIRECT
`)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if got := cfg.Subscriptions[0].Interval; got != 6*time.Hour {
		t.Fatalf("interval = %s, want 6h", got)
	}
}

// TestSubscriptionIsAValidTarget is the property that makes the section usable:
// a rule or a group may point at a subscription before anything was fetched.
func TestSubscriptionIsAValidTarget(t *testing.T) {
	cfg, err := parseAndValidate(t, `[General]
[Proxy]
local = ss, 127.0.0.1, 1, method=aes-128-gcm, password=pw

[Proxy Group]
auto = url-test, airport, local, url=http://example.com/204, interval=300

[Subscription]
airport = https://example.com/sub

[Rule]
DOMAIN,example.org,airport
FINAL,auto
`)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	// The file declares one group; the subscription declares another, which
	// exists from the start so the rule above can point at it.
	if len(cfg.Groups) != 2 {
		t.Fatalf("groups = %d, want 2", len(cfg.Groups))
	}
	sub, ok := cfg.GroupByName("airport")
	if !ok {
		t.Fatal("the subscription did not declare a group")
	}
	if len(sub.Members) != 0 {
		t.Fatalf("subscription group has %d members before the import", len(sub.Members))
	}
}

func TestSubscriptionProblemsAreReported(t *testing.T) {
	cases := []struct {
		name string
		text string
		want string
	}{
		{
			name: "unknown option",
			text: "[General]\n[Subscription]\na = https://example.com/s refresh=1h\n[Rule]\nFINAL,DIRECT\n",
			want: "unknown option",
		},
		{
			name: "not http",
			text: "[General]\n[Subscription]\na = ftp://example.com/s\n[Rule]\nFINAL,DIRECT\n",
			want: "not http or https",
		},
		{
			name: "no url",
			text: "[General]\n[Subscription]\na =\n[Rule]\nFINAL,DIRECT\n",
			want: "expected name = url",
		},
		{
			name: "too short interval",
			text: "[General]\n[Subscription]\na = https://example.com/s interval=30s\n[Rule]\nFINAL,DIRECT\n",
			want: "at least",
		},
		{
			name: "name collides with a proxy",
			text: "[General]\n[Proxy]\na = ss, 127.0.0.1, 1, method=aes-128-gcm, password=pw\n[Subscription]\na = https://example.com/s\n[Rule]\nFINAL,DIRECT\n",
			want: "same name as a proxy",
		},
		{
			name: "name collides with a group",
			text: "[General]\n[Proxy]\np = ss, 127.0.0.1, 1, method=aes-128-gcm, password=pw\n[Proxy Group]\ng = select, p\n[Subscription]\ng = https://example.com/s\n[Rule]\nFINAL,DIRECT\n",
			want: "already defined",
		},
		{
			name: "reserved name",
			text: "[General]\n[Subscription]\nDIRECT = https://example.com/s\n[Rule]\nFINAL,DIRECT\n",
			want: "reserved target",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseAndValidate(t, tc.text)
			if err == nil {
				t.Fatal("configuration was accepted, want a problem")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// TestMergeSubscriptions is the shape the daemon relies on: every node arrives
// under the subscription's prefix, and the subscription itself becomes a group
// over them so rules keep working when the provider renames things.
func TestMergeSubscriptions(t *testing.T) {
	cfg, err := parseAndValidate(t, `[General]
[Proxy]
local = ss, 127.0.0.1, 1, method=aes-128-gcm, password=pw

[Proxy Group]
auto = url-test, airport, local, url=http://example.com/204, interval=300

[Subscription]
airport = https://example.com/sub

[Rule]
FINAL,airport
`)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	nodes := map[string][]Proxy{
		"airport": {
			{Name: "Tokyo 01", Type: "vmess", Server: "a.example.com", Port: 443},
			{Name: "Osaka", Type: "vmess", Server: "b.example.com", Port: 443},
			{Name: "Tokyo 01", Type: "vmess", Server: "c.example.com", Port: 443},
		},
	}
	if err := cfg.MergeSubscriptions(nodes); err != nil {
		t.Fatalf("merge: %v", err)
	}
	if len(cfg.Proxies) != 4 {
		t.Fatalf("proxies = %d, want 4", len(cfg.Proxies))
	}
	names := []string{cfg.Proxies[1].Name, cfg.Proxies[2].Name, cfg.Proxies[3].Name}
	want := []string{"airport/Tokyo-01", "airport/Osaka", "airport/Tokyo-01-2"}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("node %d = %q, want %q (all %v)", i, names[i], want[i], names)
		}
	}
	group, ok := cfg.GroupByName("airport")
	if !ok {
		t.Fatal("the subscription did not become a group")
	}
	if group.Type != GroupSelect {
		t.Fatalf("group type = %q, want select", group.Type)
	}
	if len(group.Members) != 3 || group.Members[0] != "airport/Tokyo-01" {
		t.Fatalf("group members = %v", group.Members)
	}
	// The configuration must still be valid with the imported nodes in place:
	// this is the state the daemon builds its runtime from.
	if err := cfg.Validate(); err != nil {
		t.Fatalf("merged configuration no longer validates: %v", err)
	}
}

func TestMergeSubscriptionsRejectsAnEmptyProvider(t *testing.T) {
	cfg, err := parseAndValidate(t, `[General]
[Subscription]
airport = https://example.com/sub
[Rule]
FINAL,DIRECT
`)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	err = cfg.MergeSubscriptions(map[string][]Proxy{})
	if err == nil {
		t.Fatal("merge accepted a subscription with no nodes")
	}
	if !strings.Contains(err.Error(), "no usable nodes") {
		t.Fatalf("error = %v", err)
	}
}

func TestSanitizeNodeName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Tokyo 01", "Tokyo-01"},
		{"🇯🇵 Tokyo | 01", "Tokyo-01"},
		{"---", "node-1"},
		{"", "node-1"},
		{"a.b_c", "a.b_c"},
		{"name/with/slash", "name-with-slash"},
	}
	for _, tc := range cases {
		if got := sanitizeNodeName(tc.in, 0); got != tc.want {
			t.Fatalf("sanitizeNodeName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	long := strings.Repeat("a", 200)
	if got := sanitizeNodeName(long, 0); len(got) > maxNameLen-32 {
		t.Fatalf("long name kept %d bytes", len(got))
	}
}
