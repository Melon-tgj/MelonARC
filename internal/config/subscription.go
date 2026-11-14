package config

import (
	"fmt"
	"net/url"
	"strings"
)

// validateSubscriptions checks the [Subscription] declarations and returns the
// names rules and groups may already point at.
//
// The names are "virtual" targets: they do not exist as proxies yet, but they
// will exist as select groups as soon as the subscription has been fetched. A
// configuration can therefore be written, checked and started without network
// access, and a typo in a subscription name is still caught here.
func (c *Config) validateSubscriptions(issues *Errors, targets map[string]bool) map[string]bool {
	virtual := make(map[string]bool, len(c.Subscriptions))
	for _, s := range c.Subscriptions {
		if err := validName(s.Name); err != nil {
			issues.add(s.Line, "[Subscription]", "%v", err)
		} else if virtual[s.Name] {
			issues.add(s.Line, "[Subscription]", "subscription %q is defined more than once", s.Name)
		}
		if isBuiltinName(s.Name) {
			issues.add(s.Line, "[Subscription]", "%q is a reserved target and cannot be redefined", s.Name)
		}
		if _, taken := targets[s.Name]; taken && !isBuiltinName(s.Name) {
			issues.add(s.Line, "[Subscription]", "subscription %q has the same name as a proxy", s.Name)
		}
		if err := validSubscriptionURL(s.URL); err != nil {
			issues.add(s.Line, "[Subscription]", "subscription %q: %v", s.Name, err)
		}
		if s.Interval < minSubscriptionInterval {
			issues.add(s.Line, "[Subscription]",
				"subscription %q: interval must be at least %s", s.Name, minSubscriptionInterval)
		}
		virtual[s.Name] = true
	}
	return virtual
}

// validSubscriptionURL insists on an absolute http or https URL. Anything else
// is refused at load time: a subscription is fetched by the daemon itself, and
// finding out at the first update that the scheme was wrong would leave the
// user with an empty group hours later.
func validSubscriptionURL(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("the url is empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("the url is not valid")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("scheme %q is not http or https", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("the url has no host")
	}
	return nil
}

// MergeSubscriptions adds the nodes of every fetched subscription to the
// configuration and turns each subscription into a select group over them.
//
// The group is what makes a subscription usable: a provider changes node names
// whenever it likes, so a rule that pointed at an individual node would rot.
// Pointing at the subscription keeps working across updates, exactly like a
// hand-written group.
//
// Nodes are named "subscription/node". The prefix keeps two providers apart and
// makes what a subscription contributed recognisable in the API and in logs.
// The import is expected to run on a freshly parsed configuration, so it
// appends rather than replaces.
func (c *Config) MergeSubscriptions(nodes map[string][]Proxy) error {
	issues := &Errors{}
	used := make(map[string]bool, len(c.Proxies))
	for _, p := range c.Proxies {
		used[p.Name] = true
	}
	for _, sub := range c.Subscriptions {
		imported := nodes[sub.Name]
		if len(imported) == 0 {
			issues.add(sub.Line, "[Subscription]", "subscription %q provided no usable nodes", sub.Name)
			continue
		}
		members := make([]string, 0, len(imported))
		for i, node := range imported {
			name := uniqueName(used, sub.Name+"/"+sanitizeNodeName(node.Name, i))
			proxy := node
			proxy.Name = name
			c.Proxies = append(c.Proxies, proxy)
			used[name] = true
			members = append(members, name)
		}
		// The group was declared when the configuration was parsed, so the
		// import fills it rather than adding a second one. A subscription whose
		// group is missing means the caller merged into a configuration that
		// never declared it.
		filled := false
		for i := range c.Groups {
			if c.Groups[i].Name == sub.Name {
				c.Groups[i].Members = members
				filled = true
				break
			}
		}
		if !filled {
			issues.add(sub.Line, "[Subscription]", "subscription %q has no declared group", sub.Name)
		}
	}
	return issues.Err()
}

// sanitizeNodeName reduces a provider's node name to the character set a name
// may use. Providers decorate names with flags, spaces and punctuation; the
// result only has to be stable and readable, not pretty.
func sanitizeNodeName(name string, index int) string {
	var b strings.Builder
	lastDash := false
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '.':
			b.WriteRune(r)
			lastDash = false
		case r == '-':
			if !lastDash && b.Len() > 0 {
				b.WriteByte('-')
				lastDash = true
			}
		default:
			if !lastDash && b.Len() > 0 {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-.")
	if out == "" {
		out = fmt.Sprintf("node-%d", index+1)
	}
	if len(out) > maxNameLen-32 {
		out = strings.Trim(out[:maxNameLen-32], "-.")
	}
	return out
}

// uniqueName appends a counter until the name is free. It is bounded by the
// number of nodes, so a loop is the clearest way to write it.
func uniqueName(used map[string]bool, name string) string {
	if !used[name] {
		return name
	}
	for i := 2; ; i++ {
		candidate := fmt.Sprintf("%s-%d", name, i)
		if len(candidate) > maxNameLen {
			candidate = fmt.Sprintf("%s-%d", name[:maxNameLen-8], i)
		}
		if !used[candidate] {
			return candidate
		}
	}
}
