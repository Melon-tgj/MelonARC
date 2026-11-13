package rules

import (
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestRuleSetExpansion(t *testing.T) {
	files := map[string]string{
		"ads": "# comment line\nDOMAIN,ads.example.com\nDOMAIN-SUFFIX,adserver.example.net\n\n",
		"cn":  "DOMAIN-SUFFIX,cn.example.org",
	}
	p := compileLines(t, []string{
		"DOMAIN,first.example.com,DIRECT",
		"RULE-SET,ads,REJECT",
		"RULE-SET,cn,Proxy",
		"FINAL,Fallback",
	}, Options{RuleSets: map[string]string{"ads": "ads", "cn": "cn"}, ReadFile: readFileMap(files)})

	tests := []struct {
		host string
		want string
	}{
		{"ads.example.com", "REJECT"},
		{"sub.adserver.example.net", "REJECT"},
		{"a.cn.example.org", "Proxy"},
		{"first.example.com", "DIRECT"},
		{"unrelated.example", "Fallback"},
	}
	for _, tc := range tests {
		got, _ := p.Match(Query{Name: tc.host})
		if got.Target != tc.want {
			t.Errorf("%q: target = %q, want %q", tc.host, got.Target, tc.want)
		}
	}
	if p.Len() != 5 {
		t.Fatalf("compiled %d rules, want 5 (4 config lines, one of which expands to 2)", p.Len())
	}
	if got := p.Stats().RuleSets; len(got) != 2 || got[0] != "ads" || got[1] != "cn" {
		t.Fatalf("used rule sets = %v", got)
	}
}

func TestRuleSetPreservesPriority(t *testing.T) {
	files := map[string]string{"set": "DOMAIN-SUFFIX,example.com"}
	p := compileLines(t, []string{
		"DOMAIN-SUFFIX,example.com,Proxy",
		"RULE-SET,set,REJECT",
		"FINAL,DIRECT",
	}, Options{RuleSets: map[string]string{"set": "set"}, ReadFile: readFileMap(files)})

	got, _ := p.Match(Query{Name: "a.example.com"})
	if got.Target != "Proxy" {
		t.Fatalf("target = %q, want the earlier rule to win", got.Target)
	}
}

func TestRuleSetNested(t *testing.T) {
	files := map[string]string{
		"outer": "RULE-SET,inner\nDOMAIN,outer.example.com",
		"inner": "DOMAIN,inner.example.com",
	}
	p := compileLines(t, []string{"RULE-SET,outer,REJECT", "FINAL,DIRECT"},
		Options{RuleSets: map[string]string{"outer": "outer", "inner": "inner"}, ReadFile: readFileMap(files)})

	for _, host := range []string{"inner.example.com", "outer.example.com"} {
		got, _ := p.Match(Query{Name: host})
		if got.Target != "REJECT" {
			t.Errorf("%q: target = %q, want REJECT", host, got.Target)
		}
	}
}

func TestRuleSetCycle(t *testing.T) {
	files := map[string]string{
		"a": "RULE-SET,b",
		"b": "RULE-SET,c",
		"c": "RULE-SET,a",
	}
	_, err := Compile(Options{
		Rules:    mustParse(t, "RULE-SET,a,REJECT", "FINAL,DIRECT"),
		RuleSets: map[string]string{"a": "a", "b": "b", "c": "c"},
		ReadFile: readFileMap(files),
	})
	if err == nil {
		t.Fatal("expected a cycle error")
	}
	if !strings.Contains(err.Error(), "cycle") || !strings.Contains(err.Error(), "a -> b -> c -> a") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRuleSetSelfCycle(t *testing.T) {
	_, err := Compile(Options{
		Rules:    mustParse(t, "RULE-SET,self,REJECT", "FINAL,DIRECT"),
		RuleSets: map[string]string{"self": "self"},
		ReadFile: readFileMap(map[string]string{"self": "RULE-SET,self"}),
	})
	if err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRuleSetDepthLimit(t *testing.T) {
	files := map[string]string{}
	sets := map[string]string{}
	const depth = 8
	for i := 0; i < depth; i++ {
		name := "s" + strconv.Itoa(i)
		sets[name] = name
		if i == depth-1 {
			files[name] = "DOMAIN,deep.example.com"
			continue
		}
		files[name] = "RULE-SET,s" + strconv.Itoa(i+1)
	}
	_, err := Compile(Options{
		Rules:           mustParse(t, "RULE-SET,s0,REJECT", "FINAL,DIRECT"),
		RuleSets:        sets,
		ReadFile:        readFileMap(files),
		MaxRuleSetDepth: 4,
	})
	if err == nil || !strings.Contains(err.Error(), "deeper than 4") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRuleSetMissingFile(t *testing.T) {
	_, err := Compile(Options{
		Rules:    mustParse(t, "RULE-SET,ads,REJECT"),
		RuleSets: map[string]string{"ads": "ads"},
		ReadFile: readFileMap(map[string]string{}),
	})
	if err == nil || !strings.Contains(err.Error(), "rule set \"ads\"") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRuleSetFileErrors(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{name: "final inside a set", content: "FINAL,DIRECT", want: "must not contain FINAL"},
		{name: "target inside a set", content: "DOMAIN,a.example.com,Proxy", want: "must not carry a target"},
		{name: "bad line", content: "DOMAIN", want: "no payload"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Compile(Options{
				Rules:    mustParse(t, "RULE-SET,s,REJECT", "FINAL,DIRECT"),
				RuleSets: map[string]string{"s": "s"},
				ReadFile: readFileMap(map[string]string{"s": tc.content}),
			})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to mention %q", err, tc.want)
			}
			if err != nil && !strings.Contains(err.Error(), "s:1") {
				t.Errorf("error should name the file and line: %v", err)
			}
		})
	}
}

func TestRuleSetLineNumbers(t *testing.T) {
	files := map[string]string{"s": "\n\nDOMAIN,a.example.com\n"}
	p := compileLines(t, []string{"RULE-SET,s,REJECT", "FINAL,DIRECT"},
		Options{RuleSets: map[string]string{"s": "s"}, ReadFile: readFileMap(files)})
	rules := p.Rules()
	if rules[0].Line != 3 || rules[0].Source != "s" {
		t.Fatalf("rule origin = %q line %d, want s:3", rules[0].Source, rules[0].Line)
	}
}

func TestDomainSet(t *testing.T) {
	files := map[string]string{
		"ads.domains": "\ufeff# ad domains\r\nads.example.com\r\nDOMAIN,exact.example.net\r\nDOMAIN-SUFFIX,tracked.example.org\r\n",
	}
	p := compileLines(t, []string{
		"DOMAIN-SET,ads.domains,REJECT",
		"FINAL,DIRECT",
	}, Options{RuleSets: map[string]string{"ads.domains": "ads.domains"}, ReadFile: readFileMap(files)})

	tests := []struct {
		host string
		want string
	}{
		{"ads.example.com", "REJECT"},
		{"sub.ads.example.com", "REJECT"},
		{"exact.example.net", "REJECT"},
		{"sub.exact.example.net", "DIRECT"},
		{"x.tracked.example.org", "REJECT"},
		{"other.example", "DIRECT"},
	}
	for _, tc := range tests {
		got, _ := p.Match(Query{Name: tc.host})
		if got.Target != tc.want {
			t.Errorf("%q: target = %q, want %q", tc.host, got.Target, tc.want)
		}
	}

	s := p.Stats()
	if s.Total != 2 {
		t.Fatalf("a domain set must cost one rule slot, total = %d", s.Total)
	}
	if s.Domains != 1 || s.Suffixes != 2 {
		t.Fatalf("index entries: domains=%d suffixes=%d", s.Domains, s.Suffixes)
	}
}

func TestDomainSetRejectsOtherKinds(t *testing.T) {
	_, err := Compile(Options{
		Rules:    mustParse(t, "DOMAIN-SET,ds,REJECT", "FINAL,DIRECT"),
		RuleSets: map[string]string{"ds": "ds"},
		ReadFile: readFileMap(map[string]string{"ds": "IP-CIDR,10.0.0.0/8"}),
	})
	if err == nil || !strings.Contains(err.Error(), "domain set holds DOMAIN") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRuleSetKindConflict(t *testing.T) {
	files := map[string]string{"shared": "DOMAIN,a.example.com"}
	_, err := Compile(Options{
		Rules: mustParse(t,
			"RULE-SET,shared,REJECT",
			"DOMAIN-SET,shared,REJECT",
			"FINAL,DIRECT"),
		RuleSets: map[string]string{"shared": "shared"},
		ReadFile: readFileMap(files),
	})
	if err == nil || !strings.Contains(err.Error(), "both as") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRuleSetRelativePath(t *testing.T) {
	root := filepath.Join("etc", "melonarc")
	path := filepath.Join(root, "sets", "ads.txt")
	files := map[string]string{path: "DOMAIN,ads.example.com"}
	read := readFileMap(files)
	var seen []string
	p, err := Compile(Options{
		Rules:    mustParse(t, "RULE-SET,ads,REJECT", "FINAL,DIRECT"),
		RuleSets: map[string]string{"ads": filepath.Join("sets", "ads.txt")},
		Root:     root,
		ReadFile: func(p string) ([]byte, error) {
			seen = append(seen, p)
			return read(p)
		},
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(seen) != 1 || seen[0] != path {
		t.Fatalf("read %v, want %q", seen, path)
	}
	if got, _ := p.Match(Query{Name: "ads.example.com"}); got.Target != "REJECT" {
		t.Fatalf("target = %q", got.Target)
	}
}

func TestRuleSetRuleLimit(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 10; i++ {
		b.WriteString("DOMAIN,h" + strconv.Itoa(i) + ".example.com\n")
	}
	_, err := Compile(Options{
		Rules:           mustParse(t, "RULE-SET,s,REJECT", "FINAL,DIRECT"),
		RuleSets:        map[string]string{"s": "s"},
		ReadFile:        readFileMap(map[string]string{"s": b.String()}),
		MaxRuleSetRules: 5,
	})
	if err == nil || !strings.Contains(err.Error(), "more than 5 rules") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCleanLine(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"  # comment", ""},
		{"  ; comment", ""},
		{"// comment", ""},
		{"", ""},
		{"DOMAIN,a.example.com", "DOMAIN,a.example.com"},
		{"DOMAIN,a.example.com # trailing", "DOMAIN,a.example.com"},
		{"DOMAIN,a.example.com\t; trailing", "DOMAIN,a.example.com"},
	}
	for _, tc := range tests {
		if got := cleanLine(tc.in); got != tc.want {
			t.Errorf("cleanLine(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
