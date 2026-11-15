package config

import "testing"

// FuzzParse feeds hostile configuration text to the syntax parser.
//
// Parse is the half of loading that reads text a person or a tool wrote, so it
// is the half that sees unbalanced brackets, stray commas, quotes that never
// close and section names nobody intended. The invariant is narrow on purpose:
// every input produces either a configuration or an accumulated error, never a
// panic, and the configuration value is always present so a caller can show the
// problems it did find.
//
// The seeds start the corpus at both outcomes: the sample configuration from
// config_test.go, the accepted oddities (a byte order mark, carriage returns,
// quoted values with trailing comments), and the malformed shapes
// TestParseSyntaxErrors rejects.
func FuzzParse(f *testing.F) {
	seeds := []string{
		sampleConfig,
		// The smallest configuration that parses.
		"[Rule]\nFINAL,DIRECT\n",
		// A byte order mark and carriage returns, both accepted.
		"\ufeff[General]\r\nlog-level = warn\r\n[Rule]\r\nFINAL,DIRECT\r\n",
		// A quoted value and a trailing comment on an entry and on a rule.
		"[Proxy]\nA = ss, 1.1.1.1, 80, \"pass word\" # trailing note\n[Rule]\nFINAL,DIRECT ; trailing\n",
		// Malformed shapes: an entry before any section, an unknown section, a
		// header that never closes, a line without an equals sign.
		"log-level = info\n",
		"[Bogus]\na = b\n",
		"[General\na = b\n",
		"[General]\nlog-level info\n",
		// A repeated key and a repeated definition.
		"[General]\nlog-level = info\nlog-level = debug\n",
		"[Proxy]\nA = ss, 1.1.1.1, 80, x\nA = ss, 1.1.1.2, 80, x\n",
		// A rule whose type is unknown, and a rule set declaration with no equals.
		"[Rule]\nBOGUS,a,Proxy\n",
		"[Rule]\nrule-set ads\n",
		// An address that is not an address, and a group option that does not
		// parse.
		"[Host]\na.example.com = 300.1.1.1\n",
		"[Proxy Group]\nG = url-test, A, url=http://x, interval=lots\n",
		// No input at all.
		"",
	}
	for _, seed := range seeds {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		cfg, err := Parse(data)
		if cfg == nil && err == nil {
			// A nil configuration with no error would be the one combination a
			// caller cannot handle: there is nothing to activate and nothing to
			// report.
			t.Fatal("Parse returned no configuration and no error")
		}
	})
}
