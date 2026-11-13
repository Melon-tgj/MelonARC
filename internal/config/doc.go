// Package config parses and validates the native INI-style configuration.
//
// The format is plain text with five sections: [General], [Proxy],
// [Proxy Group], [Rule] and [Host]. Parsing is separate from validation so that
// a caller can report every problem at once, and a configuration that fails
// Validate must never take effect.
//
// A [Rule] section holds rule lines plus the declarations of external rule
// sets:
//
//	rule-set ads = ./rulesets/ads.txt
//	DOMAIN-SUFFIX,example.com,Proxy
//	RULE-SET,ads,REJECT
//	FINAL,DIRECT
//
// Hot reload is driven by the local API: the daemon re-reads the file it loaded,
// validates it again and only then activates it, so a file that does not
// validate never replaces the one in force. Share link and subscription import
// are later stages.
package config
