package main

import (
	"log/slog"

	"github.com/melon-tgj/melonarc/internal/config"
	"github.com/melon-tgj/melonarc/internal/outbound"
)

// warnUnusableProtocols reports every [Proxy] entry whose protocol this build
// implements but must not be relied on yet.
//
// It warns and does not reject. A configuration that lists such a node is a
// configuration whose author already has it — in a subscription, in a file
// carried over from another tool, in an import that would otherwise fail at
// startup. Refusing it would take the working parts of the file down with the
// unusable one, so the node is loaded, the member stays unusable, and the log
// says why. The support matrix in README.md is where the same statement is
// written for a reader.
//
// It runs on both the load paths: startup, and a reload that gets as far as
// building the dialers.
func warnUnusableProtocols(cfg *config.Config, logger *slog.Logger) {
	warnUnusable(cfg, logger, outbound.IsUnusable)
}

// warnUnusable is the mechanism behind warnUnusableProtocols. The lookup is a
// parameter because the shipped list is empty: a test that has to prove the
// message names the node and never one of its arguments must hand in the entry
// it exercises, which is exactly what the list no longer provides.
func warnUnusable(cfg *config.Config, logger *slog.Logger, lookup func(string) (outbound.Unusable, bool)) {
	for _, p := range cfg.Proxies {
		entry, unusable := lookup(p.Type)
		if !unusable {
			continue
		}
		logger.Warn("outbound protocol is known to be unusable in this build",
			"proxy", p.Name, "type", entry.Protocol, "reason", entry.Reason)
	}
}
