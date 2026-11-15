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
	for _, p := range cfg.Proxies {
		entry, unusable := outbound.IsUnusable(p.Type)
		if !unusable {
			continue
		}
		logger.Warn("outbound protocol is known to be unusable in this build",
			"proxy", p.Name, "type", entry.Protocol, "reason", entry.Reason)
	}
}
