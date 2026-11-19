import Foundation

/// Small formatters the panels share.
enum Formatting {
    /// An uptime as `3h 07m`, `4m 12s` or `9s`.
    ///
    /// Deliberately not a `DateComponentsFormatter`: the panel wants the same three
    /// shapes at every length, and a localized "about 1 hour" is less useful next to
    /// a process that has been up for 61 seconds.
    static func uptime(_ seconds: Double) -> String {
        guard seconds.isFinite, seconds >= 0 else { return "—" }
        let total = Int(seconds.rounded())
        let hours = total / 3600
        let minutes = (total % 3600) / 60
        let remainder = total % 60
        if hours > 0 { return String(format: "%dh %02dm", hours, minutes) }
        if minutes > 0 { return String(format: "%dm %02ds", minutes, remainder) }
        return String(format: "%ds", remainder)
    }

    /// A path shortened for a table cell, keeping the last components.
    static func path(_ value: String?) -> String {
        guard let value, !value.isEmpty else { return "—" }
        let parts = value.split(separator: "/", omittingEmptySubsequences: true)
        guard parts.count > 4 else { return value }
        return "…/" + parts.suffix(3).joined(separator: "/")
    }
}
