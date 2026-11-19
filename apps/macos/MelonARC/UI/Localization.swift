import Foundation

/// Lookups for keys that are only known at runtime.
///
/// Keys written in the source as literals go through `Text("…")` or
/// `String(localized: "…")`, which is what the string catalog is compiled against.
/// A panel's title and a core state's name are decided by a value, so they are
/// looked up here instead — against the same catalog, so a missing translation is
/// still visible as the key itself rather than as an empty row.
enum Localization {
    static func text(_ key: String) -> String {
        NSLocalizedString(key, bundle: .main, comment: "")
    }

    /// Fills the placeholders of a localized template. The catalog is checked for
    /// placeholder parity by `scripts/check-strings.py`, so the two languages cannot
    /// disagree about how many arguments a sentence takes.
    static func format(_ key: String, _ arguments: CVarArg...) -> String {
        String(format: NSLocalizedString(key, bundle: .main, comment: ""), arguments: arguments)
    }
}
