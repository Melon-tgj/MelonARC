import Foundation

/// Where the shell and the core keep their files.
///
/// The layout is the one the Go core already assumes, so an installation that has
/// a `shell.json` from an earlier build keeps working:
///
///     <config-home>/melonarc/shell.json    the shell's own settings
///     <data-dir>/api-token                 written by the core, read here
///     <data-dir>/melonarc.conf             the core's configuration
///     <data-dir>/core.log                  the core's output, appended
///     <data-dir>/shell.lock                held while this process runs
///
/// `config-home` is `~/Library/Application Support`: the application support
/// directory in the user domain, which is what Go's `os.UserConfigDir` returns on
/// macOS, so both sides compute the same default without being told.
enum ShellPaths {
    static let directoryName = "melonarc"
    static let settingsFileName = "shell.json"
    static let tokenFileName = "api-token"
    static let configurationFileName = "melonarc.conf"
    static let logFileName = "core.log"
    static let lockFileName = "shell.lock"
    static let coreExecutableName = "melonarc-core"

    /// Environment overrides. They exist for the same reason they existed in the
    /// previous shell: a test or a developer has to be able to point the shell at
    /// a scratch directory, and a test cannot write to the real one.
    static let dataDirectoryVariable = "MELONARC_DATA_DIR"
    static let apiAddressVariable = "MELONARC_API_ADDR"

    /// `~/Library/Application Support`.
    static func configurationHome() throws -> URL {
        guard let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else {
            throw ShellError.noConfigurationDirectory
        }
        return base
    }

    /// `<config-home>/melonarc`, the directory `shell.json` lives in.
    static func shellDirectory() throws -> URL {
        try configurationHome().appendingPathComponent(directoryName, isDirectory: true)
    }

    /// The default data directory: the directory the settings file sits in.
    /// Deriving it from the settings path keeps the two from drifting apart.
    static func defaultDataDirectory() throws -> URL {
        try shellDirectory()
    }
}

/// The failures the shell itself can hit before the core is involved.
///
/// A case carries a sentence that names the file or the value it is about; the
/// interface shows its own translation and keeps this line for a bug report.
enum ShellError: Error, Equatable, LocalizedError {
    case noConfigurationDirectory
    case invalidAddress(String)
    case unusableDataDirectory(String)

    var errorDescription: String? {
        switch self {
        case .noConfigurationDirectory:
            return "there is no Application Support directory for this user"
        case .invalidAddress(let detail):
            return "the API address is not a loopback endpoint: \(detail)"
        case .unusableDataDirectory(let detail):
            return "the data directory is not usable: \(detail)"
        }
    }
}
