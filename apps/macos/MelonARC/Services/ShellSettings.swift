import Foundation

/// The four values `shell.json` may carry.
///
/// The file is sparse on purpose: an omitted key and an empty string mean the same
/// thing ("not set"), so a cleared field disappears instead of turning into `""`.
/// The names match the file the previous shell wrote, so an existing installation
/// keeps its data directory and its core path.
struct ShellOverrides: Codable, Equatable {
    var dataDirectory: String = ""
    var apiAddress: String = ""
    var corePath: String = ""
    var coreConfig: String = ""

    enum CodingKeys: String, CodingKey {
        case dataDirectory = "data_dir"
        case apiAddress = "api_addr"
        case corePath = "core_path"
        case coreConfig = "core_config"
    }

    init() {}

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        dataDirectory = try container.decodeIfPresent(String.self, forKey: .dataDirectory) ?? ""
        apiAddress = try container.decodeIfPresent(String.self, forKey: .apiAddress) ?? ""
        corePath = try container.decodeIfPresent(String.self, forKey: .corePath) ?? ""
        coreConfig = try container.decodeIfPresent(String.self, forKey: .coreConfig) ?? ""
    }

    /// Every value, trimmed, so a hand-edited file with stray spaces still reads.
    func trimmingWhitespace() -> ShellOverrides {
        var copy = self
        copy.dataDirectory = dataDirectory.trimmingCharacters(in: .whitespacesAndNewlines)
        copy.apiAddress = apiAddress.trimmingCharacters(in: .whitespacesAndNewlines)
        copy.corePath = corePath.trimmingCharacters(in: .whitespacesAndNewlines)
        copy.coreConfig = coreConfig.trimmingCharacters(in: .whitespacesAndNewlines)
        return copy
    }

    /// Reads a settings file, or returns the defaults when there is none. A file
    /// that cannot be parsed is reported rather than fatal: the defaults still
    /// work, and the notice tells the user which file to fix.
    static func read(from url: URL, fileManager: FileManager = .default) -> (values: ShellOverrides, notice: String?) {
        guard fileManager.fileExists(atPath: url.path) else {
            return (ShellOverrides(), nil)
        }
        do {
            let data = try Data(contentsOf: url)
            let decoded = try JSONDecoder().decode(ShellOverrides.self, from: data)
            return (decoded.trimmingWhitespace(), nil)
        } catch {
            return (ShellOverrides(), "the settings file could not be read (\(url.path)): \(error.localizedDescription)")
        }
    }
}

/// Everything the shell resolved at launch: the paths, the address, and the core
/// it found.
///
/// Data directory, API address and core paths are decided once, before the first
/// child exists. Changing the first two needs a new shell — the API client and the
/// token path are bound to them — while a changed `core_path` or `core_config`
/// takes effect on the next core restart.
struct ShellSettings {
    let settingsPath: URL
    let dataDirectory: URL
    let apiAddress: APIAddress
    let configurationPath: URL
    let corePath: URL?
    let stored: ShellOverrides
    /// A sentence about the settings file itself, when it exists but could not be
    /// read. Shown in the settings window; never a reason to refuse to start.
    let notice: String?

    var tokenPath: URL { dataDirectory.appendingPathComponent(ShellPaths.tokenFileName) }
    var logPath: URL { dataDirectory.appendingPathComponent(ShellPaths.logFileName) }
    var lockPath: URL { dataDirectory.appendingPathComponent(ShellPaths.lockFileName) }

    /// Resolves the settings the way the shell did before: environment, then file,
    /// then the documented default.
    ///
    /// `directory` exists so a test can point the whole resolution at a scratch
    /// directory. Production always passes `nil` and gets
    /// `~/Library/Application Support/melonarc`.
    static func load(
        environment: [String: String] = ProcessInfo.processInfo.environment,
        fileManager: FileManager = .default,
        executable: URL? = Bundle.main.executableURL,
        directory: URL? = nil
    ) throws -> ShellSettings {
        let shellDirectory: URL
        if let directory {
            shellDirectory = directory
        } else {
            shellDirectory = try ShellPaths.shellDirectory()
        }
        let settingsPath = shellDirectory.appendingPathComponent(ShellPaths.settingsFileName)
        let (stored, notice) = ShellOverrides.read(from: settingsPath, fileManager: fileManager)

        let dataDirectoryValue = firstSet([environment[ShellPaths.dataDirectoryVariable], stored.dataDirectory])
        let dataDirectory = dataDirectoryValue.map { URL(fileURLWithPath: $0, isDirectory: true) } ?? shellDirectory

        let addressValue = firstSet([environment[ShellPaths.apiAddressVariable], stored.apiAddress]) ?? APIAddress.defaultAddress
        let apiAddress = try APIAddress.parse(addressValue)

        let configValue = firstSet([stored.coreConfig as String?])
        let configurationPath = configValue.map { URL(fileURLWithPath: $0) }
            ?? dataDirectory.appendingPathComponent(ShellPaths.configurationFileName)

        let corePath = pickCore(
            candidates: coreSearchPaths(
                explicit: stored.corePath,
                executable: executable,
                pathVariable: environment["PATH"]
            ),
            exists: { fileManager.isExecutableFile(atPath: $0.path) }
        )

        return ShellSettings(
            settingsPath: settingsPath,
            dataDirectory: dataDirectory,
            apiAddress: apiAddress,
            configurationPath: configurationPath,
            corePath: corePath,
            stored: stored,
            notice: notice
        )
    }

    /// Pins the effective data directory for this installation.
    ///
    /// Changing it is refused rather than migrated: the token, configuration,
    /// history, subscription cache and proxy snapshot all live there, and a
    /// partial move would look like a clean install with a stranded takeover
    /// record. The marker lives beside `shell.json`, not inside the directory it
    /// names, so it is still there when a later launch asks for a different one.
    func confirmDataDirectory(fileManager: FileManager = .default) throws {
        let marker = settingsPath
            .deletingLastPathComponent()
            .appendingPathComponent(ShellPaths.dataDirectoryMarkerFileName)
        let requested = dataDirectory.standardizedFileURL.path
        if let data = fileManager.contents(atPath: marker.path),
           let recorded = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
           !recorded.isEmpty {
            if recorded != requested {
                throw ShellError.dataDirectoryChanged(recorded, requested)
            }
            return
        }
        try fileManager.createDirectory(
            at: marker.deletingLastPathComponent(),
            withIntermediateDirectories: true,
            attributes: nil
        )
        try Data((requested + "\n").utf8).write(to: marker, options: .atomic)
    }

    /// Where a core binary is looked for, in this order: next to the shell, the
    /// explicit `core_path`, then each `PATH` entry. The order is part of the
    /// contract — the packaged core sits next to the shell inside `Contents/MacOS`
    /// — so it is a function rather than three call sites.
    static func coreSearchPaths(explicit: String, executable: URL?, pathVariable: String?) -> [URL] {
        var candidates: [URL] = []
        if let directory = executable?.deletingLastPathComponent() {
            candidates.append(directory.appendingPathComponent(ShellPaths.coreExecutableName))
        }
        let explicitPath = explicit.trimmingCharacters(in: .whitespacesAndNewlines)
        if !explicitPath.isEmpty {
            candidates.append(URL(fileURLWithPath: explicitPath))
        }
        if let pathVariable {
            for entry in pathVariable.split(separator: ":", omittingEmptySubsequences: true) {
                candidates.append(URL(fileURLWithPath: String(entry)).appendingPathComponent(ShellPaths.coreExecutableName))
            }
        }
        return candidates
    }

    static func pickCore(candidates: [URL], exists: (URL) -> Bool) -> URL? {
        candidates.first(where: exists)
    }

    /// The `stopped` detail line: what was looked for, in the order it was tried.
    static func coreMissingDetail(explicit: String, executable: URL?, pathVariable: String?) -> String {
        let searched = coreSearchPaths(explicit: explicit, executable: executable, pathVariable: pathVariable)
        let list = searched.map(\.path).joined(separator: ", ")
        return "no \(ShellPaths.coreExecutableName) binary was found; looked in: \(list)"
    }

    /// The first non-blank value.
    private static func firstSet(_ values: [String?]) -> String? {
        for value in values {
            guard let value else { continue }
            let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
            if !trimmed.isEmpty { return trimmed }
        }
        return nil
    }
}
