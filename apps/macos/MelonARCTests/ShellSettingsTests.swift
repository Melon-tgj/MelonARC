import XCTest

final class ShellSettingsTests: XCTestCase {
    // MARK: - The core search order

    func testTheCoreIsLookedForNextToTheShellThenExplicitlyThenOnThePath() {
        let executable = URL(fileURLWithPath: "/Applications/MelonARC.app/Contents/MacOS/MelonARC")
        let paths = ShellSettings.coreSearchPaths(
            explicit: "/opt/melonarc/melonarc-core",
            executable: executable,
            pathVariable: "/usr/bin:/usr/local/bin"
        )
        XCTAssertEqual(paths.map(\.path), [
            "/Applications/MelonARC.app/Contents/MacOS/melonarc-core",
            "/opt/melonarc/melonarc-core",
            "/usr/bin/melonarc-core",
            "/usr/local/bin/melonarc-core",
        ])
    }

    func testThePackagedCoreWins() {
        // The core the application ships with sits next to the executable inside
        // Contents/MacOS, which is the first candidate. Nothing has to be configured
        // for a normal installation to work.
        let executable = URL(fileURLWithPath: "/Applications/MelonARC.app/Contents/MacOS/MelonARC")
        let existing = "/Applications/MelonARC.app/Contents/MacOS/melonarc-core"
        let chosen = ShellSettings.pickCore(
            candidates: ShellSettings.coreSearchPaths(explicit: "/tmp/other", executable: executable, pathVariable: nil),
            exists: { $0.path == existing }
        )
        XCTAssertEqual(chosen?.path, existing)
    }

    func testAnEmptyExplicitPathAddsNoCandidate() {
        let paths = ShellSettings.coreSearchPaths(explicit: "   ", executable: nil, pathVariable: nil)
        XCTAssertTrue(paths.isEmpty)
    }

    func testTheMissingDetailNamesEveryCandidateInOrder() {
        let detail = ShellSettings.coreMissingDetail(
            explicit: "/opt/melonarc-core",
            executable: URL(fileURLWithPath: "/Applications/MelonARC.app/Contents/MacOS/MelonARC"),
            pathVariable: "/usr/bin"
        )
        XCTAssertTrue(detail.contains("melonarc-core"), detail)
        XCTAssertTrue(detail.contains("/Applications/MelonARC.app/Contents/MacOS/melonarc-core"), detail)
        XCTAssertTrue(detail.contains("/opt/melonarc-core"), detail)
        XCTAssertTrue(detail.contains("/usr/bin/melonarc-core"), detail)
    }

    // MARK: - shell.json

    func testTheSettingsFileIsReadWithItsSparseKeys() throws {
        let directory = try TemporaryDirectory("settings")
        let file = directory.file("shell.json")
        let raw = #"{"data_dir":"/tmp/state","core_path":"/opt/core/melonarc-core","core_config":"/tmp/state/custom.conf"}"#
        try Data(raw.utf8).write(to: file)

        let (values, notice) = ShellOverrides.read(from: file)
        XCTAssertNil(notice)
        XCTAssertEqual(values.dataDirectory, "/tmp/state")
        XCTAssertEqual(values.corePath, "/opt/core/melonarc-core")
        XCTAssertEqual(values.coreConfig, "/tmp/state/custom.conf")
        // An omitted key is "not set", which is the same as an empty string.
        XCTAssertEqual(values.apiAddress, "")
    }

    func testAMissingFileReadsAsNoOverridesAndNoComplaint() throws {
        let directory = try TemporaryDirectory("settings")
        let (values, notice) = ShellOverrides.read(from: directory.file("shell.json"))
        XCTAssertNil(notice)
        XCTAssertEqual(values, ShellOverrides())
    }

    func testABrokenFileIsReportedButStillYieldsTheDefaults() throws {
        let directory = try TemporaryDirectory("settings")
        let file = directory.file("shell.json")
        try Data("{not json".utf8).write(to: file)

        let (values, notice) = ShellOverrides.read(from: file)
        XCTAssertEqual(values, ShellOverrides())
        XCTAssertNotNil(notice)
        XCTAssertTrue(notice?.contains("shell.json") ?? false, notice ?? "")
    }

    func testUnknownKeysAreIgnored() throws {
        let directory = try TemporaryDirectory("settings")
        let file = directory.file("shell.json")
        try Data(#"{"data_dir":"/tmp/a","future_key":"ignored"}"#.utf8).write(to: file)

        let (values, notice) = ShellOverrides.read(from: file)
        XCTAssertNil(notice)
        XCTAssertEqual(values.dataDirectory, "/tmp/a")
    }

    // MARK: - Resolution

    func testTheEnvironmentWinsOverTheFileAndTheFileOverTheDefault() throws {
        let directory = try TemporaryDirectory("resolve")
        let file = directory.file("shell.json")
        try Data(#"{"data_dir":"/tmp/from-file","api_addr":"127.0.0.1:8000"}"#.utf8).write(to: file)

        let fromFile = try ShellSettings.load(
            environment: [:],
            executable: nil,
            directory: directory.url
        )
        XCTAssertEqual(fromFile.dataDirectory.path, "/tmp/from-file")
        XCTAssertEqual(fromFile.apiAddress.port, 8000)

        let fromEnvironment = try ShellSettings.load(
            environment: [
                ShellPaths.dataDirectoryVariable: "/tmp/from-environment",
                ShellPaths.apiAddressVariable: "127.0.0.1:9000",
            ],
            executable: nil,
            directory: directory.url
        )
        XCTAssertEqual(fromEnvironment.dataDirectory.path, "/tmp/from-environment")
        XCTAssertEqual(fromEnvironment.apiAddress.port, 9000)
    }

    func testTheDefaultDataDirectoryIsTheDirectoryOfTheSettingsFile() throws {
        let directory = try TemporaryDirectory("resolve")
        let settings = try ShellSettings.load(environment: [:], executable: nil, directory: directory.url)
        XCTAssertEqual(settings.dataDirectory.path, directory.url.path)
        XCTAssertEqual(settings.settingsPath.path, directory.file("shell.json").path)
        XCTAssertEqual(settings.tokenPath.path, directory.file("api-token").path)
        XCTAssertEqual(settings.logPath.path, directory.file("core.log").path)
        XCTAssertEqual(settings.lockPath.path, directory.file("shell.lock").path)
        XCTAssertEqual(settings.configurationPath.path, directory.file("melonarc.conf").path)
        XCTAssertEqual(settings.apiAddress.label, APIAddress.defaultAddress)
    }

    func testAConfiguredDataDirectoryMovesEveryFileWithIt() throws {
        let directory = try TemporaryDirectory("resolve")
        let file = directory.file("shell.json")
        try Data(#"{"data_dir":"/tmp/moved"}"#.utf8).write(to: file)

        let settings = try ShellSettings.load(environment: [:], executable: nil, directory: directory.url)
        XCTAssertEqual(settings.dataDirectory.path, "/tmp/moved")
        XCTAssertEqual(settings.tokenPath.path, "/tmp/moved/api-token")
        XCTAssertEqual(settings.configurationPath.path, "/tmp/moved/melonarc.conf")
        // The settings file itself always stays in the default directory: it is the
        // file that names a different data directory, so it cannot live inside it.
        XCTAssertEqual(settings.settingsPath.path, directory.file("shell.json").path)
    }

    func testTheFirstDataDirectoryIsRecordedAndTheSameOneIsAccepted() throws {
        let directory = try TemporaryDirectory("data-dir-marker")
        let first = try ShellSettings.load(environment: [:], executable: nil, directory: directory.url)
        try first.confirmDataDirectory()

        let again = try ShellSettings.load(environment: [:], executable: nil, directory: directory.url)
        XCTAssertNoThrow(try again.confirmDataDirectory())
        XCTAssertTrue(FileManager.default.fileExists(atPath: directory.file("data-dir").path))
    }

    func testChangingTheRecordedDataDirectoryIsRefused() throws {
        let directory = try TemporaryDirectory("data-dir-marker")
        let moved = try TemporaryDirectory("data-dir-moved")
        try Data(#"{"data_dir":"\#(directory.url.path)"}"#.utf8).write(to: directory.file("shell.json"))
        let first = try ShellSettings.load(environment: [:], executable: nil, directory: directory.url)
        try first.confirmDataDirectory()

        try Data(#"{"data_dir":"\#(moved.url.path)"}"#.utf8).write(to: directory.file("shell.json"))
        let second = try ShellSettings.load(environment: [:], executable: nil, directory: directory.url)
        XCTAssertThrowsError(try second.confirmDataDirectory()) { error in
            guard let shellError = error as? ShellError else {
                return XCTFail("unexpected error: \(error)")
            }
            XCTAssertEqual(shellError.code, "data_directory_changed")
        }
    }

    func testAnAddressThatIsNotLoopbackStopsTheShell() throws {
        let directory = try TemporaryDirectory("resolve")
        let file = directory.file("shell.json")
        try Data(#"{"api_addr":"192.168.1.4:7946"}"#.utf8).write(to: file)

        XCTAssertThrowsError(try ShellSettings.load(environment: [:], executable: nil, directory: directory.url))
    }
}
