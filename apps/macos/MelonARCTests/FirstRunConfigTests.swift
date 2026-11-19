import XCTest

final class FirstRunConfigTests: XCTestCase {
    func testTheFirstRunWritesTheFileOnce() throws {
        let directory = try TemporaryDirectory("first-run")
        let config = directory.file("melonarc.conf")

        XCTAssertTrue(try FirstRunConfig.ensure(at: config), "a missing file must be written")
        let text = try String(contentsOf: config, encoding: .utf8)
        XCTAssertTrue(text.contains("FINAL,DIRECT"), text)
        XCTAssertTrue(text.contains("api-listen = 127.0.0.1:7946"), text)
        XCTAssertTrue(text.contains("[General]"), text)
        XCTAssertTrue(text.contains("[Rule]"), text)
    }

    /// The data directory is a launch argument, not a line in this file: a second
    /// opinion here is what used to put the token where the shell does not look.
    func testTheFirstRunDoesNotSetADataDirectory() throws {
        let lines = FirstRunConfig.contents
            .split(separator: "\n", omittingEmptySubsequences: false)
            .map { $0.trimmingCharacters(in: .whitespaces) }
        XCTAssertFalse(lines.contains { $0.hasPrefix("data-dir") }, FirstRunConfig.contents)
    }

    func testAnExistingConfigurationIsNeverRewritten() throws {
        let directory = try TemporaryDirectory("first-run")
        let config = directory.file("melonarc.conf")
        let mine = "# mine\n[General]\nlog-level = debug\n[Rule]\nFINAL,DIRECT\n"
        try Data(mine.utf8).write(to: config)

        XCTAssertFalse(try FirstRunConfig.ensure(at: config))
        XCTAssertEqual(try String(contentsOf: config, encoding: .utf8), mine)
    }

    func testTheDirectoryAndTheFileArePrivate() throws {
        let directory = try TemporaryDirectory("first-run")
        let data = directory.file("state")
        let config = data.appendingPathComponent("melonarc.conf")

        XCTAssertTrue(try FirstRunConfig.ensure(at: config))

        let manager = FileManager.default
        let directoryMode = try manager.attributesOfItem(atPath: data.path)[.posixPermissions] as? NSNumber
        let fileMode = try manager.attributesOfItem(atPath: config.path)[.posixPermissions] as? NSNumber
        XCTAssertEqual(directoryMode?.intValue, 0o700)
        XCTAssertEqual(fileMode?.intValue, 0o600)
    }
}
