import XCTest

/// The real daemon, when the build job provides one.
///
/// `MELONARC_TEST_CORE` is the path of the darwin/arm64 core the job builds before
/// `xcodebuild test`. Without it these tests skip, so a developer can run the suite
/// without a core and still get every other test — and so a skip is never mistaken
/// for a pass: the job sets the variable, which turns "skipped" into "run".
final class SidecarTests: XCTestCase {
    // MARK: - Fixtures

    private func corePath() throws -> URL {
        guard let value = ProcessInfo.processInfo.environment["MELONARC_TEST_CORE"], !value.isEmpty else {
            throw XCTSkip("MELONARC_TEST_CORE is not set; the real-core tests were skipped")
        }
        let url = URL(fileURLWithPath: value)
        guard FileManager.default.isExecutableFile(atPath: url.path) else {
            throw XCTSkip("\(value) is not an executable file")
        }
        return url
    }

    private func makeSettings(core: URL, directory: TemporaryDirectory, port: Int) throws -> ShellSettings {
        let config = directory.file("melonarc.conf")
        let raw = """
        [General]
        log-level = error
        api-listen = 127.0.0.1:\(port)
        http-listen = 127.0.0.1:\(port + 1)
        socks5-listen = 127.0.0.1:\(port + 2)

        [Rule]
        FINAL,DIRECT
        """
        try Data(raw.utf8).write(to: config)
        return ShellSettings(
            settingsPath: directory.file("shell.json"),
            dataDirectory: directory.url,
            apiAddress: APIAddress(host: "127.0.0.1", port: port),
            configurationPath: config,
            corePath: core,
            stored: ShellOverrides(),
            notice: nil
        )
    }

    /// Runs an async call to completion from a synchronous test.
    ///
    /// The supervisor and the client are both asynchronous; XCTest runs this test on
    /// the main thread, and the URL session does its work on its own queue, so a
    /// semaphore is enough and keeps the pumping of the run loop in one place.
    private func fetchStatus(_ client: APIClient) throws -> StatusView {
        let semaphore = DispatchSemaphore(value: 0)
        var outcome: Result<StatusView, Error>?
        Task {
            do {
                outcome = .success(try await client.status())
            } catch {
                outcome = .failure(error)
            }
            semaphore.signal()
        }
        guard semaphore.wait(timeout: .now() + 20) == .success, let outcome else {
            throw APIError.unreachable("the status call did not finish")
        }
        return try outcome.get()
    }

    // MARK: - Tests

    func testTheRealCoreBecomesReadyAndAnswersWithTheToken() throws {
        let core = try corePath()
        let directory = try TemporaryDirectory("sidecar")
        let settings = try makeSettings(core: core, directory: directory, port: 47841)
        let recorder = SnapshotRecorder()
        let supervisor = CoreSupervisor(settings: settings)
        supervisor.onChange = { recorder.append($0) }
        supervisor.start()

        XCTAssertTrue(
            recorder.wait(until: { snapshots in snapshots.contains { $0.state == .running } }, timeout: 30),
            "the core never became ready: \(recorder.all)"
        )

        // The token in the file is the one the client sends: this is the whole point
        // of passing -data-dir, and it is checked rather than assumed.
        let token = try String(contentsOf: settings.tokenPath, encoding: .utf8)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        XCTAssertFalse(token.isEmpty)

        let client = APIClient(address: settings.apiAddress, tokenURL: settings.tokenPath)
        let status = try fetchStatus(client)
        XCTAssertFalse(status.version.isEmpty)
        XCTAssertEqual(status.ruleCount, 1)
        XCTAssertEqual(status.configPath, settings.configurationPath.path)

        supervisor.shutdown {}
        XCTAssertTrue(
            recorder.wait(until: { snapshots in snapshots.last?.state == .stopped }, timeout: 30),
            "the core did not stop: \(recorder.all)"
        )
    }

    func testAWrongTokenIsAnsweredWithUnauthorized() throws {
        let core = try corePath()
        let directory = try TemporaryDirectory("sidecar-token")
        let settings = try makeSettings(core: core, directory: directory, port: 47845)
        let recorder = SnapshotRecorder()
        let supervisor = CoreSupervisor(settings: settings)
        supervisor.onChange = { recorder.append($0) }
        supervisor.start()
        defer { supervisor.shutdown {} }

        XCTAssertTrue(
            recorder.wait(until: { snapshots in snapshots.contains { $0.state == .running } }, timeout: 30),
            "the core never became ready: \(recorder.all)"
        )

        // The daemon does not re-read its token, so overwriting the file with a
        // well-formed but different value is exactly the stale-token case the
        // interface has to explain instead of blaming the network.
        let wrong = String(repeating: "a", count: 43)
        try Data("\(wrong)\n".utf8).write(to: settings.tokenPath)

        let client = APIClient(address: settings.apiAddress, tokenURL: settings.tokenPath)
        XCTAssertThrowsError(try fetchStatus(client)) { error in
            XCTAssertEqual(error as? APIError, .unauthorized)
        }
    }

    /// Every start writes a new token, which is why the client re-reads the file
    /// instead of remembering one.
    func testEveryStartWritesANewToken() throws {
        let core = try corePath()
        let directory = try TemporaryDirectory("sidecar-rotation")
        let settings = try makeSettings(core: core, directory: directory, port: 47849)

        let first = CoreSupervisor(settings: settings)
        let firstRecorder = SnapshotRecorder()
        first.onChange = { firstRecorder.append($0) }
        first.start()
        XCTAssertTrue(
            firstRecorder.wait(until: { $0.contains { $0.state == .running } }, timeout: 30),
            "the first core never became ready: \(firstRecorder.all)"
        )
        let firstToken = try String(contentsOf: settings.tokenPath, encoding: .utf8)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        first.shutdown {}
        XCTAssertTrue(
            firstRecorder.wait(until: { $0.last?.state == .stopped }, timeout: 30),
            "the first core did not stop: \(firstRecorder.all)"
        )

        let second = CoreSupervisor(settings: settings)
        let secondRecorder = SnapshotRecorder()
        second.onChange = { secondRecorder.append($0) }
        second.start()
        XCTAssertTrue(
            secondRecorder.wait(until: { $0.contains { $0.state == .running } }, timeout: 30),
            "the second core never became ready: \(secondRecorder.all)"
        )
        let secondToken = try String(contentsOf: settings.tokenPath, encoding: .utf8)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        second.shutdown {}
        XCTAssertTrue(
            secondRecorder.wait(until: { $0.last?.state == .stopped }, timeout: 30),
            "the second core did not stop: \(secondRecorder.all)"
        )

        XCTAssertFalse(firstToken.isEmpty)
        XCTAssertFalse(secondToken.isEmpty)
        XCTAssertNotEqual(firstToken, secondToken, "the token must not survive a restart")
    }

    /// A listener that is already bound is reported as a conflict, not as an
    /// unexplained exit: the sentence comes from the core's own error line.
    func testAPortThatIsAlreadyBoundIsReportedAsAConflict() throws {
        let core = try corePath()
        let first = try TemporaryDirectory("sidecar-first")
        let second = try TemporaryDirectory("sidecar-second")

        let owner = CoreSupervisor(settings: try makeSettings(core: core, directory: first, port: 47853))
        let ownerRecorder = SnapshotRecorder()
        owner.onChange = { ownerRecorder.append($0) }
        owner.start()
        XCTAssertTrue(
            ownerRecorder.wait(until: { $0.contains { $0.state == .running } }, timeout: 30),
            "the first core never became ready: \(ownerRecorder.all)"
        )
        defer { owner.shutdown {} }

        let contender = CoreSupervisor(
            settings: try makeSettings(core: core, directory: second, port: 47853),
            backoff: { _ in 30 }
        )
        let contenderRecorder = SnapshotRecorder()
        contender.onChange = { contenderRecorder.append($0) }
        contender.start()

        XCTAssertTrue(
            contenderRecorder.wait(until: { _ in contenderRecorder.containsFailure(.portInUse) }, timeout: 30),
            "the conflict was not recognised: \(contenderRecorder.all)"
        )
        contender.shutdown {}
    }
}
