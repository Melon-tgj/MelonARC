import Darwin
import XCTest

/// The supervisor against fake cores.
///
/// A fake core is a shell script, which is the cheapest way to reproduce the four
/// things that matter without a daemon: an immediate exit, a process that never
/// answers, a process that ignores its first signal, and a program that prints what
/// it was started with.
final class CoreSupervisorTests: XCTestCase {
    // MARK: - Helpers

    private func settings(core: URL?, in directory: URL, port: Int = 47831) throws -> ShellSettings {
        let config = directory.appendingPathComponent("melonarc.conf")
        if !FileManager.default.fileExists(atPath: config.path) {
            let raw = "[General]\nlog-level = error\n[Rule]\nFINAL,DIRECT\n"
            try Data(raw.utf8).write(to: config)
        }
        return ShellSettings(
            settingsPath: directory.appendingPathComponent("shell.json"),
            dataDirectory: directory,
            apiAddress: APIAddress(host: "127.0.0.1", port: port),
            configurationPath: config,
            corePath: core,
            stored: ShellOverrides(),
            notice: nil
        )
    }

    private func fakeCore(in directory: URL, body: String) throws -> URL {
        let url = directory.appendingPathComponent("melonarc-core")
        try Data("#!/bin/sh\n\(body)\n".utf8).write(to: url)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.path)
        return url
    }

    /// Waits for a file the child writes, pumping the run loop while it waits.
    private func waitForFile(_ url: URL, timeout: TimeInterval) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if let text = try? String(contentsOf: url, encoding: .utf8), !text.isEmpty {
                return true
            }
            RunLoop.current.run(until: Date().addingTimeInterval(0.05))
        }
        return false
    }

    // MARK: - Tests

    /// The child is started with the paths the shell itself uses. This is the whole
    /// data-directory policy in one assertion: `-data-dir` is on the command line, so
    /// a configuration that names a different directory cannot split the token from
    /// the client that reads it.
    func testTheChildIsStartedWithThePathsTheShellUses() throws {
        let directory = try TemporaryDirectory("supervisor-arguments")
        let argumentsFile = directory.file("arguments.txt")
        setenv("MELONARC_TEST_ARGUMENTS", argumentsFile.path, 1)
        defer { unsetenv("MELONARC_TEST_ARGUMENTS") }

        let core = try fakeCore(in: directory.url, body: """
        printf '%s\\n' "$@" > "$MELONARC_TEST_ARGUMENTS"
        exit 7
        """)
        let recorder = SnapshotRecorder()
        let supervisor = CoreSupervisor(
            settings: try settings(core: core, in: directory.url, port: 47832),
            startupBudget: 5,
            backoff: { _ in 0.05 }
        )
        supervisor.onChange = { recorder.append($0) }
        supervisor.start()

        XCTAssertTrue(waitForFile(argumentsFile, timeout: 10), "the fake core never wrote its arguments")

        let arguments = try String(contentsOf: argumentsFile, encoding: .utf8)
            .split(separator: "\n")
            .map(String.init)
        XCTAssertTrue(arguments.contains("-config"), arguments.joined(separator: " "))
        XCTAssertTrue(arguments.contains(directory.file("melonarc.conf").path), arguments.joined(separator: " "))
        XCTAssertTrue(arguments.contains("-api-listen"), arguments.joined(separator: " "))
        XCTAssertTrue(arguments.contains("127.0.0.1:47832"), arguments.joined(separator: " "))
        XCTAssertTrue(arguments.contains("-data-dir"), arguments.joined(separator: " "))
        XCTAssertTrue(arguments.contains(directory.url.path), arguments.joined(separator: " "))
        XCTAssertTrue(arguments.contains("-supervise-stdin"), arguments.joined(separator: " "))
    }

    /// Five consecutive failures end the retries; a sixth attempt must not happen.
    func testFiveConsecutiveFailuresEndInCrashed() throws {
        let directory = try TemporaryDirectory("supervisor-crash")
        let core = try fakeCore(in: directory.url, body: "exit 3")
        let recorder = SnapshotRecorder()
        let supervisor = CoreSupervisor(
            settings: try settings(core: core, in: directory.url),
            startupBudget: 5,
            backoff: { _ in 0.05 }
        )
        supervisor.onChange = { recorder.append($0) }
        supervisor.start()

        XCTAssertTrue(
            recorder.wait(until: { snapshots in snapshots.contains { $0.state == .crashed } }, timeout: 20),
            "the supervisor never gave up: \(recorder.all)"
        )
        XCTAssertEqual(recorder.all.last?.failures, CoreSupervisor.maximumFailures)
        XCTAssertEqual(recorder.all.last?.failure?.reason, .exited)
        XCTAssertNil(supervisor.snapshot.pid)
    }

    /// A core that is alive but never answers is stopped at the end of the budget and
    /// the attempt is counted as a failure, with the reason saying so.
    func testACoreThatNeverAnswersFailsAtTheEndOfTheBudget() throws {
        let directory = try TemporaryDirectory("supervisor-budget")
        let core = try fakeCore(in: directory.url, body: "echo 'api: http://127.0.0.1:1'\nsleep 20")
        let recorder = SnapshotRecorder()
        let supervisor = CoreSupervisor(
            settings: try settings(core: core, in: directory.url, port: 47833),
            startupBudget: 1,
            backoff: { _ in 30 }
        )
        supervisor.onChange = { recorder.append($0) }
        supervisor.start()

        XCTAssertTrue(
            recorder.wait(until: { _ in recorder.containsFailure(.startupBudget) }, timeout: 15),
            "the budget never expired: \(recorder.all)"
        )
        supervisor.shutdown {}
        XCTAssertTrue(
            recorder.wait(until: { snapshots in snapshots.last?.state == .stopped }, timeout: 20),
            "the supervisor did not stop: \(recorder.all)"
        )
    }

    /// Shutdown waits for the child rather than leaving it behind: the core is what
    /// restores the machine's proxy settings.
    func testShutdownStopsTheChildAndSettlesOnStopped() throws {
        let directory = try TemporaryDirectory("supervisor-shutdown")
        let core = try fakeCore(in: directory.url, body: """
        trap 'exit 0' TERM
        while true; do sleep 0.2; done
        """)
        let recorder = SnapshotRecorder()
        let supervisor = CoreSupervisor(
            settings: try settings(core: core, in: directory.url, port: 47834),
            startupBudget: 10,
            backoff: { _ in 30 }
        )
        supervisor.onChange = { recorder.append($0) }
        supervisor.start()

        XCTAssertTrue(
            recorder.wait(until: { snapshots in snapshots.contains { $0.pid != nil } }, timeout: 10),
            "the fake core was never started: \(recorder.all)"
        )
        let pid = supervisor.snapshot.pid
        XCTAssertNotNil(pid)

        supervisor.shutdown {}
        XCTAssertTrue(
            recorder.wait(until: { snapshots in snapshots.last?.state == .stopped }, timeout: 20),
            "shutdown did not settle: \(recorder.all)"
        )
        XCTAssertNil(supervisor.snapshot.pid)
        if let pid {
            // A process that ignored sigterm would still be listed here; the
            // supervisor kills it at the grace deadline.
            XCTAssertEqual(kill(pid, 0), -1, "process \(pid) is still running")
        }
    }

    func testAMissingCoreIsReportedWithoutSpawningAnything() throws {
        let directory = try TemporaryDirectory("supervisor-missing")
        let recorder = SnapshotRecorder()
        let supervisor = CoreSupervisor(settings: try settings(core: nil, in: directory.url))
        supervisor.onChange = { recorder.append($0) }
        supervisor.start()

        XCTAssertTrue(
            recorder.wait(until: { _ in recorder.containsFailure(.coreMissing) }, timeout: 5),
            "a missing core was not reported: \(recorder.all)"
        )
        XCTAssertEqual(supervisor.snapshot.state, .stopped)
        XCTAssertTrue(supervisor.snapshot.failure?.detail.contains("melonarc-core") ?? false)
    }

    func testAMissingConfigurationIsReportedBeforeTheChildStarts() throws {
        let directory = try TemporaryDirectory("supervisor-no-config")
        let core = try fakeCore(in: directory.url, body: "exit 0")
        // No configuration is written for this one.
        let settings = ShellSettings(
            settingsPath: directory.file("shell.json"),
            dataDirectory: directory.url,
            apiAddress: APIAddress(host: "127.0.0.1", port: 47835),
            configurationPath: directory.file("absent.conf"),
            corePath: core,
            stored: ShellOverrides(),
            notice: nil
        )
        let recorder = SnapshotRecorder()
        let supervisor = CoreSupervisor(settings: settings)
        supervisor.onChange = { recorder.append($0) }
        supervisor.start()

        XCTAssertTrue(
            recorder.wait(until: { _ in recorder.containsFailure(.configurationMissing) }, timeout: 5),
            "a missing configuration was not reported: \(recorder.all)"
        )
        XCTAssertNil(supervisor.snapshot.pid)
    }

    /// The backoff is the sequence the previous shell documented.
    func testTheBackoffSequenceIsOneTwoThenFiveSeconds() {
        XCTAssertEqual(CoreSupervisor.backoffDelay(after: 0), 1)
        XCTAssertEqual(CoreSupervisor.backoffDelay(after: 1), 1)
        XCTAssertEqual(CoreSupervisor.backoffDelay(after: 2), 2)
        XCTAssertEqual(CoreSupervisor.backoffDelay(after: 3), 5)
        XCTAssertEqual(CoreSupervisor.backoffDelay(after: 99), 5)
    }
}
