import Darwin
import Foundation

/// What the supervised core is doing.
///
/// The four names are the contract with the interface: `rawValue` is the suffix of
/// the localization key (`core.state.running`), so adding a state means adding a
/// case and its translation, and nothing else.
enum CoreState: String, Equatable {
    case starting
    case running
    case stopped
    case crashed

    var localizationKey: String { "core.state.\(rawValue)" }
}

/// Why the last attempt ended.
///
/// The reason is translated; the detail is the English line a bug report needs and
/// is never used as a sentence on screen.
struct CoreFailure: Equatable {
    enum Reason: String, Equatable {
        /// No `melonarc-core` was found anywhere in the search order.
        case coreMissing = "core_missing"
        /// The configuration file the core would be started with is not there.
        case configurationMissing = "configuration_missing"
        /// A listener the core needs is already bound.
        case portInUse = "port_in_use"
        /// The core exited on its own with a status.
        case exited = "exited"
        /// The core was killed by a signal.
        case signalled = "signalled"
        /// The core never answered within the start-up budget.
        case startupBudget = "startup_budget"
        /// The child could not be created at all.
        case launchFailed = "launch_failed"
    }

    let reason: Reason
    let detail: String

    var localizationKey: String { "core.failure.reason.\(reason.rawValue)" }
}

/// An immutable view of the supervisor, which is what the interface draws.
struct CoreSnapshot: Equatable {
    var state: CoreState = .stopped
    var pid: Int32?
    var startedAt: Date?
    var restarts: Int = 0
    var failures: Int = 0
    var failure: CoreFailure?
}

/// Hosts one `melonarc-core` process for the whole life of the application.
///
/// It is a host, not a supervisor daemon: one child, one timer that ticks twice a
/// second, and a state the window reads. The rules are the ones the previous shell
/// documented and the milestone keeps:
///
/// * a child that is alive but has not answered an authenticated `/v1/status` is
///   `starting`; it gets the start-up budget to become `running`, after which it is
///   stopped and the attempt counts as a failure;
/// * a failure waits 1, 2 and then 5 seconds and tries again, up to five
///   consecutive failures; the sixth state is `crashed` and nothing is retried
///   until the user asks for a restart;
/// * reaching `running` clears the count, so a core that fails once a week keeps
///   being restarted.
///
/// Two things are different from the previous shell on purpose. The readiness
/// handshake goes through the pipe the child inherits: the core prints the bound
/// API address and the token path before it answers, so "the port is bound and the
/// token exists" is observed rather than guessed. And shutdown waits as long as the
/// core's own shutdown budget, because restoring the machine's proxy settings is
/// part of it — three seconds was not enough for the platforms that write several
/// settings per network service.
///
/// Every property below is touched only on `queue`; the interface reads
/// `snapshot`, which is a copy taken under that queue.
final class CoreSupervisor {
    /// How long a spawned core may take to answer before the attempt fails.
    static let defaultStartupBudget: TimeInterval = 15
    /// The supervisor's tick. Fast enough to notice an exit, slow enough to be
    /// invisible in a process list.
    static let tickInterval: TimeInterval = 0.5
    /// Consecutive failures after which the supervisor gives up.
    static let maximumFailures = 5
    /// How long a child gets to exit and restore the machine before it is killed.
    /// The core's own shutdown budget is five seconds; this leaves room for the
    /// system tools it calls.
    static let shutdownGrace: TimeInterval = 12
    /// One readiness probe. The core answers loopback requests in microseconds.
    static let probeTimeout: TimeInterval = 5

    /// Delivered on the main queue after every state change. Set it before
    /// `start()`; the supervisor never replaces it.
    var onChange: ((CoreSnapshot) -> Void)?

    private let settings: ShellSettings
    private let budget: TimeInterval
    private let backoff: (Int) -> TimeInterval
    private let queue = DispatchQueue(label: "org.melonarc.core-supervisor")
    private static let outputBatchSize = 64 * 1024

    private var timer: DispatchSourceTimer?
    private var state: CoreState = .stopped
    private var child: Process?
    private var inputPipe: Pipe?
    private var outputSource: DispatchSourceRead?
    private var logHandle: FileHandle?
    private var spawnedAt: Date?
    private var restartAt: Date?
    private var failures = 0
    private var restarts = 0
    private var failure: CoreFailure?
    private var stopping = false
    private var probeRunning = false
    private var announced = false
    /// A bounded tail of the child's output, used to recognise a known failure
    /// from the sentence the core printed.
    private var captured = Data()
    /// Set when the shell stops the child itself, so the exit is reported with the
    /// reason the shell knows instead of "exited with status".
    private var pendingFailure: CoreFailure?
    /// Why the child is being stopped, which decides what its exit means.
    private var intent: Intent = .supervise

    private enum Intent {
        case supervise
        case restart
        case shutdown
    }

    init(
        settings: ShellSettings,
        startupBudget: TimeInterval = CoreSupervisor.defaultStartupBudget,
        backoff: @escaping (Int) -> TimeInterval = CoreSupervisor.backoffDelay
    ) {
        self.settings = settings
        self.budget = startupBudget
        self.backoff = backoff
    }

    // MARK: - Lifecycle

    /// Starts the tick and makes the first attempt.
    func start() {
        queue.async {
            guard self.timer == nil, !self.stopping else { return }
            let timer = DispatchSource.makeTimerSource(queue: self.queue)
            timer.schedule(deadline: .now() + CoreSupervisor.tickInterval,
                           repeating: CoreSupervisor.tickInterval,
                           leeway: .milliseconds(100))
            timer.setEventHandler { [weak self] in self?.tick() }
            timer.resume()
            self.timer = timer
            self.launch()
        }
    }

    /// Stops the child, forgets the failure count and starts again. This is the
    /// button the overview shows when the core is stopped or crashed.
    func restart() {
        queue.async {
            guard !self.stopping else { return }
            self.failures = 0
            self.failure = nil
            self.restartAt = nil
            guard let running = self.child else {
                self.launch()
                return
            }
            self.intent = .restart
            if running.isRunning {
                running.terminate()
            }
            // A child that ignores SIGTERM must not leave the window in a state
            // that says "restarting" forever.
            self.awaitExit(of: running, deadline: Date().addingTimeInterval(CoreSupervisor.shutdownGrace)) { [weak self] in
                self?.queue.async { self?.restartFinished() }
            }
        }
    }

    /// Stops the child for good and calls `completion` on the main queue when the
    /// core is gone, or after the grace period has passed.
    ///
    /// The caller is the quit path: `applicationShouldTerminate` has to answer
    /// asynchronously, and the answer must not arrive before the core had its chance
    /// to put the machine's proxy settings back.
    func shutdown(completion: @escaping () -> Void) {
        queue.async {
            self.stopping = true
            self.intent = .shutdown
            self.restartAt = nil
            self.timer?.cancel()
            self.timer = nil
            guard let running = self.child else {
                self.finishShutdown(completion)
                return
            }
            if running.isRunning {
                running.terminate()
            }
            // The second path to the same place: the writing end of the liveness
            // pipe closing is what the core sees when this process dies.
            self.closeLivenessPipe()
            self.awaitExit(of: running, deadline: Date().addingTimeInterval(CoreSupervisor.shutdownGrace)) { [weak self] in
                self?.queue.async { self?.finishShutdown(completion) }
            }
        }
    }

    /// A copy of the state, safe to read from any thread.
    var snapshot: CoreSnapshot {
        queue.sync {
            CoreSnapshot(state: state, pid: child?.processIdentifier, startedAt: spawnedAt,
                         restarts: restarts, failures: failures, failure: failure)
        }
    }

    // MARK: - The tick

    private func tick() {
        guard !stopping else { return }

        // 1. A child that is gone has already been reported by its termination
        //    handler; this covers the case where the handler has not run yet.
        if let running = child, !running.isRunning {
            childExited(running)
            return
        }

        // 2. A live child that has not answered: promote it, or fail the attempt
        //    when its budget is over. A child that reached `running` is not probed
        //    again — the exit check above watches it from here on.
        if child != nil {
            if state == .running { return }
            if let started = spawnedAt, Date().timeIntervalSince(started) >= budget {
                requestFailure(CoreFailure(
                    reason: .startupBudget,
                    detail: "the core did not answer within \(Int(budget))s"
                ))
                return
            }
            if announced, !probeRunning { probe() }
            return
        }

        // 3. Nothing is running: start the pending attempt when its delay is over.
        guard state != .crashed, let due = restartAt, Date() >= due else { return }
        restartAt = nil
        restarts += 1
        launch()
    }

    // MARK: - Starting

    private func launch() {
        restartAt = nil
        announced = false
        probeRunning = false
        captured.removeAll(keepingCapacity: true)
        failure = nil

        guard let core = settings.corePath else {
            state = .stopped
            failure = CoreFailure(
                reason: .coreMissing,
                detail: ShellSettings.coreMissingDetail(
                    explicit: settings.stored.corePath,
                    executable: Bundle.main.executableURL,
                    pathVariable: ProcessInfo.processInfo.environment["PATH"]
                )
            )
            publish()
            return
        }
        guard FileManager.default.fileExists(atPath: settings.configurationPath.path) else {
            state = .stopped
            failure = CoreFailure(
                reason: .configurationMissing,
                detail: "the core configuration is missing: \(settings.configurationPath.path)"
            )
            publish()
            return
        }

        do {
            try prepareDataDirectory()
            let log = try openLog()
            logHandle = log
            let process = try makeChild(core: core, log: log)
            child = process
            spawnedAt = Date()
            state = .starting
            publish()
        } catch {
            closeLog()
            state = .stopped
            failure = CoreFailure(reason: .launchFailed, detail: "\(error)")
            publish()
        }
    }

    private func prepareDataDirectory() throws {
        try FileManager.default.createDirectory(
            at: settings.dataDirectory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
    }

    private func openLog() throws -> FileHandle {
        let manager = FileManager.default
        if !manager.fileExists(atPath: settings.logPath.path) {
            let created = manager.createFile(
                atPath: settings.logPath.path,
                contents: nil,
                attributes: [.posixPermissions: 0o600]
            )
            guard created else {
                throw ShellError.unusableDataDirectory("cannot create \(settings.logPath.path)")
            }
        }
        let handle = try FileHandle(forWritingTo: settings.logPath)
        try handle.seekToEnd()
        return handle
    }

    /// Builds and starts the child.
    ///
    /// Arguments are explicit on purpose: `-config` and `-data-dir` are the two
    /// places the shell and the core could disagree about a path, and
    /// `-api-listen` is the one address the shell's client is bound to.
    /// `-supervise-stdin` turns the pipe below into the parent's liveness signal.
    private func makeChild(core: URL, log: FileHandle) throws -> Process {
        let process = Process()
        process.executableURL = core
        process.arguments = [
            "-config", settings.configurationPath.path,
            "-api-listen", settings.apiAddress.label,
            "-data-dir", settings.dataDirectory.path,
            "-supervise-stdin",
        ]

        let input = Pipe()
        let output = Pipe()
        process.standardInput = input
        process.standardOutput = output
        process.standardError = output

        process.terminationHandler = { [weak self] finished in
            self?.queue.async { self?.childExited(finished) }
        }
        let reader = output.fileHandleForReading
        let descriptor = reader.fileDescriptor
        let flags = fcntl(descriptor, F_GETFL)
        guard flags >= 0, fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
        try process.run()

        // The child has its own copies now. Ours would keep the pipe open and hide
        // both the child's end of file and the shell's death from the other side.
        try? output.fileHandleForWriting.close()
        try? input.fileHandleForReading.close()

        inputPipe = input
        let source = DispatchSource.makeReadSource(fileDescriptor: descriptor, queue: queue)
        source.setEventHandler { [weak self] in
            guard let self, self.child === process else { return }
            self.readOutput(upTo: Self.outputBatchSize)
        }
        source.setCancelHandler { try? reader.close() }
        outputSource = source
        source.resume()
        return process
    }

    // MARK: - Output and readiness

    /// Appends what the child printed and watches for the handshake.
    ///
    /// The core prints `api: http://…` and `api token file: …` after the token file
    /// is written and the listener is bound, so those two lines are the private
    /// confirmation the shell needs before it starts asking for `/v1/status`. The
    /// text is also where a busy port is recognised: the core's own sentence is the
    /// only place that distinction exists.
    private func ingest(_ data: Data) {
        if let log = logHandle {
            try? log.write(contentsOf: data)
        }
        captured.append(data)
        if !announced, captured.range(of: Data("api: http://".utf8)) != nil {
            announced = true
        }
        if captured.count > 8192 {
            captured = Data(captured.suffix(8192))
        }
    }

    /// A busy writer gets a bounded turn on the same queue that supervises it.
    private func readOutput(upTo limit: Int) {
        guard let source = outputSource else { return }
        let descriptor = Int32(source.handle)
        var buffer = [UInt8](repeating: 0, count: 4096)
        var remaining = limit
        while remaining > 0 {
            let count = read(descriptor, &buffer, min(remaining, buffer.count))
            if count > 0 {
                ingest(Data(buffer.prefix(count)))
                remaining -= count
                continue
            }
            if count < 0 && errno == EINTR { continue }
            if count == 0 || (errno != EAGAIN && errno != EWOULDBLOCK) {
                cancelOutput()
            }
            return
        }
    }

    /// Darwin reports the unread pipe bytes in st_size. Drain that snapshot before
    /// classification even if a descendant keeps the write end open or keeps logging.
    private func finishOutput() {
        guard let source = outputSource else { return }
        var info = stat()
        let limit = fstat(Int32(source.handle), &info) == 0 ? Int(info.st_size) : Self.outputBatchSize
        readOutput(upTo: limit)
        cancelOutput()
    }

    private func cancelOutput() {
        outputSource?.cancel()
        outputSource = nil
    }

    private func probe() {
        probeRunning = true
        let address = settings.apiAddress
        let tokenURL = settings.tokenPath
        let timeout = CoreSupervisor.probeTimeout
        Task.detached { [weak self] in
            let client = APIClient(address: address, tokenURL: tokenURL, timeout: timeout)
            var ready = false
            do {
                _ = try await client.status()
                ready = true
            } catch {
                ready = false
            }
            guard let self else { return }
            self.queue.async { self.probeFinished(ready: ready) }
        }
    }

    private func probeFinished(ready: Bool) {
        probeRunning = false
        guard !stopping, child != nil, state != .running else { return }
        guard ready else { return }
        state = .running
        failures = 0
        failure = nil
        publish()
    }

    // MARK: - Ending

    private func childExited(_ process: Process) {
        guard process === child else { return }
        finishOutput()
        closeLog()
        closeLivenessPipe()
        child = nil
        spawnedAt = nil
        probeRunning = false

        let outcome = intent
        intent = .supervise

        switch outcome {
        case .shutdown:
            state = .stopped
            publish()
        case .restart:
            let pending = pendingFailure
            pendingFailure = nil
            failure = pending
            state = .starting
            restartAt = nil
            failures = 0
            launch()
        case .supervise:
            let derived = pendingFailure ?? describeExit(process)
            pendingFailure = nil
            record(failure: derived)
        }
    }

    /// Stops the child because the shell decided the attempt failed.
    private func requestFailure(_ reason: CoreFailure) {
        pendingFailure = reason
        if let running = child, running.isRunning {
            running.terminate()
            return
        }
        if child == nil {
            let pending = pendingFailure
            pendingFailure = nil
            if let pending { record(failure: pending) }
        }
    }

    private func record(failure: CoreFailure) {
        self.failure = failure
        failures += 1
        if failures >= CoreSupervisor.maximumFailures {
            state = .crashed
            restartAt = nil
        } else {
            state = .starting
            restartAt = Date().addingTimeInterval(backoff(failures))
        }
        publish()
    }

    private func restartFinished() {
        guard !stopping, intent == .restart, child == nil else { return }
        intent = .supervise
        failures = 0
        failure = nil
        state = .starting
        launch()
    }

    private func finishShutdown(_ completion: @escaping () -> Void) {
        if let running = child, running.isRunning {
            kill(running.processIdentifier, SIGKILL)
        }
        finishOutput()
        closeLog()
        closeLivenessPipe()
        child = nil
        spawnedAt = nil
        state = .stopped
        publish()
        DispatchQueue.main.async(execute: completion)
    }

    /// Calls `action` once the process is gone, killing it at the deadline.
    private func awaitExit(of process: Process, deadline: Date, action: @escaping () -> Void) {
        if !process.isRunning {
            action()
            return
        }
        if Date() >= deadline {
            kill(process.processIdentifier, SIGKILL)
            action()
            return
        }
        queue.asyncAfter(deadline: .now() + 0.1) { [weak self] in
            self?.awaitExit(of: process, deadline: deadline, action: action)
        }
    }

    private func closeLivenessPipe() {
        guard let input = inputPipe else { return }
        try? input.fileHandleForWriting.close()
        inputPipe = nil
    }

    private func closeLog() {
        guard let log = logHandle else { return }
        try? log.close()
        logHandle = nil
    }

    private func describeExit(_ process: Process) -> CoreFailure {
        let text: String
        switch process.terminationReason {
        case .exit:
            text = "the core exited with status \(process.terminationStatus)"
        case .uncaughtSignal:
            text = "the core was terminated by signal \(process.terminationStatus)"
        @unknown default:
            text = "the core stopped for an unknown reason"
        }

        let reason: CoreFailure.Reason
        if captured.range(of: Data("address already in use".utf8)) != nil {
            reason = .portInUse
        } else if process.terminationReason == .uncaughtSignal {
            reason = .signalled
        } else {
            reason = .exited
        }
        return CoreFailure(reason: reason, detail: text)
    }

    private func publish() {
        let snapshot = CoreSnapshot(state: state, pid: child?.processIdentifier, startedAt: spawnedAt,
                                    restarts: restarts, failures: failures, failure: failure)
        let handler = onChange
        DispatchQueue.main.async { handler?(snapshot) }
    }

    /// The sequence the previous shell documented, kept identical.
    static func backoffDelay(after failures: Int) -> TimeInterval {
        switch failures {
        case 0, 1:
            return 1
        case 2:
            return 2
        default:
            return 5
        }
    }
}
