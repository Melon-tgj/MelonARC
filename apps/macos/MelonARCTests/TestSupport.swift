import XCTest

/// A scratch directory that removes itself.
final class TemporaryDirectory {
    let url: URL

    init(_ label: String = "melonarc") throws {
        let base = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
        url = base.appendingPathComponent("\(label)-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    }

    func file(_ name: String) -> URL {
        url.appendingPathComponent(name)
    }

    deinit {
        try? FileManager.default.removeItem(at: url)
    }
}

/// Collects supervisor snapshots from the background queue so a test can wait for a
/// state or a failure reason without racing the next transition.
final class SnapshotRecorder {
    private let lock = NSLock()
    private var snapshots: [CoreSnapshot] = []

    func append(_ snapshot: CoreSnapshot) {
        lock.lock()
        defer { lock.unlock() }
        snapshots.append(snapshot)
    }

    var all: [CoreSnapshot] {
        lock.lock()
        defer { lock.unlock() }
        return snapshots
    }

    func contains(_ state: CoreState) -> Bool {
        all.contains { $0.state == state }
    }

    func containsFailure(_ reason: CoreFailure.Reason) -> Bool {
        all.contains { $0.failure?.reason == reason }
    }

    /// Waits for a condition, polling while pumping the main run loop.
    ///
    /// The supervisor delivers every snapshot on the main queue — that is what the
    /// interface needs — and XCTest runs a synchronous test on the main thread, so a
    /// wait that only sleeps would never see one arrive.
    func wait(until condition: @escaping ([CoreSnapshot]) -> Bool, timeout: TimeInterval) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if condition(all) { return true }
            RunLoop.current.run(until: Date().addingTimeInterval(0.05))
        }
        return condition(all)
    }
}
