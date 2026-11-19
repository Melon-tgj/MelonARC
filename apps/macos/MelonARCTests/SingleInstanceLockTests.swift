import XCTest

final class SingleInstanceLockTests: XCTestCase {
    func testTheLockFileIsCreatedInsideTheDataDirectory() throws {
        let directory = try TemporaryDirectory("lock")
        let path = directory.file("shell.lock")

        guard case .acquired(let held) = SingleInstanceLock.acquire(at: path) else {
            return XCTFail("a fresh directory must be lockable")
        }
        XCTAssertTrue(FileManager.default.fileExists(atPath: path.path))
        held.release()
    }

    /// Two shells on one data directory would fight over the token file, so the
    /// second one is told which case it is in rather than being allowed to start.
    func testASecondLockOnTheSameFileIsBusy() throws {
        let directory = try TemporaryDirectory("lock")
        let path = directory.file("shell.lock")

        guard case .acquired(let held) = SingleInstanceLock.acquire(at: path) else {
            return XCTFail("the first lock must succeed")
        }
        defer { held.release() }

        switch SingleInstanceLock.acquire(at: path) {
        case .busy:
            break
        case .acquired:
            XCTFail("a second lock must not be granted")
        case .unavailable(let reason):
            XCTFail("a second lock reported \(reason) instead of busy")
        }
    }

    func testReleasingLetsTheNextLaunchIn() throws {
        let directory = try TemporaryDirectory("lock")
        let path = directory.file("shell.lock")

        guard case .acquired(let first) = SingleInstanceLock.acquire(at: path) else {
            return XCTFail("the first lock must succeed")
        }
        first.release()

        guard case .acquired(let second) = SingleInstanceLock.acquire(at: path) else {
            return XCTFail("the lock must be usable after a release")
        }
        second.release()
    }
}
