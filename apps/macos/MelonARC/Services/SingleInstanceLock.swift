import Darwin
import Foundation

/// One shell per data directory.
///
/// Two copies of the application would mean two supervisors, two children and two
/// writers on the same `api-token`, so the second one stops before it starts a core.
/// The lock is a real file lock rather than a pid file: the kernel drops it when the
/// process dies, so a crash never leaves a lock that has to be cleaned up by hand.
///
/// A lock that cannot be taken because the *file* cannot be opened is not a second
/// instance — it is a permissions problem, and refusing to start over it would be
/// worse than running without the protection. That case is reported and the shell
/// continues.
final class SingleInstanceLock {
    enum Outcome {
        case acquired(SingleInstanceLock)
        /// Another process holds the lock.
        case busy
        /// The lock file could not be opened or locked for a reason that is not
        /// another instance. The string is the system's own sentence.
        case unavailable(String)
    }

    private var descriptor: Int32
    private(set) var isHeld = false

    private init(descriptor: Int32) {
        self.descriptor = descriptor
        self.isHeld = true
    }

    static func acquire(at url: URL) -> Outcome {
        let directory = url.deletingLastPathComponent()
        do {
            try FileManager.default.createDirectory(
                at: directory,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
        } catch {
            return .unavailable("cannot create \(directory.path): \(error.localizedDescription)")
        }

        let descriptor = open(url.path, O_CREAT | O_RDWR, 0o600)
        guard descriptor >= 0 else {
            return .unavailable("cannot open \(url.path): \(String(cString: strerror(errno)))")
        }
        if flock(descriptor, LOCK_EX | LOCK_NB) != 0 {
            let code = errno
            close(descriptor)
            if code == EWOULDBLOCK {
                return .busy
            }
            return .unavailable("cannot lock \(url.path): \(String(cString: strerror(code)))")
        }
        return .acquired(SingleInstanceLock(descriptor: descriptor))
    }

    /// Releases the lock. Called on the way out so a relaunch does not have to wait
    /// for the process to disappear.
    func release() {
        guard isHeld else { return }
        isHeld = false
        flock(descriptor, LOCK_UN)
        close(descriptor)
        descriptor = -1
    }

    deinit {
        if isHeld, descriptor >= 0 {
            close(descriptor)
        }
    }
}
