import Foundation

/// The configuration the shell writes when the data directory has none.
///
/// It is the smallest file that starts a working daemon and changes nothing on the
/// machine: two loopback listeners, the local API, and every connection going
/// straight out. No proxy, no subscription, no system proxy, no TUN — the first
/// launch must not be able to touch the network settings of a machine whose user has
/// not yet decided anything.
///
/// `data-dir` is deliberately absent. The shell passes `-data-dir` on every launch
/// (see `CoreSupervisor.makeChild`), and a second opinion in this file is what made
/// the token land in a directory the shell never reads in the first place.
enum FirstRunConfig {
    static let contents = """
    # MelonARC configuration.
    #
    # Written once, on the first launch of the desktop application, and never
    # rewritten: edit it freely, the application reads what is here.
    #
    # Every listener is on loopback. A proxy that listens on every interface is an
    # open relay, and the local API carries a bearer token.
    #
    # The data directory is not set here on purpose: the application passes
    # -data-dir on every launch, so the token, the observation history and the
    # system proxy record always live where the application looks for them.

    [General]
    log-level = info
    api-listen = 127.0.0.1:7946
    http-listen = 127.0.0.1:7890
    socks5-listen = 127.0.0.1:7891

    [Rule]
    # Nothing is routed anywhere yet: every connection goes straight out. Add a
    # [Proxy] entry and name it here to send traffic through it.
    FINAL,DIRECT

    """

    /// Writes the file when it is missing, and leaves an existing one alone.
    ///
    /// Returns whether a file was written, so the caller can say so once instead of
    /// guessing. The directory is created 0700 and the file 0600: the same directory
    /// later holds the API token.
    @discardableResult
    static func ensure(at url: URL, fileManager: FileManager = .default) throws -> Bool {
        if fileManager.fileExists(atPath: url.path) {
            return false
        }
        let directory = url.deletingLastPathComponent()
        try fileManager.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        guard let data = contents.data(using: .utf8) else {
            throw ShellError.unusableDataDirectory("the built-in configuration is not valid UTF-8")
        }
        try data.write(to: url, options: [.atomic])
        // An atomic write installs a temporary file with the process umask, so the
        // mode is set afterwards rather than assumed.
        try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        return true
    }
}
