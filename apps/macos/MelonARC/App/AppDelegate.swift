import AppKit

/// The AppKit half of the application.
///
/// Three things SwiftUI does not do on its own: keep running with no window (the
/// proxy outlives the interface), bring the window back when the Dock icon or a
/// second launch asks for it, and wait for the core to restore the machine's proxy
/// settings before the process ends.
final class AppDelegate: NSObject, NSApplicationDelegate {
    /// Posted by a second copy of the application before it gives up.
    static let activationNotification = Notification.Name("org.melonarc.app.activate")

    private var terminating = false

    func applicationDidFinishLaunching(_ notification: Notification) {
        let environment = AppEnvironment.shared

        DistributedNotificationCenter.default().addObserver(
            self,
            selector: #selector(handleActivation(_:)),
            name: AppDelegate.activationNotification,
            object: nil
        )

        switch environment.instance {
        case .owner, .unprotected:
            environment.start()
        case .busy:
            // Another copy owns this data directory: hand the user to it and leave
            // before a second supervisor can touch the token file.
            handOverToRunningCopy()
            NSApp.terminate(nil)
        }
    }

    /// Closing the last window is not quitting: the core keeps carrying traffic and
    /// the menu bar item keeps the state visible. Quitting is a separate, explicit
    /// request that stops the core and puts the proxy settings back.
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }

    /// A click on the Dock icon, or a relaunch through LaunchServices, lands here.
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if !flag {
            AppEnvironment.shared.showMainWindow()
        }
        return true
    }

    /// Tells macOS that this application opts into secure state restoration, which is
    /// the answer the system asks for since macOS 14. There is no restorable state to
    /// encode: the state lives in the core.
    func applicationSupportsSecureRestorableState(_ app: NSApplication) -> Bool {
        true
    }

    /// Quitting waits for the core.
    ///
    /// `terminateLater` is the documented way to answer asynchronously: the interface
    /// stays alive while the child is asked to stop, and the reply arrives when the
    /// core is gone — or after the grace period, so a stuck core cannot keep the
    /// application from quitting.
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard !terminating else { return .terminateNow }
        terminating = true
        AppEnvironment.shared.beginTermination {
            NSApp.reply(toApplicationShouldTerminate: true)
        }
        return .terminateLater
    }

    @objc private func handleActivation(_ notification: Notification) {
        AppEnvironment.shared.showMainWindow()
    }

    private func handOverToRunningCopy() {
        guard let identifier = Bundle.main.bundleIdentifier else { return }
        let others = NSRunningApplication.runningApplications(withBundleIdentifier: identifier)
        guard let other = others.first(where: { $0 != NSRunningApplication.current }) else { return }

        DistributedNotificationCenter.default().postNotificationName(
            AppDelegate.activationNotification,
            object: nil,
            userInfo: nil,
            deliverImmediately: true
        )
        if #available(macOS 14.0, *) {
            other.activate()
        } else {
            other.activate(options: [.activateAllWindows])
        }
    }
}
