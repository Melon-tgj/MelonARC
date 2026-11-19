import SwiftUI

/// The application: one window, one settings window, one menu bar item.
///
/// AppKit owns the lifecycle (`AppDelegate`), SwiftUI owns the interface. The window
/// is a `Window` rather than a `WindowGroup` on purpose: there is one document — the
/// daemon — so a second window would only be a second view of the same state, with
/// its own polling and its own chance to look stale.
@main
struct MelonARCApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var environment = AppEnvironment.shared

    var body: some Scene {
        Window("window.title", id: MelonARCApp.mainWindowIdentifier) {
            RootView()
                .environmentObject(environment)
        }
        .defaultSize(width: 980, height: 620)
        .commands {
            // No "New" item: there is nothing a new one would be.
            CommandGroup(replacing: .newItem) {}
            CommandGroup(after: .appInfo) {
                Button("menu.open") {
                    environment.showMainWindow()
                }
            }
        }

        // A Settings scene is what makes the app menu carry the native "Settings…"
        // item and ⌘, on macOS 13, where `SettingsLink` does not exist yet.
        Settings {
            SettingsView(environment: environment)
        }

        // Closing the window leaves this behind, and the core running with it: the
        // proxy is a machine-wide setting, and quitting the interface is not a
        // request to stop routing.
        MenuBarExtra {
            Button("menu.open") {
                environment.showMainWindow()
            }
            Divider()
            Text(environment.menuStateText)
            Divider()
            Button("menu.quit") {
                NSApp.terminate(nil)
            }
        } label: {
            Image(systemName: environment.menuBarSymbol)
        }
    }

    static let mainWindowIdentifier = "main"
}
