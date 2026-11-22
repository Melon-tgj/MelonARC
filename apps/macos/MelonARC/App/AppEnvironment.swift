import AppKit
import Combine
import Foundation

/// The composed application: the settings, the lock, the core and the client.
///
/// One instance, created on first use, because three different entry points need the
/// same object — the app's scene tree, the application delegate and the menu bar.
/// Nothing here starts anything: `start()` is called once the application has
/// finished launching, so a failure to start is reported by a window that already
/// exists instead of by a process that vanishes.
final class AppEnvironment: ObservableObject {
    static let shared = AppEnvironment()

    /// What happened when the instance lock was taken.
    enum InstanceState: Equatable {
        /// This process owns the data directory.
        case owner
        /// Another process owns it; this launch should hand over and stop.
        case busy
        /// The lock file could not be used. The shell runs anyway, and says so.
        case unprotected(String)
    }

    struct BootstrapEvent: Equatable {
        enum Kind: Equatable {
            case written
            case failed
        }

        let kind: Kind
        let path: String
        let detail: String
    }

    let settings: ShellSettings?
    /// Why the settings could not be resolved at all. Not a reason to refuse to
    /// show a window; it is the reason the window shows one sentence.
    let settingsFailure: String?
    let instance: InstanceState
    let apiClient: APIClient?
    let supervisor: CoreSupervisor?
    let update: UpdateModel
    let overview: OverviewModel
    let policies: PoliciesModel
    let subscriptions: SubscriptionsModel
    let rules: RulesModel
    let connections: ConnectionsModel
    let logs: LogsModel

    /// The supervisor's state, mirrored for the interface.
    @Published private(set) var snapshot = CoreSnapshot()
    /// A line about the first-run configuration, when something was said about it.
    @Published private(set) var bootstrapNotice: String?
    @Published private(set) var bootstrapEvent: BootstrapEvent?
    /// A launch-time refusal, such as a data-directory change. The core is not
    /// started in that case, and the window says so instead of showing stale
    /// state from a directory this launch is not allowed to use.
    @Published private(set) var launchFailure: String?

    private var heldLock: SingleInstanceLock?
    private var windowOpener: ((String) -> Void)?
    private var terminating = false

    private init() {
        var loaded: ShellSettings?
        var failure: String?
        do {
            loaded = try ShellSettings.load()
        } catch {
            loaded = nil
            failure = error.localizedDescription
        }
        settings = loaded
        settingsFailure = failure

        guard let loaded else {
            instance = .owner
            apiClient = nil
            supervisor = nil
            update = UpdateModel()
            overview = OverviewModel(client: nil)
            policies = PoliciesModel(client: nil)
            subscriptions = SubscriptionsModel(client: nil)
            rules = RulesModel(client: nil)
            connections = ConnectionsModel(client: nil)
            logs = LogsModel(client: nil)
            return
        }

        let client = APIClient(address: loaded.apiAddress, tokenURL: loaded.tokenPath)
        apiClient = client
        overview = OverviewModel(client: client)
        policies = PoliciesModel(client: client)
        subscriptions = SubscriptionsModel(client: client)
        rules = RulesModel(client: client)
        connections = ConnectionsModel(client: client)
        logs = LogsModel(client: client)
        update = UpdateModel()
        supervisor = CoreSupervisor(settings: loaded)

        switch SingleInstanceLock.acquire(at: loaded.lockPath) {
        case .acquired(let held):
            heldLock = held
            instance = .owner
        case .busy:
            instance = .busy
        case .unavailable(let reason):
            instance = .unprotected(reason)
        }
    }

    // MARK: - Lifecycle

    /// Writes the first configuration if there is none, then starts the supervisor.
    func start() {
        // A busy data directory belongs to another process; an unusable lock file is
        // a permission problem and starting anyway is the lesser evil, which is what
        // the previous shell did too.
        if case .busy = instance { return }
        guard let settings, let supervisor else { return }

        do {
            try settings.confirmDataDirectory()
        } catch {
            launchFailure = error.localizedDescription
            return
        }

        do {
            let wrote = try FirstRunConfig.ensure(at: settings.configurationPath)
            if wrote {
                bootstrapNotice = Localization.text("startup.first_config_written_short")
                bootstrapEvent = BootstrapEvent(
                    kind: .written,
                    path: settings.configurationPath.path,
                    detail: Localization.text("startup.first_config_written_short")
                )
            }
        } catch {
            bootstrapNotice = Localization.text("startup.first_config_failed_short")
            bootstrapEvent = BootstrapEvent(
                kind: .failed,
                path: settings.configurationPath.path,
                detail: error.localizedDescription
            )
        }

        supervisor.onChange = { [weak self] snapshot in
            self?.snapshot = snapshot
        }
        snapshot = supervisor.snapshot
        supervisor.start()
    }

    /// Stops the core and releases the lock, then answers the quit request.
    ///
    /// The answer is asynchronous on purpose: the core restores the machine's proxy
    /// settings on the way out, and a reply that arrives first would leave the
    /// restore to a process that no longer exists.
    func beginTermination(completion: @escaping () -> Void) {
        guard !terminating else {
            completion()
            return
        }
        terminating = true
        stopAllPanels()
        guard let supervisor else {
            heldLock?.release()
            heldLock = nil
            completion()
            return
        }
        supervisor.shutdown { [weak self] in
            self?.heldLock?.release()
            self?.heldLock = nil
            completion()
        }
    }

    /// Brings the window back: after a second launch, from the menu bar, or from a
    /// click on the Dock icon.
    func showMainWindow() {
        activate()
        if let opener = windowOpener {
            opener("main")
        } else if let window = NSApp.windows.first(where: { $0.canBecomeMain }) {
            window.makeKeyAndOrderFront(nil)
        }
    }

    /// The scene hands its `openWindow` action over once, so the delegate and the
    /// menu can reopen a window that SwiftUI has already released.
    func attachWindowOpener(_ action: @escaping (String) -> Void) {
        windowOpener = action
    }

    func restartCore() {
        supervisor?.restart()
    }

    // MARK: - Panels

    /// Starts exactly the page being shown. The sidebar is generated from the
    /// registry, so this switch is about panel *behaviour*, not its count: an
    /// unregistered page simply refreshes nothing.
    func startPanel(_ id: String?) {
        switch id {
        case PanelRegistry.overview.id: overview.start()
        case PanelRegistry.policies.id: policies.start()
        case PanelRegistry.subscriptions.id: subscriptions.start()
        case PanelRegistry.rules.id: rules.start()
        case PanelRegistry.connections.id: connections.start()
        case PanelRegistry.logs.id: logs.start()
        default: break
        }
    }

    func stopAllPanels() {
        overview.stop()
        policies.stop()
        subscriptions.stop()
        rules.stop()
        connections.stop()
        logs.stop()
    }

    /// Writes the proxy setting, reloads, and then restarts only if the daemon
    /// says the change cannot take effect in this process. The boolean the
    /// interface keeps comes from a fresh configuration read, not from the
    /// request that was sent.
    @discardableResult
    func setSystemProxy(_ enabled: Bool) async throws -> ConfigurationView {
        guard let apiClient else {
            throw APIError.unreachable("the API client is not available")
        }
        _ = try await apiClient.updateConfiguration(
            ConfigUpdateRequest(logLevel: nil, systemProxy: enabled)
        )
        let reload = try await apiClient.reloadConfiguration()
        if reload.pendingRestart.contains("system-proxy") {
            restartCore()
        }
        let current = try await apiClient.configuration()
        await MainActor.run {
            overview.refresh()
        }
        return current
    }

    // MARK: - Presentation

    /// The menu bar icon follows the state, so the menu itself is a status display.
    var menuBarSymbol: String {
        switch snapshot.state {
        case .running: return "gauge"
        case .crashed: return "exclamationmark.triangle"
        case .starting, .stopped: return "circle.dashed"
        }
    }

    var menuStateText: String {
        Localization.format("menu.core_state", Localization.text(snapshot.state.localizationKey))
    }

    private func activate() {
        if #available(macOS 14.0, *) {
            NSApp.activate()
        } else {
            NSApp.activate(ignoringOtherApps: true)
        }
    }
}
