import Combine
import Foundation

/// The shared shape of the panels that read a live endpoint.
///
/// A panel owns its timer rather than the window owning every panel's timer:
/// leaving a page calls `stop()`, so a hidden page never keeps asking the core
/// for rows nobody is reading. The list is replaced by a bounded page on every
/// successful read; it is never appended to, which is what keeps a busy daemon
/// from growing the interface without limit.
class BoundedPanelModel: ObservableObject {
    static let defaultPageSize = 200
    static let defaultInterval: TimeInterval = 5

    let api: APIClient?
    let pageSize: Int
    let interval: TimeInterval

    @Published private(set) var failure: APIError?
    @Published private(set) var lastUpdated: Date?

    private var timer: Timer?
    private var loading = false

    init(
        client: APIClient?,
        pageSize: Int = BoundedPanelModel.defaultPageSize,
        interval: TimeInterval = BoundedPanelModel.defaultInterval
    ) {
        self.api = client
        self.pageSize = pageSize
        self.interval = interval
    }

    var isRunning: Bool { timer != nil }

    func start() {
        guard timer == nil, api != nil else { return }
        refresh()
        let timer = Timer(timeInterval: interval, repeats: true) { [weak self] _ in
            self?.refresh()
        }
        RunLoop.main.add(timer, forMode: .common)
        self.timer = timer
    }

    func stop() {
        timer?.invalidate()
        timer = nil
    }

    func refresh() {
        guard let api, !loading else { return }
        loading = true
        Task { [weak self] in
            do {
                try await self?.load(api)
                await MainActor.run {
                    self?.failure = nil
                    self?.lastUpdated = Date()
                }
            } catch let error as APIError {
                await MainActor.run { self?.failure = error }
            } catch {
                await MainActor.run { self?.failure = .unreachable(error.localizedDescription) }
            }
            await MainActor.run { self?.loading = false }
        }
    }

    /// Each panel replaces this with one bounded read. It runs off the main
    /// actor and publishes its result there.
    func load(_ api: APIClient) async throws {
        _ = api
    }
}

final class PoliciesModel: BoundedPanelModel {
    @Published private(set) var policies: [PolicyView] = []

    override func load(_ api: APIClient) async throws {
        let all = try await api.policies()
        let page = Array(all.prefix(pageSize))
        await MainActor.run { policies = page }
    }

    func select(group: String, member: String) async throws {
        guard let api else { return }
        _ = try await api.selectPolicy(group: group, member: member)
        refresh()
    }
}

final class SubscriptionsModel: BoundedPanelModel {
    @Published private(set) var subscriptions: [SubscriptionView] = []
    @Published private(set) var refreshing: Set<String> = []
    @Published private(set) var lastResult: SubscriptionRefreshView?

    override func load(_ api: APIClient) async throws {
        let view = try await api.subscriptions()
        let page = Array(view.subscriptions.prefix(pageSize))
        await MainActor.run { subscriptions = page }
    }

    func refreshNow(_ name: String) async throws {
        guard let api else { return }
        await MainActor.run { refreshing.insert(name) }
        defer {
            Task { @MainActor in self.refreshing.remove(name) }
        }
        let result = try await api.refreshSubscription(name)
        await MainActor.run { lastResult = result }
        refresh()
    }
}

final class RulesModel: BoundedPanelModel {
    @Published private(set) var rules: [RuleView] = []
    @Published private(set) var total = 0

    override func load(_ api: APIClient) async throws {
        let page = try await api.rules(limit: pageSize)
        await MainActor.run {
            rules = Array(page.rules.prefix(pageSize))
            total = page.total
        }
    }
}

final class ConnectionsModel: BoundedPanelModel {
    @Published private(set) var connections: [ConnectionView] = []

    override func load(_ api: APIClient) async throws {
        let page = try await api.connections(limit: pageSize)
        await MainActor.run { connections = Array(page.connections.suffix(pageSize)) }
    }
}

final class LogsModel: BoundedPanelModel {
    @Published private(set) var events: [EventView] = []

    override func load(_ api: APIClient) async throws {
        let page = try await api.events(limit: pageSize)
        await MainActor.run { events = Array(page.events.suffix(pageSize)) }
    }
}
