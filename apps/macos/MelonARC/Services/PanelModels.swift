import Combine
import Foundation

enum PanelLoadPhase: Equatable {
    case idle
    case loading
    case loaded
    case empty
    case failed(APIError)
}

enum PanelLoadSnapshot {
    case policies([PolicyView])
    case subscriptions([SubscriptionView])
    case rules([RuleView], total: Int)
    case connections([ConnectionView])
    case logs([EventView])

    var hasContent: Bool {
        switch self {
        case .policies(let values): return !values.isEmpty
        case .subscriptions(let values): return !values.isEmpty
        case .rules(let values, _): return !values.isEmpty
        case .connections(let values): return !values.isEmpty
        case .logs(let values): return !values.isEmpty
        }
    }
}

class BoundedPanelModel: ObservableObject {
    static let defaultPageSize = 200
    static let defaultInterval: TimeInterval = 5

    let api: APIClient?
    let pageSize: Int
    let interval: TimeInterval

    @Published private(set) var phase: PanelLoadPhase = .idle
    @Published private(set) var failure: APIError?
    @Published private(set) var writeFailure: APIError?
    @Published private(set) var lastUpdated: Date?

    private var timer: Timer?
    private var generation = 0
    private var inFlight = false
    private var hasLoaded = false

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
        inFlight = false
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
        generation += 1
        inFlight = false
    }

    func refresh(force: Bool = false) {
        guard let api, !inFlight || force else { return }
        generation += 1
        let current = generation
        inFlight = true
        if !hasLoaded { phase = .loading }
        Task { [weak self] in
            guard let self else { return }
            do {
                let snapshot = try await self.load(api)
                await MainActor.run {
                    guard current == self.generation else { return }
                    self.inFlight = false
                    self.hasLoaded = true
                    self.failure = nil
                    self.lastUpdated = Date()
                    self.apply(snapshot)
                    self.phase = snapshot.hasContent ? .loaded : .empty
                }
            } catch let error as APIError {
                await MainActor.run {
                    guard current == self.generation else { return }
                    self.inFlight = false
                    self.failure = error
                    if !self.hasLoaded { self.phase = .failed(error) }
                }
            } catch {
                let error = APIError.unreachable(error.localizedDescription)
                await MainActor.run {
                    guard current == self.generation else { return }
                    self.inFlight = false
                    self.failure = error
                    if !self.hasLoaded { self.phase = .failed(error) }
                }
            }
        }
    }

    func load(_ api: APIClient) async throws -> PanelLoadSnapshot {
        _ = api
        return .subscriptions([])
    }

    func apply(_ snapshot: PanelLoadSnapshot) {
        _ = snapshot
    }

    func recordWriteFailure(_ error: Error) {
        let mapped: APIError
        if let error = error as? APIError {
            mapped = error
        } else {
            mapped = .unreachable(error.localizedDescription)
        }
        Task { @MainActor in self.writeFailure = mapped }
    }

    func clearWriteFailure() {
        Task { @MainActor in self.writeFailure = nil }
    }
}

final class PoliciesModel: BoundedPanelModel {
    @Published private(set) var policies: [PolicyView] = []

    override func load(_ api: APIClient) async throws -> PanelLoadSnapshot {
        let all = try await api.policies()
        return .policies(Array(all.prefix(pageSize)))
    }

    override func apply(_ snapshot: PanelLoadSnapshot) {
        guard case .policies(let values) = snapshot else { return }
        policies = values
    }

    func select(group: String, member: String) async throws {
        guard let api else { return }
        clearWriteFailure()
        do {
            _ = try await api.selectPolicy(group: group, member: member)
            refresh(force: true)
        } catch {
            recordWriteFailure(error)
            throw error
        }
    }
}

final class SubscriptionsModel: BoundedPanelModel {
    @Published private(set) var subscriptions: [SubscriptionView] = []
    @Published private(set) var refreshing: Set<String> = []
    @Published private(set) var lastResult: SubscriptionRefreshView?
    @Published private(set) var lastCreatedName: String?
    @Published private(set) var creating = false

    override func load(_ api: APIClient) async throws -> PanelLoadSnapshot {
        let view = try await api.subscriptions()
        return .subscriptions(Array(view.subscriptions.prefix(pageSize)))
    }

    override func apply(_ snapshot: PanelLoadSnapshot) {
        guard case .subscriptions(let values) = snapshot else { return }
        subscriptions = values
    }

    func create(name: String, url: String, intervalSeconds: Int64?) async throws -> SubscriptionView {
        guard let api else { throw APIError.unreachable("the API client is not available") }
        await MainActor.run {
            creating = true
            writeFailure = nil
        }
        defer {
            Task { @MainActor in self.creating = false }
        }
        do {
            let request = SubscriptionCreateRequest(
                name: name,
                url: url,
                intervalSeconds: intervalSeconds
            )
            let view = try await api.createSubscription(request)
            await MainActor.run { lastCreatedName = view.name }
            refresh(force: true)
            return view
        } catch {
            recordWriteFailure(error)
            throw error
        }
    }

    func refreshNow(_ name: String) async throws {
        guard let api else { return }
        await MainActor.run { refreshing.insert(name) }
        defer {
            Task { @MainActor in self.refreshing.remove(name) }
        }
        do {
            let result = try await api.refreshSubscription(name)
            if let reason = result.error, !reason.isEmpty {
                throw APIError.api("subscription_refresh_failed", 200, reason)
            }
            await MainActor.run { lastResult = result }
            refresh(force: true)
        } catch {
            recordWriteFailure(error)
            throw error
        }
    }
}

final class RulesModel: BoundedPanelModel {
    @Published private(set) var rules: [RuleView] = []
    @Published private(set) var total = 0

    override func load(_ api: APIClient) async throws -> PanelLoadSnapshot {
        let page = try await api.rules(limit: pageSize)
        return .rules(Array(page.rules.prefix(pageSize)), total: page.total)
    }

    override func apply(_ snapshot: PanelLoadSnapshot) {
        guard case .rules(let values, let total) = snapshot else { return }
        rules = values
        self.total = total
    }
}

final class ConnectionsModel: BoundedPanelModel {
    @Published private(set) var connections: [ConnectionView] = []

    override func load(_ api: APIClient) async throws -> PanelLoadSnapshot {
        let page = try await api.connections(limit: pageSize)
        return .connections(Array(page.connections.suffix(pageSize)))
    }

    override func apply(_ snapshot: PanelLoadSnapshot) {
        guard case .connections(let values) = snapshot else { return }
        connections = values
    }
}

final class LogsModel: BoundedPanelModel {
    @Published private(set) var events: [EventView] = []

    override func load(_ api: APIClient) async throws -> PanelLoadSnapshot {
        let page = try await api.events(limit: pageSize)
        return .logs(Array(page.events.suffix(pageSize)))
    }

    override func apply(_ snapshot: PanelLoadSnapshot) {
        guard case .logs(let values) = snapshot else { return }
        events = values
    }
}
