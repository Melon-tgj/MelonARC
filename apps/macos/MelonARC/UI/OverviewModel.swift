import Combine
import Foundation

/// The overview's own state: what the last authenticated read said.
///
/// The polling lives here rather than in the view so that leaving the panel stops it
/// — a settings window or a hidden window must not keep asking the core for a status
/// it is not drawing. The interval is a compromise the previous page also made: two
/// seconds is fast enough to see a core start or die, slow enough that a window left
/// open overnight costs nothing worth measuring.
final class OverviewModel: ObservableObject {
    static let refreshInterval: TimeInterval = 2

    @Published private(set) var status: StatusView?
    @Published private(set) var configuration: ConfigurationView?
    @Published private(set) var failure: APIError?
    @Published private(set) var lastUpdated: Date?

    private let client: APIClient?
    private var timer: Timer?
    private var refreshing = false

    init(client: APIClient?) {
        self.client = client
    }

    /// Starts the timer, and refreshes once immediately so the panel is never blank
    /// for a whole interval.
    func start() {
        guard timer == nil, client != nil else { return }
        refresh()
        let timer = Timer(timeInterval: OverviewModel.refreshInterval, repeats: true) { [weak self] _ in
            self?.refresh()
        }
        RunLoop.main.add(timer, forMode: .common)
        self.timer = timer
    }

    func stop() {
        timer?.invalidate()
        timer = nil
    }

    /// One read of `/v1/status`, and of `/v1/config` when the first succeeded. A
    /// configuration read that fails on its own is not worth an error banner: the
    /// status is the answer the panel exists for.
    func refresh() {
        guard let client, !refreshing else { return }
        refreshing = true
        Task { [weak self] in
            var status: StatusView?
            var configuration: ConfigurationView?
            var failure: APIError?
            do {
                status = try await client.status()
                configuration = try? await client.configuration()
            } catch let error as APIError {
                failure = error
            } catch {
                failure = .unreachable(error.localizedDescription)
            }
            await MainActor.run {
                self?.refreshing = false
                self?.failure = failure
                if let status {
                    self?.status = status
                    self?.configuration = configuration
                    self?.lastUpdated = Date()
                }
                // A failed read keeps the last known values on screen: blanking the
                // panel would hide that the core had been answering a second ago.
            }
        }
    }
}
