import Combine
import Foundation

final class OverviewModel: ObservableObject {
    static let refreshInterval: TimeInterval = 2

    @Published private(set) var status: StatusView?
    @Published private(set) var configuration: ConfigurationView?
    @Published private(set) var statusFailure: APIError?
    @Published private(set) var configurationFailure: APIError?
    @Published private(set) var lastStatusSuccess: Date?
    @Published private(set) var lastConfigurationSuccess: Date?

    private let client: APIClient?
    private var timer: Timer?
    private var refreshing = false
    private var generation = 0

    init(client: APIClient?) {
        self.client = client
    }

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
        generation += 1
    }

    func refresh() {
        guard let client, !refreshing else { return }
        refreshing = true
        generation += 1
        let current = generation
        Task { [weak self] in
            guard let self else { return }
            async let status = client.status()
            async let configuration = client.configuration()
            let statusResult: Result<StatusView, Error>
            do {
                statusResult = .success(try await status)
            } catch {
                statusResult = .failure(error)
            }
            let configurationResult: Result<ConfigurationView, Error>
            do {
                configurationResult = .success(try await configuration)
            } catch {
                configurationResult = .failure(error)
            }
            await MainActor.run {
                guard current == self.generation else { return }
                self.refreshing = false
                switch statusResult {
                case .success(let value):
                    self.status = value
                    self.statusFailure = nil
                    self.lastStatusSuccess = Date()
                case .failure(let error):
                    self.statusFailure = self.map(error)
                }
                switch configurationResult {
                case .success(let value):
                    self.configuration = value
                    self.configurationFailure = nil
                    self.lastConfigurationSuccess = Date()
                case .failure(let error):
                    self.configurationFailure = self.map(error)
                }
            }
        }
    }

    private func map(_ error: Error) -> APIError {
        if let error = error as? APIError { return error }
        return .unreachable(error.localizedDescription)
    }
}
