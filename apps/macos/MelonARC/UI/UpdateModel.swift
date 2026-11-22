import AppKit
import Foundation

enum UpdatePhase: String {
    case idle
    case checking
    case available
    case upToDate
    case noReleases
    case noCompatible
    case incomplete
    case offline
    case timeout
    case malformed
    case rateLimited
    case downloading
    case verifying
    case checksumMismatch
    case unsafeAsset
    case ready
    case saved
    case saveFailed
    case cancelled
}

enum UpdateSaveError: Error {
    case quarantine
}

private enum QuarantineKey {
    static let type = "LSQuarantineTypeKey"
    static let agent = "LSQuarantineAgentNameKey"
    static let origin = "LSQuarantineOriginURLKey"
    static let timestamp = "LSQuarantineTimestampKey"
    static let webDownload = 2
}

final class UpdateModel: ObservableObject {
    @Published private(set) var phase: UpdatePhase = .idle
    @Published private(set) var candidate: ReleaseCandidate?
    @Published private(set) var retryDate: Date?
    @Published var alertPresented = false

    private let service: ReleaseUpdateService
    private var downloaded: URL?
    private var generation = 0

    init(service: ReleaseUpdateService? = nil) {
        self.service = service ?? ReleaseUpdateService()
    }

    var isBusy: Bool {
        phase == .checking || phase == .downloading || phase == .verifying
    }

    var canDownload: Bool {
        phase == .available && candidate != nil && !isBusy
    }

    var canSave: Bool {
        phase == .ready && downloaded != nil
    }

    var statusKey: String {
        switch phase {
        case .idle: return "updates.state.idle"
        case .checking: return "updates.state.checking"
        case .available: return "updates.state.available"
        case .upToDate: return "updates.state.up_to_date"
        case .noReleases: return "updates.no_release"
        case .noCompatible: return "updates.state.no_compatible"
        case .incomplete: return "updates.state.incomplete"
        case .offline: return "updates.state.offline"
        case .timeout: return "updates.state.timeout"
        case .malformed: return "updates.state.malformed"
        case .rateLimited: return "updates.state.rate_limited"
        case .downloading: return "updates.state.downloading"
        case .verifying: return "updates.state.verifying"
        case .checksumMismatch: return "updates.state.checksum_mismatch"
        case .unsafeAsset: return "updates.state.unsafe_asset"
        case .ready: return "updates.state.ready"
        case .saved: return "updates.state.saved"
        case .saveFailed: return "updates.state.save_failed"
        case .cancelled: return "updates.state.cancelled"
        }
    }

    var statusText: String {
        if phase == .rateLimited, let retryDate {
            return Localization.format(
                "updates.state.rate_limited_until",
                DateFormatter.localizedString(from: retryDate, dateStyle: .none, timeStyle: .short)
            )
        }
        return Localization.text(statusKey)
    }

    var alertMessage: String {
        if phase == .available, let candidate {
            return Localization.format(
                "updates.alert.available",
                candidate.manifest.shortVersion ?? "",
                candidate.manifest.buildNumber ?? ""
            )
        }
        return statusText
    }

    var candidateName: String {
        candidate?.manifest.candidate ?? "MelonARC.dmg"
    }

    func check() {
        guard !isBusy else { return }
        let info = Bundle.main.infoDictionary
        guard let short = ReleaseVersionParser.shortVersion(info?["CFBundleShortVersionString"] as? String),
              let build = ReleaseVersionParser.build(info?["CFBundleVersion"] as? String) else {
            phase = .malformed
            return
        }
        let channel = MelonARCUpdateChannel(infoValue: Bundle.main.object(forInfoDictionaryKey: "MelonARCUpdateChannel") as? String)
        let os = ProcessInfo.processInfo.operatingSystemVersion
        let system = SystemVersion(major: os.majorVersion, minor: os.minorVersion)
        #if arch(arm64)
        let architecture = "arm64"
        #else
        let architecture = "x86_64"
        #endif

        generation += 1
        let current = generation
        phase = .checking
        alertPresented = false
        candidate = nil
        retryDate = nil
        let version = ReleaseVersion(short: short, build: build)
        let service = self.service
        Task {
            let outcome = await service.check(channel: channel, current: version, architecture: architecture, system: system)
            await MainActor.run {
                guard current == self.generation else { return }
                self.apply(outcome)
            }
        }
    }

    func download() {
        guard canDownload, let candidate else { return }
        generation += 1
        let current = generation
        phase = .downloading
        let service = self.service
        let target = candidate
        Task {
            do {
                let file = try await service.download(target)
                await MainActor.run {
                    guard current == self.generation else {
                        service.cleanUp(file)
                        return
                    }
                    self.phase = .verifying
                    self.downloaded = file
                    self.phase = .ready
                    self.alertPresented = true
                }
            } catch {
                await MainActor.run {
                    guard current == self.generation else { return }
                    self.phase = Self.phase(for: error)
                    self.alertPresented = true
                }
            }
        }
    }

    func cancel() {
        generation += 1
        service.cancelDownload()
        if let downloaded {
            service.cleanUp(downloaded)
            self.downloaded = nil
        }
        phase = .cancelled
    }

    @MainActor
    func saveDownload() async {
        guard canSave, let downloaded, let candidate else { return }
        let panel = NSSavePanel()
        panel.allowedFileTypes = ["dmg"]
        panel.nameFieldStringValue = candidate.manifest.candidate ?? candidateName
        panel.canCreateDirectories = true
        let response = await panel.begin()
        guard response == .OK, let destination = panel.url else {
            phase = .cancelled
            return
        }
        do {
            if FileManager.default.fileExists(atPath: destination.path) {
                try FileManager.default.removeItem(at: destination)
            }
            try FileManager.default.copyItem(at: downloaded, to: destination)
            try ensureQuarantine(destination, origin: candidate.dmg.browserDownloadURL)
            NSWorkspace.shared.activateFileViewerSelecting([destination])
            service.cleanUp(downloaded)
            self.downloaded = nil
            phase = .saved
        } catch {
            phase = .saveFailed
        }
    }

    private func apply(_ outcome: UpdateCheckOutcome) {
        switch outcome {
        case .update(let found):
            candidate = found
            phase = .available
            alertPresented = true
        case .upToDate: phase = .upToDate
        case .noReleases: phase = .noReleases
        case .noCompatible: phase = .noCompatible
        case .incomplete: phase = .incomplete
        case .rateLimited(let date):
            retryDate = date
            phase = .rateLimited
        case .offline: phase = .offline
        case .timeout: phase = .timeout
        case .malformed: phase = .malformed
        }
    }

    private static func phase(for error: Error) -> UpdatePhase {
        switch ReleaseServiceError.map(error) {
        case .cancelled: return .cancelled
        case .offline: return .offline
        case .timeout: return .timeout
        case .rateLimited: return .rateLimited
        case .checksumMismatch, .digestMismatch: return .checksumMismatch
        case .unsafeAsset, .untrustedRedirect: return .unsafeAsset
        case .malformed, .incompletePage, .httpStatus: return .malformed
        }
    }

    private func ensureQuarantine(_ file: URL, origin: String) throws {
        var values = try file.resourceValues(forKeys: [.quarantinePropertiesKey])
        if values.quarantineProperties?.isEmpty != false {
            var properties: [String: Any] = [
                QuarantineKey.type: QuarantineKey.webDownload,
                QuarantineKey.agent: "MelonARC",
                QuarantineKey.timestamp: Date(),
            ]
            if !origin.isEmpty { properties[QuarantineKey.origin] = origin }
            values.quarantineProperties = properties
            var mutableFile = file
            try mutableFile.setResourceValues(values)
        }
        let verified = try file.resourceValues(forKeys: [.quarantinePropertiesKey])
        guard let final = verified.quarantineProperties, !final.isEmpty else {
            throw UpdateSaveError.quarantine
        }
    }
}
