import CryptoKit
import Foundation

enum ReleaseServiceError: Error {
    case offline
    case timeout
    case rateLimited(Date?)
    case httpStatus(Int)
    case malformed
    case incompletePage
    case untrustedRedirect
    case unsafeAsset
    case checksumMismatch
    case digestMismatch
    case cancelled

    static func map(_ error: Error) -> ReleaseServiceError {
        if let service = error as? ReleaseServiceError { return service }
        guard let urlError = error as? URLError else { return .malformed }
        switch urlError.code {
        case .cancelled: return .cancelled
        case .timedOut: return .timeout
        case .notConnectedToInternet, .networkConnectionLost, .cannotFindHost, .cannotConnectToHost:
            return .offline
        default: return .offline
        }
    }
}

enum UpdateCheckOutcome {
    case update(ReleaseCandidate)
    case upToDate
    case noReleases
    case noCompatible
    case incomplete
    case rateLimited(Date?)
    case offline
    case timeout
    case malformed
}

final class ReleaseDownloadDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    private let lock = NSLock()
    private var task: URLSessionTask?
    private(set) var redirects = 0
    private(set) var cancelled = false

    func urlSession(_ session: URLSession, didCreateTask task: URLSessionTask) {
        lock.lock()
        self.task = task
        lock.unlock()
        if cancelled { task.cancel() }
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        lock.lock()
        redirects += 1
        let count = redirects
        let origin = task.originalRequest?.url ?? task.currentRequest?.url
        let blocked = cancelled
        lock.unlock()
        guard !blocked,
              let origin,
              let target = request.url,
              ReleaseDownloadPolicy.allowsRedirect(from: origin, to: target, count: count) else {
            completionHandler(nil)
            return
        }
        var clean = URLRequest(url: target)
        clean.httpMethod = "GET"
        clean.timeoutInterval = request.timeoutInterval
        completionHandler(clean)
    }

    func cancel() {
        lock.lock()
        cancelled = true
        let task = self.task
        lock.unlock()
        task?.cancel()
    }
}

protocol ReleaseHTTPTransport: AnyObject {
    func data(for request: URLRequest) async throws -> (Data, HTTPURLResponse)
    func download(for request: URLRequest, delegate: ReleaseDownloadDelegate) async throws -> (URL, HTTPURLResponse)
}

final class URLSessionReleaseTransport: ReleaseHTTPTransport {
    private let session: URLSession

    init(protocolClasses: [AnyClass]? = nil) {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.urlCache = nil
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.urlCredentialStorage = nil
        configuration.timeoutIntervalForRequest = 12
        configuration.timeoutIntervalForResource = 90
        if let protocolClasses { configuration.protocolClasses = protocolClasses }
        self.session = URLSession(configuration: configuration)
    }

    func data(for request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        do {
            let result = try await session.data(for: request)
            guard let http = result.1 as? HTTPURLResponse else { throw ReleaseServiceError.malformed }
            return (result.0, http)
        } catch {
            throw ReleaseServiceError.map(error)
        }
    }

    func download(for request: URLRequest, delegate: ReleaseDownloadDelegate) async throws -> (URL, HTTPURLResponse) {
        do {
            let result = try await session.download(for: request, delegate: delegate)
            guard let http = result.1 as? HTTPURLResponse else { throw ReleaseServiceError.malformed }
            return (result.0, http)
        } catch {
            throw ReleaseServiceError.map(error)
        }
    }
}

enum DownloadDigest {
    static func sha256Hex(_ url: URL) throws -> String {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        var hasher = SHA256()
        while true {
            let chunk = try handle.read(upToCount: 1024 * 1024) ?? Data()
            if chunk.isEmpty { break }
            hasher.update(data: chunk)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }
}

final class ReleaseUpdateService {
    private let transport: any ReleaseHTTPTransport
    private let decoder = JSONDecoder()
    private var activeDownload: ReleaseDownloadDelegate?

    init(transport: any ReleaseHTTPTransport = URLSessionReleaseTransport()) {
        self.transport = transport
    }

    func check(
        channel: MelonARCUpdateChannel,
        current: ReleaseVersion,
        architecture: String,
        system: SystemVersion
    ) async -> UpdateCheckOutcome {
        do {
            let records = try await fetchReleases()
            guard !records.isEmpty else { return .noReleases }
            var resolved: [ResolvedRelease] = []
            for record in records where channel.accepts(record) {
                let data = await fetchManifest(for: record)
                resolved.append(ResolvedRelease(record: record, manifestData: data))
            }
            switch ReleaseCatalog.evaluate(
                resolved,
                channel: channel,
                current: current,
                architecture: architecture,
                system: system
            ) {
            case .update(let candidate): return .update(candidate)
            case .upToDate: return .upToDate
            case .noReleases: return .noReleases
            case .noCompatible: return .noCompatible
            case .incomplete: return .incomplete
            }
        } catch {
            switch ReleaseServiceError.map(error) {
            case .rateLimited(let date): return .rateLimited(date)
            case .offline: return .offline
            case .timeout: return .timeout
            case .cancelled: return .offline
            default: return .malformed
            }
        }
    }

    func download(_ candidate: ReleaseCandidate) async throws -> URL {
        guard let url = URL(string: candidate.dmg.browserDownloadURL),
              ReleaseDownloadPolicy.isTrustedInitial(url, assetName: candidate.dmg.name) else {
            throw ReleaseServiceError.unsafeAsset
        }
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.timeoutInterval = 30
        let delegate = ReleaseDownloadDelegate()
        activeDownload = delegate
        defer { activeDownload = nil }

        let location: URL
        do {
            let result = try await transport.download(for: request, delegate: delegate)
            guard (200..<300).contains(result.1.statusCode) else {
                throw ReleaseServiceError.httpStatus(result.1.statusCode)
            }
            location = result.0
        } catch {
            throw ReleaseServiceError.map(error)
        }

        let temporary = FileManager.default.temporaryDirectory
            .appendingPathComponent("melonarc-update-\(UUID().uuidString).dmg")
        do {
            let digest = try DownloadDigest.sha256Hex(location)
            guard digest == candidate.manifest.sha256?.lowercased() else {
                throw ReleaseServiceError.checksumMismatch
            }
            guard ReleaseDigest.matches(hex: digest, assetDigest: candidate.dmg.digest) else {
                throw ReleaseServiceError.digestMismatch
            }
            try FileManager.default.copyItem(at: location, to: temporary)
            return temporary
        } catch {
            try? FileManager.default.removeItem(at: temporary)
            try? FileManager.default.removeItem(at: location)
            throw error
        }
    }

    func cleanUp(_ url: URL?) {
        guard let url else { return }
        try? FileManager.default.removeItem(at: url)
    }

    func cancelDownload() {
        activeDownload?.cancel()
    }

    private func fetchReleases() async throws -> [ReleaseRecord] {
        var pages: [[ReleaseRecord]] = []
        var url = ReleaseEndpointPolicy.releasesURL
        for _ in 0..<ReleaseEndpointPolicy.pages {
            let request = makeRequest(url)
            let (data, response) = try await transport.data(for: request)
            try interpret(response)
            do {
                pages.append(try decoder.decode([ReleaseRecord].self, from: data))
            } catch {
                throw ReleaseServiceError.malformed
            }
            guard let link = response.value(forHTTPHeaderField: "Link"),
                  let next = nextPageURL(from: link) else { break }
            url = next
        }
        return ReleasePaging.merge(pages)
    }

    private func fetchManifest(for record: ReleaseRecord) async -> Data? {
        guard let asset = record.assets.first(where: { $0.name.lowercased() == "candidate.json" }),
              let url = URL(string: asset.browserDownloadURL),
              url.scheme?.lowercased() == "https" else { return nil }
        do {
            let (data, response) = try await transport.data(for: makeRequest(url))
            guard (200..<300).contains(response.statusCode) else { return nil }
            return data
        } catch {
            return nil
        }
    }

    private func makeRequest(_ url: URL) -> URLRequest {
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        request.setValue("MelonARC", forHTTPHeaderField: "User-Agent")
        return request
    }

    private func interpret(_ response: HTTPURLResponse) throws {
        switch response.statusCode {
        case 200..<300: return
        case 403, 429:
            throw ReleaseServiceError.rateLimited(retryDate(from: response))
        default:
            throw ReleaseServiceError.httpStatus(response.statusCode)
        }
    }

    private func retryDate(from response: HTTPURLResponse) -> Date? {
        if let retry = response.value(forHTTPHeaderField: "Retry-After") {
            if let seconds = Double(retry) { return Date().addingTimeInterval(seconds) }
            let formatter = DateFormatter()
            formatter.locale = Locale(identifier: "en_US_POSIX")
            formatter.timeZone = TimeZone(secondsFromGMT: 0)
            formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss zzz"
            if let date = formatter.date(from: retry) { return date }
        }
        if let reset = response.value(forHTTPHeaderField: "X-RateLimit-Reset"),
           let seconds = Double(reset) { return Date(timeIntervalSince1970: seconds) }
        return nil
    }

    private func nextPageURL(from link: String) -> URL? {
        for part in link.split(separator: ",") {
            let piece = part.trimmingCharacters(in: .whitespacesAndNewlines)
            guard piece.contains("rel=\"next\""),
                  let start = piece.firstIndex(of: "<"),
                  let end = piece.firstIndex(of: ">") else { continue }
            let raw = String(piece[piece.index(after: start)..<end])
            guard let url = URL(string: raw) else { continue }
            return ReleaseEndpointPolicy.trustedNextPage(url) ? url : nil
        }
        return nil
    }
}
