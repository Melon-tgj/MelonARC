import Foundation

/// The paths this shell can call.
///
/// Adding an endpoint is one case here and one method on `APIClient`; the
/// transport, the token handling and the error mapping stay untouched. That is the
/// extension point the next milestone builds the remaining panels on.
enum APIEndpoint: String, CaseIterable {
    case status = "/v1/status"
    case configuration = "/v1/config"
    case policies = "/v1/policies"
    case rules = "/v1/rules"
    case subscriptions = "/v1/subscriptions"
    case inbound = "/v1/inbound"
    case failures = "/v1/failures"
    case dns = "/v1/dns"
}

/// A call that could not be completed.
///
/// `code` is the stable name the interface translates; `detail` is the English
/// technical line that belongs in a bug report and is never shown as a sentence.
enum APIError: Error, Equatable, LocalizedError {
    /// The token file is missing, empty or not a token.
    case tokenMissing(String)
    /// The core answered 401: the token is stale or belongs to another core.
    case unauthorized
    /// Nothing is listening, or the connection died.
    case unreachable(String)
    /// The core answered, but not with the expected body.
    case status(Int, String?)
    /// The body could not be decoded.
    case decoding(String)

    var code: String {
        switch self {
        case .tokenMissing: return "token_missing"
        case .unauthorized: return "unauthorized"
        case .unreachable: return "unreachable"
        case .status: return "http_status"
        case .decoding: return "decoding"
        }
    }

    var detail: String {
        switch self {
        case .tokenMissing(let path):
            return "the API token could not be read from \(path)"
        case .unauthorized:
            return "the core rejected the bearer token with 401"
        case .unreachable(let detail):
            return "the core did not answer: \(detail)"
        case .status(let code, let apiCode):
            let suffix = apiCode.map { " (\($0))" } ?? ""
            return "the core answered with HTTP \(code)\(suffix)"
        case .decoding(let detail):
            return "the core answered with a body this build cannot read: \(detail)"
        }
    }

    var errorDescription: String? { detail }
}

/// Refuses every redirect.
///
/// The API is one loopback origin; a redirect would be either a bug or an attempt
/// to move the bearer token somewhere else. `nil` in the completion handler tells
/// the session to deliver the 3xx response itself, which the status check then
/// refuses.
private final class RedirectRefuser: NSObject, URLSessionTaskDelegate {
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }
}

/// The only place the API token is used.
///
/// A dedicated session, not `URLSession.shared`: the shared session follows the
/// system proxy and keeps a cache, and neither is acceptable for a control channel
/// that has to work while the machine's proxy is misconfigured by this very
/// program. The configuration here is ephemeral, has no proxy dictionary at all,
/// no cache and no cookies, and its delegate refuses redirects.
final class APIClient {
    private let address: APIAddress
    private let tokenURL: URL
    private let timeout: TimeInterval
    private let session: URLSession
    private let redirects = RedirectRefuser()

    init(address: APIAddress, tokenURL: URL, timeout: TimeInterval = 5) {
        self.address = address
        self.tokenURL = tokenURL
        self.timeout = timeout

        let configuration = URLSessionConfiguration.ephemeral
        // An empty dictionary means "no proxy": the default, `nil`, means "use the
        // system settings", which is exactly what must not happen here. See
        // `URLSessionConfiguration.connectionProxyDictionary`.
        configuration.connectionProxyDictionary = [:]
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.urlCache = nil
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.timeoutIntervalForRequest = timeout
        configuration.timeoutIntervalForResource = timeout
        configuration.waitsForConnectivity = false
        self.session = URLSession(configuration: configuration, delegate: redirects, delegateQueue: nil)
    }

    // MARK: - Endpoints

    func status() async throws -> StatusView {
        try await get(.status)
    }

    func configuration() async throws -> ConfigurationView {
        try await get(.configuration)
    }

    func policies() async throws -> [PolicyView] {
        struct Envelope: Decodable { let policies: [PolicyView] }
        let envelope: Envelope = try await get(.policies)
        return envelope.policies
    }

    // MARK: - Transport

    private func get<T: Decodable>(_ endpoint: APIEndpoint) async throws -> T {
        let token = try readToken()
        guard let base = address.baseURL, let url = URL(string: endpoint.rawValue, relativeTo: base)?.absoluteURL else {
            throw APIError.unreachable("\(address.label) is not a usable base URL")
        }

        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.timeoutInterval = timeout
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")

        let data: Data
        let response: URLResponse
        do {
            let result = try await session.data(for: request)
            data = result.0
            response = result.1
        } catch let error as URLError {
            throw APIError.unreachable(error.localizedDescription)
        } catch {
            throw APIError.unreachable(error.localizedDescription)
        }

        guard let http = response as? HTTPURLResponse else {
            throw APIError.status(0, nil)
        }
        switch http.statusCode {
        case 200:
            do {
                return try Self.makeDecoder().decode(T.self, from: data)
            } catch {
                throw APIError.decoding(String(describing: error))
            }
        case 401, 403:
            throw APIError.unauthorized
        default:
            throw APIError.status(http.statusCode, Self.apiCode(in: data))
        }
    }

    private static func makeDecoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return decoder
    }

    private static func apiCode(in data: Data) -> String? {
        try? makeDecoder().decode(APIErrorEnvelope.self, from: data).error.code
    }

    /// Reads `<data-dir>/api-token`.
    ///
    /// The daemon writes the file with 0600 and replaces it atomically; this side
    /// only checks the shape of what it found, because a file a user pasted into is
    /// worse than a missing one when the value travels in a header.
    func readToken() throws -> String {
        guard let data = try? Data(contentsOf: tokenURL) else {
            throw APIError.tokenMissing(tokenURL.path)
        }
        guard let raw = String(data: data, encoding: .utf8) else {
            throw APIError.tokenMissing(tokenURL.path)
        }
        let token = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !token.isEmpty, token.utf8.count <= 512 else {
            throw APIError.tokenMissing(tokenURL.path)
        }
        for scalar in token.unicodeScalars {
            if scalar.value <= 0x20 || scalar.value == 0x7F {
                throw APIError.tokenMissing(tokenURL.path)
            }
        }
        return token
    }
}
