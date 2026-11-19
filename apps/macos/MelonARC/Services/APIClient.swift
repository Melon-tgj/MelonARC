import Foundation

/// The paths this shell can call.
///
/// Adding an endpoint is one case here and one method on `APIClient`; the
/// transport, the token handling and the error mapping stay untouched. Paths
/// that carry a name have a builder instead of a case, so the name is escaped
/// in exactly one place. That is the extension point the remaining panels use.
enum APIEndpoint: String, CaseIterable {
    case status = "/v1/status"
    case configuration = "/v1/config"
    case configUpdate = "/v1/config/update"
    case configReload = "/v1/config/reload"
    case policies = "/v1/policies"
    case policySelect = "/v1/policies/select"
    case rules = "/v1/rules"
    case subscriptions = "/v1/subscriptions"
    case connections = "/v1/history/connections"
    case events = "/v1/history/events"
    case inbound = "/v1/inbound"
    case failures = "/v1/failures"
    case dns = "/v1/dns"

    /// The single-segment escape used by every path with a configuration name.
    static func escapedSegment(_ value: String) -> String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        return value.addingPercentEncoding(withAllowedCharacters: allowed) ?? ""
    }

    static func subscriptionRefresh(_ name: String) -> String {
        "/v1/subscriptions/\(escapedSegment(name))/refresh"
    }
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
    /// The core answered with a structured error of its own.
    case api(String, Int, String?)
    /// The body could not be decoded.
    case decoding(String)

    var code: String {
        switch self {
        case .tokenMissing: return "token_missing"
        case .unauthorized: return "unauthorized"
        case .unreachable: return "unreachable"
        case .status: return "http_status"
        case .api(let code, _, _): return code
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
        case .api(let code, let status, let message):
            let suffix = message.map { ": \($0)" } ?? ""
            return "the core answered HTTP \(status) with \(code)\(suffix)"
        case .decoding(let detail):
            return "the core answered with a body this build cannot read: \(detail)"
        }
    }

    var errorDescription: String? { detail }
}

/// Type erasure for write bodies. It keeps one transport method for every
/// endpoint while `JSONEncoder` still sees a concrete `Encodable`.
private struct AnyEncodable: Encodable {
    private let encodeValue: (Encoder) throws -> Void

    init<T: Encodable>(_ value: T) {
        encodeValue = { encoder in try value.encode(to: encoder) }
    }

    func encode(to encoder: Encoder) throws {
        try encodeValue(encoder)
    }
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
        try await send(.get, APIEndpoint.status.rawValue)
    }

    func configuration() async throws -> ConfigurationView {
        try await send(.get, APIEndpoint.configuration.rawValue)
    }

    func policies() async throws -> [PolicyView] {
        struct Envelope: Decodable { let policies: [PolicyView] }
        let envelope: Envelope = try await send(.get, APIEndpoint.policies.rawValue)
        return envelope.policies
    }

    func rules(limit: Int) async throws -> RulePage {
        try await send(.get, APIEndpoint.rules.rawValue + "?limit=\(limit)")
    }

    func subscriptions() async throws -> SubscriptionListView {
        try await send(.get, APIEndpoint.subscriptions.rawValue)
    }

    func refreshSubscription(_ name: String) async throws -> SubscriptionRefreshView {
        try await send(.post, APIEndpoint.subscriptionRefresh(name))
    }

    func connections(limit: Int) async throws -> ConnectionListView {
        try await send(.get, APIEndpoint.connections.rawValue + "?limit=\(limit)")
    }

    func events(limit: Int) async throws -> EventListView {
        try await send(.get, APIEndpoint.events.rawValue + "?limit=\(limit)")
    }

    func selectPolicy(group: String, member: String) async throws -> SelectView {
        struct Body: Encodable { let group: String; let member: String }
        return try await send(.post, APIEndpoint.policySelect.rawValue, body: AnyEncodable(Body(group: group, member: member)))
    }

    func updateConfiguration(_ request: ConfigUpdateRequest) async throws -> ConfigUpdateView {
        try await send(.post, APIEndpoint.configUpdate.rawValue, body: AnyEncodable(request))
    }

    func reloadConfiguration() async throws -> ReloadView {
        try await send(.post, APIEndpoint.configReload.rawValue)
    }

    // MARK: - Transport

    private enum Method: String {
        case get = "GET"
        case post = "POST"
    }

    private func send<T: Decodable>(
        _ method: Method,
        _ path: String,
        body: AnyEncodable? = nil
    ) async throws -> T {
        let token = try readToken()
        guard let base = address.baseURL, let url = URL(string: path, relativeTo: base)?.absoluteURL else {
            throw APIError.unreachable("\(address.label) is not a usable base URL")
        }

        var request = URLRequest(url: url)
        request.httpMethod = method.rawValue
        request.timeoutInterval = timeout
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        if let body {
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = try Self.makeEncoder().encode(body)
        }

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
            if let envelope = try? Self.makeDecoder().decode(APIErrorEnvelope.self, from: data) {
                throw APIError.api(envelope.error.code, http.statusCode, envelope.error.message)
            }
            throw APIError.status(http.statusCode, nil)
        }
    }

    private static func makeDecoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return decoder
    }

    private static func makeEncoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        return encoder
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
