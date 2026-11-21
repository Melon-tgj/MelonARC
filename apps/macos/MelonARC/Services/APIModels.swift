import Foundation

// The wire format of the local API, and only the fields this build shows.
//
// The views are declared here rather than by decoding everything: a field that is
// not drawn is still decoded (and would then have to be kept in step with the
// daemon), and a field that is drawn but missing from the model is the bug this
// file exists to prevent. Each type is a subset of the Go view of the same name;
// extra keys in the JSON are ignored.

/// `GET /v1/status`.
struct StatusView: Decodable, Equatable {
    let version: String
    let uptimeSeconds: Double
    let configPath: String?
    let ruleCount: Int
    let policyCount: Int
}

/// The stable display state of the desktop proxy takeover.
///
/// The core chooses the value so precedence is decided in one place. An unknown
/// value from a newer core is kept rather than mapped onto a known state: showing
/// "off" for a state this build cannot name would be a lie.
enum SystemProxyState: String, Decodable, Equatable {
    case off
    case configured
    case pendingRestart = "pending_restart"
    case applied
    case recoveryFailed = "recovery_failed"
    case unknown

    init(from decoder: Decoder) throws {
        let raw = try decoder.singleValueContainer().decode(String.self)
        self = SystemProxyState(rawValue: raw) ?? .unknown
    }

    var localizationKey: String {
        switch self {
        case .off: return "system_proxy.state.off"
        case .configured: return "system_proxy.state.configured"
        case .pendingRestart: return "system_proxy.state.pending_restart"
        case .applied: return "system_proxy.state.applied"
        case .recoveryFailed: return "system_proxy.state.recovery_failed"
        case .unknown: return "system_proxy.state.unknown"
        }
    }
}

/// The four-state proxy report carried by `GET /v1/config`.
struct SystemProxyStateView: Decodable, Equatable {
    let state: SystemProxyState
    let configured: Bool
    let pendingRestart: Bool
    let applied: Bool
    let recoveryFailed: Bool
    let detail: String

    private enum CodingKeys: String, CodingKey {
        case state, configured, pendingRestart, applied, recoveryFailed, detail
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        state = try container.decodeIfPresent(SystemProxyState.self, forKey: .state) ?? .off
        configured = try container.decodeIfPresent(Bool.self, forKey: .configured) ?? false
        pendingRestart = try container.decodeIfPresent(Bool.self, forKey: .pendingRestart) ?? false
        applied = try container.decodeIfPresent(Bool.self, forKey: .applied) ?? false
        recoveryFailed = try container.decodeIfPresent(Bool.self, forKey: .recoveryFailed) ?? false
        detail = try container.decodeIfPresent(String.self, forKey: .detail) ?? ""
    }

    init(
        state: SystemProxyState,
        configured: Bool = false,
        pendingRestart: Bool = false,
        applied: Bool = false,
        recoveryFailed: Bool = false,
        detail: String = ""
    ) {
        self.state = state
        self.configured = configured
        self.pendingRestart = pendingRestart
        self.applied = applied
        self.recoveryFailed = recoveryFailed
        self.detail = detail
    }
}

/// The part of `GET /v1/config` the shell reports and writes.
struct ConfigurationView: Decodable, Equatable {
    let path: String?
    let logLevel: String
    let httpListen: String?
    let socks5Listen: String?
    let systemProxy: Bool
    let systemProxyState: SystemProxyStateView
    let pendingRestart: [String]

    private enum CodingKeys: String, CodingKey {
        case path, logLevel, httpListen, socks5Listen, systemProxy, systemProxyState, pendingRestart
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        path = try container.decodeIfPresent(String.self, forKey: .path)
        logLevel = try container.decodeIfPresent(String.self, forKey: .logLevel) ?? ""
        httpListen = try container.decodeIfPresent(String.self, forKey: .httpListen)
        socks5Listen = try container.decodeIfPresent(String.self, forKey: .socks5Listen)
        systemProxy = try container.decodeIfPresent(Bool.self, forKey: .systemProxy) ?? false
        systemProxyState = (try container.decodeIfPresent(SystemProxyStateView.self, forKey: .systemProxyState))
            ?? SystemProxyStateView(state: .off)
        pendingRestart = try container.decodeIfPresent([String].self, forKey: .pendingRestart) ?? []
    }
}

/// One policy group, as `GET /v1/policies` reports it.
struct PolicyView: Decodable, Equatable, Identifiable {
    struct Member: Decodable, Equatable, Identifiable {
        let name: String
        let healthy: Bool
        let checked: Bool
        let latencyMs: Double
        let checkedAt: String?
        let failures: Int
        let error: String?

        var id: String { name }
    }

    let name: String
    let type: String
    /// The member in force: the one a rule naming this group reaches.
    let active: String
    let healthyMembers: Int
    let allUnhealthy: Bool
    let members: [Member]

    var id: String { name }
}

/// One page of `GET /v1/rules`.
struct RulePage: Decodable, Equatable {
    let total: Int
    let limit: Int
    let rules: [RuleView]
}

struct RuleView: Decodable, Equatable, Identifiable {
    let index: Int
    let type: String
    let payload: String?
    let target: String
    let source: String?
    let line: Int?
    let noResolve: Bool?

    var id: Int { index }
}

/// One subscription's refresh state, without the skipped detail.
struct SubscriptionView: Decodable, Equatable, Identifiable {
    let name: String
    let nodes: Int
    let skipped: Int
    let fetchedAt: String?
    let nextAt: String?
    let attempts: Int
    let error: String?

    var id: String { name }
}

struct SubscriptionListView: Decodable, Equatable {
    let subscriptions: [SubscriptionView]
}

struct SubscriptionCreateRequest: Encodable, Equatable {
    let name: String
    let url: String
    let intervalSeconds: Int64?
}

struct SubscriptionSkippedEntryView: Decodable, Equatable {
    let item: Int
    let reason: String
}

struct SubscriptionSkippedView: Decodable, Equatable {
    let subscription: String
    let refreshed: Bool
    let fetchedAt: String?
    let total: Int
    let offset: Int
    let limit: Int
    let skipped: [SubscriptionSkippedEntryView]
}

struct SubscriptionRefreshView: Decodable, Equatable {
    let subscription: String
    let refreshed: Bool
    let reloaded: Bool
    let nodes: Int
    let skipped: Int
    let fetchedAt: String?
    let attempts: Int
    let error: String?
}

/// One carried connection, from `GET /v1/history/connections`.
struct ConnectionView: Decodable, Equatable, Identifiable {
    let time: String
    let protocolName: String
    let target: String
    let network: String
    let rule: String?
    let policy: String?
    let outbound: String?
    let up: Int64
    let down: Int64
    let durationMs: Double

    enum CodingKeys: String, CodingKey {
        case time, target, network, rule, policy, outbound, up, down
        case protocolName = "protocol"
        case durationMs
    }

    var id: String { "\(time)-\(protocolName)-\(target)-\(network)" }
}

struct ConnectionListView: Decodable, Equatable {
    let count: Int
    let connections: [ConnectionView]
}

/// One daemon event, from `GET /v1/history/events`.
struct EventView: Decodable, Equatable, Identifiable {
    let time: String
    let kind: String
    let name: String?
    let detail: String?
    let ok: Bool

    var id: String { "\(time)-\(kind)-\(name ?? "")-\(detail ?? "")" }
}

struct EventListView: Decodable, Equatable {
    let count: Int
    let events: [EventView]
}

/// The outcome of pinning a manual policy group.
struct SelectView: Decodable, Equatable {
    let group: String
    let previous: String?
    let active: String
}

/// The outcome of re-reading the configuration file.
struct ReloadView: Decodable, Equatable {
    let ok: Bool
    let path: String?
    let ruleCount: Int
    let proxyCount: Int
    let groupCount: Int
    let hostCount: Int
    let restartRequired: [String]
    let pendingRestart: [String]
}

/// The body and answer of `POST /v1/config/update`.
struct ConfigUpdateRequest: Encodable, Equatable {
    let logLevel: String?
    let systemProxy: Bool?
}

struct ConfigUpdateView: Decodable, Equatable {
    let path: String?
    let logLevel: String?
    let systemProxy: Bool
    let restartRequired: [String]
}

/// The shape every error response uses: `{"error":{"code":…,"message":…}}`.
struct APIErrorEnvelope: Decodable, Equatable {
    struct Body: Decodable, Equatable {
        let code: String
        let message: String
    }

    let error: Body
}
