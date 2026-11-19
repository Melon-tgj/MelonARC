import Foundation

// The wire format of the local API, and only the fields this milestone shows.
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

/// The part of `GET /v1/config` the overview reports. System proxy state is
/// reported by the core, never assumed here: the shell does not write it.
struct ConfigurationView: Decodable, Equatable {
    let path: String?
    let logLevel: String
    let httpListen: String?
    let socks5Listen: String?
    let systemProxy: Bool
    let pendingRestart: [String]
}

/// One policy group, as `GET /v1/policies` reports it. Declared now because the
/// policies panel is the next screen and the shape is already stable.
struct PolicyView: Decodable, Equatable, Identifiable {
    struct Member: Decodable, Equatable, Identifiable {
        let name: String
        let healthy: Bool
        let checked: Bool
        let failures: Int

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

    var id: Int { index }
}

/// The shape every error response uses: `{"error":{"code":…,"message":…}}`.
struct APIErrorEnvelope: Decodable, Equatable {
    struct Body: Decodable, Equatable {
        let code: String
        let message: String
    }

    let error: Body
}
