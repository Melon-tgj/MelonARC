import Foundation

/// The loopback endpoint of the core's local API.
///
/// Only loopback is accepted, and it is decided by the address rather than by a
/// string prefix: `127.example.com` is not loopback and never becomes one. No name
/// is ever resolved — a name that resolved to loopback at start-up could resolve
/// somewhere else at connect time and take the bearer token with it — so the one
/// name understood is `localhost`, which RFC 6761 defines as loopback and which is
/// mapped here to the IPv4 literal the core listens on. IPv6 loopback is refused:
/// the application declares exactly one ATS exception, for `127.0.0.1`, and a
/// second loopback literal would need a second one.
struct APIAddress: Equatable {
    /// A dotted IPv4 literal in 127.0.0.0/8.
    let host: String
    let port: Int

    /// The default of the core and of the previous shell.
    static let defaultPort = 7946
    static let defaultAddress = "127.0.0.1:7946"

    /// `host:port`, with an IPv6 host bracketed, which is what a URL needs.
    var label: String { "\(host):\(port)" }

    var baseURL: URL? { URL(string: "http://\(label)/") }

    init(host: String, port: Int) {
        self.host = host
        self.port = port
    }

    /// Parses `host:port` and `localhost:port`. Brackets are recognised only so
    /// that an IPv6 address gets a clear error instead of a silent guess.
    static func parse(_ raw: String) throws -> APIAddress {
        let value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty else {
            throw ShellError.invalidAddress("the address is empty")
        }
        let (host, port) = try split(value)
        return APIAddress(host: try canonicalLoopback(host), port: port)
    }

    /// Splits the host from the port. An unbracketed value with more than one
    /// colon is refused rather than guessed at: `::1:7946` is ambiguous, and
    /// guessing wrong would send the token to a host nobody named.
    private static func split(_ value: String) throws -> (String, Int) {
        if value.hasPrefix("[") {
            guard let close = value.firstIndex(of: "]") else {
                throw ShellError.invalidAddress("\(value) has no closing bracket")
            }
            let host = String(value[value.index(after: value.startIndex)..<close])
            let rest = value[value.index(after: close)...]
            guard rest.hasPrefix(":") else {
                throw ShellError.invalidAddress("\(value) has no port")
            }
            return (host, try parsePort(String(rest.dropFirst()), in: value))
        }
        guard let colon = value.lastIndex(of: ":") else {
            throw ShellError.invalidAddress("\(value) has no port")
        }
        let host = String(value[..<colon])
        guard !host.contains(":") else {
            throw ShellError.invalidAddress("an IPv6 address must be bracketed: [\(host)]:\(value[value.index(after: colon)...])")
        }
        return (host, try parsePort(String(value[value.index(after: colon)...]), in: value))
    }

    private static func parsePort(_ raw: String, in value: String) throws -> Int {
        guard let port = Int(raw), (1...65535).contains(port) else {
            throw ShellError.invalidAddress("\(value) does not end in a port between 1 and 65535")
        }
        return port
    }

    /// The canonical literal for a loopback host, or an error naming what was
    /// given instead.
    private static func canonicalLoopback(_ host: String) throws -> String {
        let lowered = host.lowercased()
        if lowered == "localhost" { return "127.0.0.1" }

        let parts = lowered.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4, parts[0] == "127" else {
            throw ShellError.invalidAddress("\(host) is not a loopback address")
        }
        for part in parts {
            guard let octet = Int(part), (0...255).contains(octet) else {
                throw ShellError.invalidAddress("\(host) is not a dotted IPv4 address")
            }
        }
        return lowered
    }
}
