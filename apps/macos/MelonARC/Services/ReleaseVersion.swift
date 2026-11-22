import Foundation

enum MelonARCUpdateChannel: String, CaseIterable {
    case preview
    case release

    init(infoValue: String?) {
        let value = infoValue?.lowercased() ?? ""
        self = MelonARCUpdateChannel(rawValue: value) ?? .preview
    }

    func accepts(_ record: ReleaseRecord) -> Bool {
        guard !record.isDraft else { return false }
        switch self {
        case .release: return !record.isPrerelease
        case .preview: return true
        }
    }
}

struct ReleaseShortVersion: Comparable {
    let major: Int
    let minor: Int
    let patch: Int

    static func < (lhs: ReleaseShortVersion, rhs: ReleaseShortVersion) -> Bool {
        if lhs.major != rhs.major { return lhs.major < rhs.major }
        if lhs.minor != rhs.minor { return lhs.minor < rhs.minor }
        return lhs.patch < rhs.patch
    }
}

struct SystemVersion: Comparable {
    let major: Int
    let minor: Int

    static func < (lhs: SystemVersion, rhs: SystemVersion) -> Bool {
        if lhs.major != rhs.major { return lhs.major < rhs.major }
        return lhs.minor < rhs.minor
    }
}

struct ReleaseVersion: Comparable {
    let short: ReleaseShortVersion
    let build: Int

    static func < (lhs: ReleaseVersion, rhs: ReleaseVersion) -> Bool {
        if lhs.short != rhs.short { return lhs.short < rhs.short }
        return lhs.build < rhs.build
    }
}

enum ReleaseVersionParser {
    static func shortVersion(_ text: String?) -> ReleaseShortVersion? {
        guard let text else { return nil }
        let parts = text.split(separator: ".", omittingEmptySubsequences: false)
        guard (1...3).contains(parts.count) else { return nil }
        var numbers: [Int] = []
        for part in parts {
            guard !part.isEmpty else { return nil }
            for scalar in part.unicodeScalars where scalar.value < 48 || scalar.value > 57 {
                return nil
            }
            guard let number = Int(part), number >= 0 else { return nil }
            numbers.append(number)
        }
        return ReleaseShortVersion(
            major: numbers[0],
            minor: numbers.count > 1 ? numbers[1] : 0,
            patch: numbers.count > 2 ? numbers[2] : 0
        )
    }

    static func build(_ text: String?) -> Int? {
        guard let text, !text.isEmpty else { return nil }
        for scalar in text.unicodeScalars where scalar.value < 48 || scalar.value > 57 {
            return nil
        }
        return Int(text)
    }

    static func systemVersion(_ text: String?) -> SystemVersion? {
        guard let text else { return nil }
        let parts = text.split(separator: ".", omittingEmptySubsequences: false)
        guard (1...2).contains(parts.count) else { return nil }
        var numbers: [Int] = []
        for part in parts {
            guard !part.isEmpty else { return nil }
            for scalar in part.unicodeScalars where scalar.value < 48 || scalar.value > 57 {
                return nil
            }
            guard let number = Int(part), number >= 0 else { return nil }
            numbers.append(number)
        }
        return SystemVersion(major: numbers[0], minor: numbers.count > 1 ? numbers[1] : 0)
    }
}

struct ReleaseAsset: Decodable {
    let name: String
    let browserDownloadURL: String
    let digest: String?
    let size: Int64?

    private enum CodingKeys: String, CodingKey {
        case name
        case browserDownloadURL = "browser_download_url"
        case digest
        case size
    }
}

struct ReleaseRecord: Decodable {
    let tagName: String?
    let name: String?
    let draft: Bool?
    let prerelease: Bool?
    let publishedAt: String?
    let htmlURL: String?
    let assets: [ReleaseAsset]

    var isDraft: Bool { draft ?? false }
    var isPrerelease: Bool { prerelease ?? false }

    private enum CodingKeys: String, CodingKey {
        case tagName = "tag_name"
        case name
        case draft
        case prerelease
        case publishedAt = "published_at"
        case htmlURL = "html_url"
        case assets
    }
}

struct CandidateManifest: Decodable {
    let schemaVersion: Int?
    let candidate: String?
    let version: String?
    let buildNumber: String?
    let shortVersion: String?
    let commit: String?
    let sha256: String?
    let arch: String?
    let minimumSystemVersion: String?
    let bundleId: String?
    let license: String?

    private enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case candidate
        case version
        case buildNumber = "build_number"
        case shortVersion = "short_version"
        case commit
        case sha256
        case arch
        case minimumSystemVersion = "minimum_system_version"
        case bundleId = "bundle_id"
        case license
    }

    var releaseVersion: ReleaseVersion? {
        guard let short = ReleaseVersionParser.shortVersion(shortVersion),
              let build = ReleaseVersionParser.build(buildNumber) else { return nil }
        return ReleaseVersion(short: short, build: build)
    }
}

struct ReleaseCandidate {
    let record: ReleaseRecord
    let manifest: CandidateManifest
    let dmg: ReleaseAsset
    let version: ReleaseVersion
}

struct ResolvedRelease {
    let record: ReleaseRecord
    let manifestData: Data?
}

enum ReleaseCatalogResult {
    case update(ReleaseCandidate)
    case upToDate
    case noReleases
    case noCompatible
    case incomplete
}

enum ReleaseCatalog {
    static func evaluate(
        _ resolved: [ResolvedRelease],
        channel: MelonARCUpdateChannel,
        current: ReleaseVersion,
        architecture: String,
        system: SystemVersion
    ) -> ReleaseCatalogResult {
        let eligible = resolved.filter { channel.accepts($0.record) }
        guard !eligible.isEmpty else { return .noReleases }

        var candidates: [ReleaseCandidate] = []
        var sawIncomplete = false
        let decoder = JSONDecoder()

        for entry in eligible {
            guard let data = entry.manifestData,
                  let manifest = try? decoder.decode(CandidateManifest.self, from: data),
                  let version = manifest.releaseVersion,
                  manifest.schemaVersion == 1,
                  manifest.bundleId == "org.melonarc.app",
                  let candidateName = manifest.candidate,
                  let expected = manifest.sha256, expected.count == 64,
                  let arch = manifest.arch,
                  let minimum = ReleaseVersionParser.systemVersion(manifest.minimumSystemVersion),
                  let short = manifest.shortVersion, !short.isEmpty else {
                sawIncomplete = true
                continue
            }
            guard arch == architecture, system >= minimum else { continue }
            let dmgs = entry.record.assets.filter {
                $0.name.lowercased().hasSuffix(".dmg") && $0.name == candidateName
            }
            guard dmgs.count == 1, let dmg = dmgs.first, !dmg.browserDownloadURL.isEmpty else {
                sawIncomplete = true
                continue
            }
            candidates.append(ReleaseCandidate(
                record: entry.record,
                manifest: manifest,
                dmg: dmg,
                version: version
            ))
        }

        guard let newest = candidates.max(by: { $0.version < $1.version }) else {
            return sawIncomplete ? .incomplete : .noCompatible
        }
        return newest.version > current ? .update(newest) : .upToDate
    }
}

enum ReleasePaging {
    static func merge(_ pages: [[ReleaseRecord]]) -> [ReleaseRecord] {
        var seen: Set<String> = []
        var result: [ReleaseRecord] = []
        for page in pages {
            for record in page {
                let key = record.tagName ?? record.htmlURL ?? "\(record.name ?? "")#\(record.publishedAt ?? "")"
                guard seen.insert(key).inserted else { continue }
                result.append(record)
            }
        }
        return result
    }
}

enum ReleaseEndpointPolicy {
    static let host = "api.github.com"
    static let path = "/repos/Melon-tgj/MelonARC/releases"
    static let releasesURL = URL(string: "https://api.github.com/repos/Melon-tgj/MelonARC/releases?per_page=100")!
    static let pages = 5

    static func trustedNextPage(_ url: URL) -> Bool {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              components.scheme?.lowercased() == "https",
              components.host?.lowercased() == host,
              components.path == path else { return false }
        var page: Int?
        var perPage: String?
        for item in components.queryItems ?? [] {
            switch item.name {
            case "page": page = Int(item.value ?? "")
            case "per_page": perPage = item.value
            default: return false
            }
        }
        guard let page, page > 1 else { return false }
        return perPage == nil || perPage == "100"
    }
}

enum ReleaseDownloadPolicy {
    static let repositoryPrefix = "/Melon-tgj/MelonARC/releases/download/"
    static let redirectHosts = [
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com",
        "github-releases.githubusercontent.com",
    ]
    static let maxRedirects = 3

    static func isTrustedInitial(_ url: URL, assetName: String) -> Bool {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              components.scheme?.lowercased() == "https",
              components.host?.lowercased() == "github.com",
              components.path.hasPrefix(repositoryPrefix),
              url.lastPathComponent == assetName else { return false }
        return true
    }

    static func allowsRedirect(from: URL, to: URL, count: Int) -> Bool {
        guard count < maxRedirects,
              from.scheme?.lowercased() == "https",
              to.scheme?.lowercased() == "https",
              let host = to.host?.lowercased() else { return false }
        if host == "github.com" && (from.host?.lowercased() == "github.com" || redirectHosts.contains(from.host?.lowercased() ?? "")) {
            return true
        }
        return redirectHosts.contains(host)
    }
}

enum ReleaseDigest {
    static func matches(hex: String, assetDigest: String?) -> Bool {
        guard let assetDigest, !assetDigest.isEmpty else { return true }
        let normalized = hex.lowercased()
        let value = assetDigest.trimmingCharacters(in: .whitespacesAndNewlines)
        if value.lowercased().hasPrefix("sha256:") {
            let encoded = String(value.dropFirst("sha256:".count))
            guard let bytes = Data(base64Encoded: encoded), bytes.count == 32 else { return false }
            return bytes.map { String(format: "%02x", $0) }.joined() == normalized
        }
        return value.lowercased() == normalized
    }
}
