import CryptoKit
import Foundation
import XCTest

private final class FakeReleaseTransport: ReleaseHTTPTransport {
    var dataHandler: ((URLRequest) async throws -> (Data, HTTPURLResponse))?
    var downloadHandler: ((URLRequest, ReleaseDownloadDelegate) async throws -> (URL, HTTPURLResponse))?
    private(set) var requests: [URLRequest] = []

    func data(for request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        requests.append(request)
        guard let dataHandler else { throw URLError(.unknown) }
        return try await dataHandler(request)
    }

    func download(for request: URLRequest, delegate: ReleaseDownloadDelegate) async throws -> (URL, HTTPURLResponse) {
        requests.append(request)
        guard let downloadHandler else { throw URLError(.unknown) }
        return try await downloadHandler(request, delegate)
    }
}

private func httpResponse(
    _ status: Int,
    url: URL = URL(string: "https://api.github.com/repos/Melon-tgj/MelonARC/releases")!,
    headers: [String: String] = [:]
) -> HTTPURLResponse {
    HTTPURLResponse(url: url, statusCode: status, httpVersion: nil, headerFields: headers)!
}

private func releaseList(_ records: [[String: Any]]) throws -> Data {
    try JSONSerialization.data(withJSONObject: records)
}

private func asset(
    name: String = "melonarc-test-macos-arm64.dmg",
    digest: String? = nil,
    url: String? = nil
) -> [String: Any] {
    var value: [String: Any] = [
        "name": name,
        "browser_download_url": url ?? "https://github.com/Melon-tgj/MelonARC/releases/download/t/\(name)",
        "size": 1024,
    ]
    if let digest { value["digest"] = digest }
    return value
}

private func record(
    tag: String,
    prerelease: Bool = false,
    draft: Bool = false,
    assets: [[String: Any]] = []
) -> [String: Any] {
    [
        "tag_name": tag,
        "name": tag,
        "prerelease": prerelease,
        "draft": draft,
        "published_at": "2026-11-20T12:00:00Z",
        "html_url": "https://github.com/Melon-tgj/MelonARC/releases/tag/\(tag)",
        "assets": assets,
    ]
}

private func manifestData(
    short: String = "0.1.0",
    build: String = "42",
    digest: String,
    arch: String = "arm64",
    minimum: String = "13.0",
    dmg: String = "melonarc-test-macos-arm64.dmg"
) throws -> Data {
    try JSONSerialization.data(withJSONObject: [
        "schema_version": 1,
        "candidate": dmg,
        "commit": "abc123",
        "build_number": build,
        "version": "0.1.0-preview-candidate.\(build)",
        "short_version": short,
        "arch": arch,
        "minimum_system_version": minimum,
        "bundle_id": "org.melonarc.app",
        "license": "GPL-3.0-only",
        "sha256": digest,
    ])
}

private func hexDigest(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

private func candidate(for data: Data, digest: String? = nil) throws -> ReleaseCandidate {
    let decoder = JSONDecoder()
    let decoded = try decoder.decode(
        ReleaseRecord.self,
        from: releaseList([record(tag: "v42", assets: [asset(digest: digest)])])
    )
    let manifest = try decoder.decode(
        CandidateManifest.self,
        from: manifestData(digest: hexDigest(data))
    )
    return ReleaseCandidate(
        record: decoded,
        manifest: manifest,
        dmg: decoded.assets[0],
        version: manifest.releaseVersion!
    )
}

private func currentVersion(_ short: String = "0.1.0", _ build: String = "41") -> ReleaseVersion {
    ReleaseVersion(
        short: ReleaseVersionParser.shortVersion(short)!,
        build: ReleaseVersionParser.build(build)!
    )
}

final class ReleaseUpdateTests: XCTestCase {
    func testCheckUsesRepositoryEndpointWithoutLocalSecrets() async throws {
        let transport = FakeReleaseTransport()
        transport.dataHandler = { _ in (try releaseList([]), httpResponse(200)) }
        let service = ReleaseUpdateService(transport: transport)

        let outcome = await service.check(
            channel: .preview,
            current: currentVersion(),
            architecture: "arm64",
            system: SystemVersion(major: 15, minor: 0)
        )

        guard case .noReleases = outcome else { return XCTFail("expected no releases") }
        XCTAssertEqual(transport.requests.count, 1)
        let request = try XCTUnwrap(transport.requests.first)
        XCTAssertEqual(request.url, ReleaseEndpointPolicy.releasesURL)
        XCTAssertEqual(request.httpMethod, "GET")
        XCTAssertNil(request.value(forHTTPHeaderField: "Authorization"))
        let headers = request.allHTTPHeaderFields?.values.joined(separator: " ").lowercased() ?? ""
        XCTAssertFalse(headers.contains("token"))
        XCTAssertFalse(headers.contains("subscription"))
    }

    func testCheckFetchesManifestAndFindsPreviewBuild() async throws {
        let dmg = "melonarc-test-macos-arm64.dmg"
        let digest = String(repeating: "b", count: 64)
        let manifestURL = "https://github.com/Melon-tgj/MelonARC/releases/download/t/candidate.json"
        let transport = FakeReleaseTransport()
        transport.dataHandler = { request in
            if request.url?.path.hasSuffix("/releases") == true {
                return (
                    try releaseList([
                        record(
                            tag: "preview-42",
                            prerelease: true,
                            assets: [asset(name: "candidate.json", url: manifestURL), asset(name: dmg)],
                        ),
                    ]),
                    httpResponse(200)
                )
            }
            return (try manifestData(digest: digest), httpResponse(200))
        }
        let service = ReleaseUpdateService(transport: transport)

        let outcome = await service.check(
            channel: .preview,
            current: currentVersion(),
            architecture: "arm64",
            system: SystemVersion(major: 15, minor: 0)
        )

        guard case .update(let found) = outcome else { return XCTFail("expected an update") }
        XCTAssertEqual(found.manifest.buildNumber, "42")
        XCTAssertEqual(found.dmg.name, dmg)
        XCTAssertEqual(transport.requests.count, 2)
    }

    func testCheckFollowsOneTrustedNextPage() async throws {
        let first = record(tag: "one")
        let second = record(tag: "two", assets: [asset(name: "candidate.json")])
        let transport = FakeReleaseTransport()
        transport.dataHandler = { request in
            if request.url?.query?.contains("page=2") == true {
                return (try releaseList([second]), httpResponse(200))
            }
            return (
                try releaseList([first]),
                httpResponse(200, headers: [
                    "Link": "<https://api.github.com/repos/Melon-tgj/MelonARC/releases?per_page=100&page=2>; rel=\"next\"",
                ])
            )
        }
        let service = ReleaseUpdateService(transport: transport)

        _ = await service.check(
            channel: .preview,
            current: currentVersion(),
            architecture: "arm64",
            system: SystemVersion(major: 15, minor: 0)
        )

        XCTAssertEqual(transport.requests.count, 3)
        XCTAssertEqual(transport.requests[1].url?.query, "per_page=100&page=2")
    }

    func testRateLimitAndOfflineAreReportedSeparately() async throws {
        let limited = FakeReleaseTransport()
        limited.dataHandler = { _ in
            (Data(), httpResponse(429, headers: ["Retry-After": "60"]))
        }
        let limitedOutcome = await ReleaseUpdateService(transport: limited).check(
            channel: .preview,
            current: currentVersion(),
            architecture: "arm64",
            system: SystemVersion(major: 15, minor: 0)
        )
        guard case .rateLimited(let date) = limitedOutcome else {
            return XCTFail("expected rate limiting")
        }
        XCTAssertNotNil(date)

        let offline = FakeReleaseTransport()
        offline.dataHandler = { _ in throw URLError(.notConnectedToInternet) }
        let offlineOutcome = await ReleaseUpdateService(transport: offline).check(
            channel: .preview,
            current: currentVersion(),
            architecture: "arm64",
            system: SystemVersion(major: 15, minor: 0)
        )
        guard case .offline = offlineOutcome else { return XCTFail("expected offline") }
    }

    func testMalformedReleasePayloadIsNotCrashing() async throws {
        let transport = FakeReleaseTransport()
        transport.dataHandler = { _ in (Data("not json".utf8), httpResponse(200)) }
        let outcome = await ReleaseUpdateService(transport: transport).check(
            channel: .preview,
            current: currentVersion(),
            architecture: "arm64",
            system: SystemVersion(major: 15, minor: 0)
        )
        guard case .malformed = outcome else { return XCTFail("expected malformed") }
    }

    func testVerifiedDownloadReturnsTemporaryFile() async throws {
        let payload = Data("signed candidate image".utf8)
        let transport = FakeReleaseTransport()
        transport.downloadHandler = { _, _ in
            let location = FileManager.default.temporaryDirectory
                .appendingPathComponent("fake-download-\(UUID().uuidString).dmg")
            try payload.write(to: location)
            return (location, httpResponse(200))
        }
        let service = ReleaseUpdateService(transport: transport)
        let candidate = try candidate(for: payload)

        let saved = try await service.download(candidate)
        defer { service.cleanUp(saved) }

        XCTAssertEqual(try Data(contentsOf: saved), payload)
        XCTAssertTrue(saved.lastPathComponent.hasPrefix("melonarc-update-"))
    }

    func testChecksumMismatchNeverDeliversTheDownload() async throws {
        let payload = Data("tampered image".utf8)
        let transport = FakeReleaseTransport()
        transport.downloadHandler = { _, _ in
            let location = FileManager.default.temporaryDirectory
                .appendingPathComponent("fake-download-\(UUID().uuidString).dmg")
            try payload.write(to: location)
            return (location, httpResponse(200))
        }
        let service = ReleaseUpdateService(transport: transport)
        let candidate = try candidate(for: Data("expected image".utf8))

        do {
            _ = try await service.download(candidate)
            XCTFail("expected checksum mismatch")
        } catch let error as ReleaseServiceError {
            guard case .checksumMismatch = error else { return XCTFail("unexpected error: \(error)") }
        }
    }

    func testUnsafeAssetIsRejectedBeforeAnyRequest() async throws {
        let transport = FakeReleaseTransport()
        let service = ReleaseUpdateService(transport: transport)
        let base = try candidate(for: Data("payload".utf8))
        let candidate = ReleaseCandidate(
            record: base.record,
            manifest: base.manifest,
            dmg: ReleaseAsset(
                name: "melonarc-test-macos-arm64.dmg",
                browserDownloadURL: "https://example.org/melonarc-test-macos-arm64.dmg",
                digest: nil,
                size: 1
            ),
            version: base.version
        )

        do {
            _ = try await service.download(candidate)
            XCTFail("expected unsafe asset")
        } catch let error as ReleaseServiceError {
            guard case .unsafeAsset = error else { return XCTFail("unexpected error: \(error)") }
        }
        XCTAssertTrue(transport.requests.isEmpty)
    }
}
