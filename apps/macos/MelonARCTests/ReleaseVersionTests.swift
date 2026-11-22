import Foundation
import XCTest

final class ReleaseVersionTests: XCTestCase {
    private func record(
        tag: String,
        prerelease: Bool = false,
        draft: Bool = false,
        assets: [[String: Any]] = []
    ) -> ReleaseRecord {
        let object: [String: Any] = [
            "tag_name": tag,
            "name": tag,
            "prerelease": prerelease,
            "draft": draft,
            "published_at": "2026-11-20T12:00:00Z",
            "html_url": "https://github.com/Melon-tgj/MelonARC/releases/tag/\(tag)",
            "assets": assets,
        ]
        let data = try! JSONSerialization.data(withJSONObject: object)
        return try! JSONDecoder().decode(ReleaseRecord.self, from: data)
    }

    private func dmgAsset(name: String = "melonarc-test-macos-arm64.dmg", digest: String? = nil) -> [String: Any] {
        var asset: [String: Any] = [
            "name": name,
            "browser_download_url": "https://github.com/Melon-tgj/MelonARC/releases/download/t/\(name)",
            "size": 1024,
        ]
        if let digest { asset["digest"] = digest }
        return asset
    }

    private func manifest(
        short: String,
        build: String,
        arch: String = "arm64",
        minimum: String = "13.0",
        dmg: String = "melonarc-test-macos-arm64.dmg"
    ) -> Data {
        let object: [String: Any] = [
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
            "sha256": String(repeating: "a", count: 64),
        ]
        return try! JSONSerialization.data(withJSONObject: object)
    }

    private func version(_ short: String, _ build: String) -> ReleaseVersion {
        ReleaseVersion(
            short: ReleaseVersionParser.shortVersion(short)!,
            build: ReleaseVersionParser.build(build)!
        )
    }

    func testShortVersionAndDecimalBuildCompareAsIntegers() {
        XCTAssertEqual(ReleaseVersionParser.shortVersion("0.1.0"), ReleaseShortVersion(major: 0, minor: 1, patch: 0))
        XCTAssertNil(ReleaseVersionParser.shortVersion("0.1.x"))
        XCTAssertNil(ReleaseVersionParser.build("01a"))
        XCTAssertNil(ReleaseVersionParser.build(""))
        XCTAssertEqual(ReleaseVersionParser.build("9"), 9)
        XCTAssertTrue(version("0.1.0", "42") > version("0.1.0", "41"))
        XCTAssertTrue(version("0.1.0", "9") < version("0.1.0", "41"))
        XCTAssertTrue(version("0.2.0", "1") > version("0.1.9", "999"))
    }

    func testChannelsFilterDraftsAndPreviews() {
        let normal = record(tag: "stable")
        let preview = record(tag: "preview", prerelease: true)
        let draft = record(tag: "draft", draft: true)
        XCTAssertFalse(MelonARCUpdateChannel.release.accepts(draft))
        XCTAssertFalse(MelonARCUpdateChannel.release.accepts(preview))
        XCTAssertTrue(MelonARCUpdateChannel.release.accepts(normal))
        XCTAssertFalse(MelonARCUpdateChannel.preview.accepts(draft))
        XCTAssertTrue(MelonARCUpdateChannel.preview.accepts(preview))
        XCTAssertTrue(MelonARCUpdateChannel.preview.accepts(normal))
    }

    func testPaginationMergeIsStableAndDeduplicates() {
        let first = record(tag: "one")
        let second = record(tag: "two")
        let merged = ReleasePaging.merge([[first, second], [second]])
        XCTAssertEqual(merged.count, 2)
        XCTAssertEqual(merged.first?.tagName, "one")
    }

    func testCatalogChoosesTheNewestStrictlyGreaterBuild() {
        let older = ResolvedRelease(record: record(tag: "old", assets: [dmgAsset()]), manifestData: manifest(short: "0.1.0", build: "40"))
        let lowerBuild = ResolvedRelease(record: record(tag: "low", assets: [dmgAsset()]), manifestData: manifest(short: "0.1.0", build: "9"))
        let newest = ResolvedRelease(record: record(tag: "new", assets: [dmgAsset()]), manifestData: manifest(short: "0.1.0", build: "42"))
        let result = ReleaseCatalog.evaluate(
            [older, lowerBuild, newest],
            channel: .preview,
            current: version("0.1.0", "41"),
            architecture: "arm64",
            system: SystemVersion(major: 15, minor: 0)
        )
        guard case .update(let found) = result else {
            return XCTFail("expected an update")
        }
        XCTAssertEqual(found.version, version("0.1.0", "42"))
        XCTAssertEqual(found.manifest.buildNumber, "42")
    }

    func testSameBinaryPromotedToReleaseIsAlreadyInstalled() {
        let promoted = ResolvedRelease(
            record: record(tag: "stable", assets: [dmgAsset()]),
            manifestData: manifest(short: "0.1.0", build: "42")
        )
        let result = ReleaseCatalog.evaluate(
            [promoted],
            channel: .release,
            current: version("0.1.0", "42"),
            architecture: "arm64",
            system: SystemVersion(major: 15, minor: 0)
        )
        guard case .upToDate = result else { return XCTFail("expected up to date") }
    }

    func testIncompatibleAndIncompleteRecordsAreDistinguished() {
        let wrongArch = ResolvedRelease(
            record: record(tag: "intel", assets: [dmgAsset()]),
            manifestData: manifest(short: "0.1.0", build: "99", arch: "x86_64")
        )
        let newOS = ResolvedRelease(
            record: record(tag: "future", assets: [dmgAsset()]),
            manifestData: manifest(short: "0.1.0", build: "99", minimum: "26.0")
        )
        let incompatible = ReleaseCatalog.evaluate(
            [wrongArch, newOS],
            channel: .preview,
            current: version("0.1.0", "41"),
            architecture: "arm64",
            system: SystemVersion(major: 15, minor: 0)
        )
        guard case .noCompatible = incompatible else { return XCTFail("expected no compatible release") }

        let missingManifest = ResolvedRelease(record: record(tag: "broken", assets: [dmgAsset()]), manifestData: nil)
        let incomplete = ReleaseCatalog.evaluate(
            [missingManifest],
            channel: .preview,
            current: version("0.1.0", "41"),
            architecture: "arm64",
            system: SystemVersion(major: 15, minor: 0)
        )
        guard case .incomplete = incomplete else { return XCTFail("expected incomplete release") }
    }

    func testEmptyChannelAndPaginationTrustRules() {
        let empty = ReleaseCatalog.evaluate(
            [],
            channel: .preview,
            current: version("0.1.0", "41"),
            architecture: "arm64",
            system: SystemVersion(major: 15, minor: 0)
        )
        guard case .noReleases = empty else { return XCTFail("expected no releases") }
        XCTAssertTrue(ReleaseEndpointPolicy.trustedNextPage(
            URL(string: "https://api.github.com/repos/Melon-tgj/MelonARC/releases?per_page=100&page=2")!
        ))
        XCTAssertFalse(ReleaseEndpointPolicy.trustedNextPage(
            URL(string: "https://example.org/repos/Melon-tgj/MelonARC/releases?per_page=100&page=2")!
        ))
        XCTAssertFalse(ReleaseEndpointPolicy.trustedNextPage(
            URL(string: "https://api.github.com/repos/Melon-tgj/MelonARC/releases?per_page=100&page=1")!
        ))
    }

    func testDigestComparisonAcceptsHexAndGitHubBase64() {
        let hex = String(repeating: "a", count: 64)
        XCTAssertTrue(ReleaseDigest.matches(hex: hex, assetDigest: nil))
        XCTAssertTrue(ReleaseDigest.matches(hex: hex, assetDigest: hex.uppercased()))
        let base64 = Data(repeating: 0xaa, count: 32).base64EncodedString()
        XCTAssertTrue(ReleaseDigest.matches(hex: hex, assetDigest: "sha256:\(base64)"))
        XCTAssertFalse(ReleaseDigest.matches(hex: hex, assetDigest: "sha256:AAAA"))
    }

    func testDownloadInitialURLMustBeTheRepositoryReleaseAsset() {
        XCTAssertTrue(ReleaseDownloadPolicy.isTrustedInitial(
            URL(string: "https://github.com/Melon-tgj/MelonARC/releases/download/v1/melonarc-test-macos-arm64.dmg")!,
            assetName: "melonarc-test-macos-arm64.dmg"
        ))
        XCTAssertFalse(ReleaseDownloadPolicy.isTrustedInitial(
            URL(string: "https://example.org/melonarc-test-macos-arm64.dmg")!,
            assetName: "melonarc-test-macos-arm64.dmg"
        ))
        XCTAssertTrue(ReleaseDownloadPolicy.allowsRedirect(
            from: URL(string: "https://github.com/Melon-tgj/MelonARC/releases/download/v1/a.dmg")!,
            to: URL(string: "https://objects.githubusercontent.com/a")!,
            count: 1
        ))
        XCTAssertFalse(ReleaseDownloadPolicy.allowsRedirect(
            from: URL(string: "https://github.com/Melon-tgj/MelonARC/releases/download/v1/a.dmg")!,
            to: URL(string: "https://example.org/a.dmg")!,
            count: 1
        ))
    }
}
