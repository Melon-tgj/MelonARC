import Foundation
import XCTest

final class LocalizationTests: XCTestCase {
    private func catalog() throws -> [String: Any] {
        let source = URL(fileURLWithPath: #filePath)
        let root = source.deletingLastPathComponent().deletingLastPathComponent()
        let path = root.appendingPathComponent("MelonARC/Resources/Localizable.xcstrings")
        let data = try Data(contentsOf: path)
        let parsed = try JSONSerialization.jsonObject(with: data)
        return try XCTUnwrap(parsed as? [String: Any])
    }

    private func value(_ key: String, language: String, in strings: [String: Any]) throws -> String {
        let entry = try XCTUnwrap(strings[key] as? [String: Any], "missing key \(key)")
        let localizations = try XCTUnwrap(entry["localizations"] as? [String: Any], "no localizations for \(key)")
        let localization = try XCTUnwrap(localizations[language] as? [String: Any], "no \(language) for \(key)")
        let unit = try XCTUnwrap(localization["stringUnit"] as? [String: Any], "no string unit for \(key)")
        return try XCTUnwrap(unit["value"] as? String, "no value for \(key)")
    }

    func testTheCatalogHasBothLanguagesForEveryNewStateAndCode() throws {
        let root = try catalog()
        let strings = try XCTUnwrap(root["strings"] as? [String: Any])
        let keys = [
            "system_proxy.state.off", "system_proxy.state.configured",
            "system_proxy.state.pending_restart", "system_proxy.state.applied",
            "system_proxy.state.recovery_failed", "system_proxy.state.unknown",
            "error.unknown_subscription", "error.bad_request", "error.conflict",
            "error.unprocessable_entity", "error.internal_error",
            "error.data_directory_changed", "common.not_implemented",
            "settings.system_proxy.enabled", "settings.tun.note",
            "subscriptions.action.add", "subscriptions.empty.title",
            "connections.empty.title", "panel.state.loading", "panel.state.retry",
            "overview.proxy.unknown", "overview.state.unknown",
            "settings.section.network", "settings.section.diagnostics",
            "settings.section.about", "error.subscription_refresh_failed",
        ]
        for key in keys {
            XCTAssertFalse(try value(key, language: "en", in: strings).isEmpty, key)
            XCTAssertFalse(try value(key, language: "zh-Hans", in: strings).isEmpty, key)
        }
        XCTAssertEqual(try value("common.not_implemented", language: "zh-Hans", in: strings), "尚未实现")
    }

    func testPlaceholdersAgreeBetweenLanguages() throws {
        let root = try catalog()
        let strings = try XCTUnwrap(root["strings"] as? [String: Any])
        for key in ["startup.first_config_written", "policies.health", "connections.bytes", "settings.error"] {
            let en = try value(key, language: "en", in: strings)
            let zh = try value(key, language: "zh-Hans", in: strings)
            XCTAssertEqual(en.components(separatedBy: "%@").count, zh.components(separatedBy: "%@").count, key)
        }
    }
}
