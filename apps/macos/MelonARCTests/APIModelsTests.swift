import XCTest

final class APIModelsTests: XCTestCase {
    private func decoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return decoder
    }

    func testConfigurationDecodesAllFiveProxyStates() throws {
        let raw = """
        {"log_level":"info","system_proxy":true,
         "system_proxy_state":{"state":"recovery_failed","configured":true,
         "pending_restart":false,"applied":false,"recovery_failed":true,
         "detail":"a takeover record was kept"},"pending_restart":[]}
        """
        let view = try decoder().decode(ConfigurationView.self, from: Data(raw.utf8))
        XCTAssertEqual(view.systemProxyState.state, .recoveryFailed)
        XCTAssertTrue(view.systemProxyState.configured)
        XCTAssertTrue(view.systemProxyState.recoveryFailed)
        XCTAssertEqual(view.systemProxyState.detail, "a takeover record was kept")
        XCTAssertEqual(view.systemProxyState.state.localizationKey, "system_proxy.state.recovery_failed")
    }

    func testAnOlderCoreWithoutTheFourStateViewDecodesAsOff() throws {
        let raw = #"{"log_level":"info","system_proxy":false,"pending_restart":[]}"#
        let view = try decoder().decode(ConfigurationView.self, from: Data(raw.utf8))
        XCTAssertEqual(view.systemProxyState.state, .off)
        XCTAssertFalse(view.systemProxyState.applied)
    }

    func testAnUnknownStateIsNotReportedAsOff() throws {
        let raw = #"{"state":"new_state_from_a_future_core"}"#
        let value = try decoder().decode(SystemProxyStateView.self, from: Data(raw.utf8))
        XCTAssertEqual(value.state, .unknown)
        XCTAssertEqual(value.state.localizationKey, "system_proxy.state.unknown")
    }

    func testCoreErrorCodesStayStableForLocalization() {
        XCTAssertEqual(APIError.api("unknown_subscription", 404, nil).code, "unknown_subscription")
        XCTAssertEqual(APIError.status(500, nil).code, "http_status")
        XCTAssertEqual(APIError.unauthorized.code, "unauthorized")
        XCTAssertEqual(APIError.api("bad_request", 400, nil).code, "bad_request")
    }

    func testNamesInRefreshPathsAreEscapedAsOneSegment() {
        XCTAssertEqual(APIEndpoint.escapedSegment("a/b c"), "a%2Fb%20c")
        XCTAssertEqual(
            APIEndpoint.subscriptionRefresh("a/b"),
            "/v1/subscriptions/a%2Fb/refresh"
        )
    }

    func testConnectionPagesDecodeBothEmptyAndPopulatedBodies() throws {
        let empty = try decoder().decode(ConnectionListView.self, from: Data(#"{"count":0,"connections":[]}"#.utf8))
        XCTAssertEqual(empty.count, 0)
        XCTAssertTrue(empty.connections.isEmpty)

        let raw = """
        {"count":1,"connections":[{"time":"2026-11-21T10:00:00Z","protocol":"HTTP",
        "target":"example.org:443","network":"tcp","rule":"final","policy":"direct",
        "outbound":"direct","up":12,"down":34,"duration_ms":7.5}]}
        """
        let page = try decoder().decode(ConnectionListView.self, from: Data(raw.utf8))
        XCTAssertEqual(page.connections.count, 1)
        XCTAssertEqual(page.connections.first?.protocolName, "HTTP")
        XCTAssertEqual(page.connections.first?.durationMs, 7.5)
    }

    func testSubscriptionCreateRequestUsesTheCoreFieldName() throws {
        let request = SubscriptionCreateRequest(name: "demo", url: "https://example.org/feed", intervalSeconds: 21600)
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        let object = try JSONSerialization.jsonObject(with: encoder.encode(request)) as? [String: Any]
        XCTAssertEqual(object?["name"] as? String, "demo")
        XCTAssertEqual(object?["url"] as? String, "https://example.org/feed")
        XCTAssertEqual(object?["interval_seconds"] as? Int, 21600)
    }
}
