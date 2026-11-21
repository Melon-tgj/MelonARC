import XCTest

final class PanelStateTests: XCTestCase {
    func testLoadPhaseDistinguishesEmptyFromLoadedAndFailure() {
        let error = APIError.api("unreachable", 503, nil)
        XCTAssertNotEqual(PanelLoadPhase.empty, .loaded)
        XCTAssertNotEqual(PanelLoadPhase.loaded, .failed(error))
        XCTAssertEqual(PanelLoadPhase.failed(error), .failed(error))
    }

    func testSnapshotsReportWhetherTheyCarryRows() {
        XCTAssertFalse(PanelLoadSnapshot.subscriptions([]).hasContent)
        XCTAssertTrue(PanelLoadSnapshot.subscriptions([
            SubscriptionView(
                name: "demo",
                nodes: 1,
                skipped: 0,
                fetchedAt: nil,
                nextAt: nil,
                attempts: 1,
                error: nil
            )
        ]).hasContent)
        XCTAssertFalse(PanelLoadSnapshot.rules([], total: 4).hasContent)
        XCTAssertTrue(PanelLoadSnapshot.rules([RuleView(
            index: 0,
            type: "final",
            payload: nil,
            target: "DIRECT",
            source: nil,
            line: nil,
            noResolve: nil
        )], total: 1).hasContent)
    }

    func testSubscriptionCreateRequestOmitsTheDefaultInterval() throws {
        let request = SubscriptionCreateRequest(name: "demo", url: "https://example.org/feed", intervalSeconds: nil)
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        let object = try JSONSerialization.jsonObject(with: encoder.encode(request)) as? [String: Any]
        XCTAssertNil(object?["interval_seconds"])
    }
}
