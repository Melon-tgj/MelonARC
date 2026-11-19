import XCTest

final class PanelRegistryTests: XCTestCase {
    func testEveryPanelHasAUniqueIdentifierAndAKey() {
        var identifiers = Set<String>()
        var keys = Set<String>()
        for panel in PanelRegistry.all {
            XCTAssertFalse(panel.id.isEmpty)
            XCTAssertFalse(panel.titleKey.isEmpty)
            XCTAssertTrue(panel.titleKey.hasPrefix("panel."), panel.titleKey)
            XCTAssertTrue(panel.titleKey.hasSuffix(".title"), panel.titleKey)
            XCTAssertTrue(identifiers.insert(panel.id).inserted, "\(panel.id) is registered twice")
            XCTAssertTrue(keys.insert(panel.titleKey).inserted, "\(panel.titleKey) is used twice")
        }
    }

    /// The sidebar is the registry, minus the screens that are opened from the app
    /// menu. Six business panels are what the product has.
    func testTheSidebarHasTheSixBusinessPanelsInOrder() {
        let navigation = PanelRegistry.navigation()
        XCTAssertEqual(navigation.map(\.id), [
            "overview", "policies", "subscriptions", "connections", "rules", "logs",
        ])
        let orders = navigation.map(\.order)
        XCTAssertEqual(orders, orders.sorted(), "the sidebar order must be the declared order")
    }

    func testSettingsIsRegisteredButNotInTheSidebar() {
        XCTAssertNotNil(PanelRegistry.panel(with: "settings"))
        XCTAssertFalse(PanelRegistry.navigation().contains { $0.id == "settings" })
    }

    func testThisMilestoneFillsTheOverviewOnly() {
        let ready = PanelRegistry.all.filter { $0.availability == .ready }.map(\.id)
        XCTAssertEqual(ready, ["overview"])
    }

    func testAnUnknownIdentifierResolvesToNothing() {
        XCTAssertNil(PanelRegistry.panel(with: "no-such-panel"))
    }
}
