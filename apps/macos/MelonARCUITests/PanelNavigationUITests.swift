import XCTest

/// Navigation smoke tests for the generated sidebar.
///
/// The identifiers are on the view itself, so these tests do not depend on the
/// current language or on a translation being loaded. They check the property
/// the registry promises: every registered business panel can be reached from
/// the window and gets its own root view.
final class PanelNavigationUITests: XCTestCase {
    private let panels = ["overview", "policies", "subscriptions", "connections", "rules", "logs"]

    override func setUp() {
        continueAfterFailure = false
    }

    private func sidebarItem(for panel: String, in app: XCUIApplication) -> XCUIElement? {
        let identifier = "panel.\(panel)"
        let identified = app.descendants(matching: .any)
            .matching(identifier: identifier)
            .firstMatch
        guard identified.waitForExistence(timeout: 10) else { return nil }

        let queries = [
            app.descendants(matching: .outlineRow).matching(identifier: identifier),
            app.descendants(matching: .outlineRow).containing(.any, identifier: identifier),
            app.descendants(matching: .cell).matching(identifier: identifier),
            app.descendants(matching: .cell).containing(.any, identifier: identifier),
        ]
        for query in queries {
            let candidate = query.firstMatch
            if candidate.exists { return candidate }
        }

        let frame = identified.frame
        let rows = app.descendants(matching: .outlineRow).allElementsBoundByIndex
            + app.descendants(matching: .cell).allElementsBoundByIndex
        return rows.first { $0.frame.contains(frame) }
    }

    func testEveryBusinessPanelCanBeOpened() {
        let app = XCUIApplication()
        app.launch()
        defer { app.terminate() }

        for panel in panels {
            guard let item = sidebarItem(for: panel, in: app) else {
                XCTFail("no sidebar item for \(panel)")
                return
            }
            item.click()
            let root = app.otherElements["panel.\(panel).root"]
            XCTAssertTrue(root.waitForExistence(timeout: 10), "no root view for \(panel)")
        }
    }
}
