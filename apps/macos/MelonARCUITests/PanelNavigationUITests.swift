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

    func testEveryBusinessPanelCanBeOpened() {
        let app = XCUIApplication()
        app.launch()
        defer { app.terminate() }

        for panel in panels {
            let item = app.cells["panel.\(panel)"]
            XCTAssertTrue(item.waitForExistence(timeout: 10), "no sidebar item for \(panel)")
            item.click()
            let root = app.otherElements["panel.\(panel).root"]
            XCTAssertTrue(root.waitForExistence(timeout: 10), "no root view for \(panel)")
        }
    }
}
