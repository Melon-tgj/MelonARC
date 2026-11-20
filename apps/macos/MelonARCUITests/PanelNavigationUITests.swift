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

    private func clickSidebarItem(_ item: XCUIElement, for panel: String, in app: XCUIApplication) {
        let identifier = "panel.\(panel)"
        let window = app.windows.containing(.any, identifier: identifier).firstMatch
        let windowFrame = window.exists ? String(describing: window.frame) : "missing"
        let rowHittable = item.isHittable
        print("[sidebar] panel=\(panel) foreground=\(app.state == .runningForeground) window=\(windowFrame) row=\(item.frame) selected=\(item.isSelected) rowHittable=\(rowHittable)")

        if !rowHittable {
            let label = item.descendants(matching: .any).matching(identifier: identifier).firstMatch
            for content in [label, item.staticTexts.firstMatch] where content.exists {
                let hittable = content.isHittable
                print("[sidebar] panel=\(panel) child=\(content.elementType) frame=\(content.frame) childHittable=\(hittable)")
                if hittable {
                    content.click()
                    return
                }
            }
        }
        // An offscreen row can still be scrolled into view by click().
        item.click()
    }

    func testEveryBusinessPanelCanBeOpened() {
        let app = XCUIApplication()
        addTeardownBlock {
            if (self.testRun?.totalFailureCount ?? 0) > 0 {
                let screen = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
                screen.name = "Sidebar navigation failure"
                self.add(screen)
                print("[sidebar] failure appState=\(app.state.rawValue)")
                if app.state != .notRunning { print(app.debugDescription) }
            }
            app.terminate()
        }
        app.launch()

        // Reopen overview from logs so it also requires a selection change.
        for panel in panels + ["overview"] {
            guard let item = sidebarItem(for: panel, in: app) else {
                XCTFail("no sidebar item for \(panel)")
                return
            }
            clickSidebarItem(item, for: panel, in: app)
            let root = app.descendants(matching: .any)
                .matching(identifier: "panel.\(panel).root")
                .firstMatch
            guard root.waitForExistence(timeout: 10) else {
                XCTFail("no root view for \(panel)")
                return
            }
        }
    }
}
