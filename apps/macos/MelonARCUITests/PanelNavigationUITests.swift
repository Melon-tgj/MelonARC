import XCTest

final class PanelNavigationUITests: XCTestCase {
    private let panels = ["overview", "policies", "subscriptions", "connections", "rules", "logs"]

    override func setUp() {
        continueAfterFailure = false
    }

    private func sidebarButton(for panel: String, in app: XCUIApplication) -> XCUIElement? {
        let button = app.buttons["panel.\(panel)"]
        return button.waitForExistence(timeout: 10) ? button : nil
    }

    func testEveryBusinessPanelCanBeOpened() {
        let app = XCUIApplication()
        addTeardownBlock {
            if (self.testRun?.totalFailureCount ?? 0) > 0 {
                let screen = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
                screen.name = "Sidebar navigation failure"
                self.add(screen)
                if app.state != .notRunning { print(app.debugDescription) }
            }
            app.terminate()
        }
        app.launch()

        for panel in panels + ["overview"] {
            guard let button = sidebarButton(for: panel, in: app) else {
                XCTFail("no sidebar button for \(panel)")
                return
            }
            XCTAssertTrue(button.isHittable, "sidebar button \(panel) is not hittable")
            button.click()
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
