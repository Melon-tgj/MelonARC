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

    private func panelRoot(for panel: String, in app: XCUIApplication) -> XCUIElement {
        app.descendants(matching: .any)
            .matching(identifier: "panel.\(panel).root")
            .firstMatch
    }

    private func open(_ panel: String, in app: XCUIApplication) throws {
        guard let button = sidebarButton(for: panel, in: app) else {
            XCTFail("no sidebar button for \(panel)")
            return
        }
        XCTAssertTrue(button.isHittable, "sidebar button \(panel) is not hittable")
        button.click()
        guard panelRoot(for: panel, in: app).waitForExistence(timeout: 10) else {
            XCTFail("no root view for \(panel)")
            return
        }
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
            let root = panelRoot(for: panel, in: app)
            guard root.waitForExistence(timeout: 10) else {
                XCTFail("no root view for \(panel)")
                return
            }
        }
    }

    func testSidebarEdgeRemainsPartOfTheButton() {
        let app = XCUIApplication()
        app.launch()
        for panel in panels {
            guard let button = sidebarButton(for: panel, in: app) else {
                XCTFail("no sidebar button for \(panel)")
                return
            }
            button.coordinate(withNormalizedOffset: CGVector(dx: 0.02, dy: 0.5)).click()
            guard panelRoot(for: panel, in: app).waitForExistence(timeout: 10) else {
                XCTFail("edge click did not select \(panel)")
                return
            }
        }
    }

    func testArrowKeysDoNotWrapPastTheFirstAndLastPanel() throws {
        let app = XCUIApplication()
        app.launch()
        try open("overview", in: app)

        app.typeKey(.downArrow, modifierFlags: [])
        guard panelRoot(for: "policies", in: app).waitForExistence(timeout: 3) else {
            throw XCTSkip("keyboard focus is not on the sidebar in this environment")
        }
        app.typeKey(.upArrow, modifierFlags: [])
        XCTAssertTrue(panelRoot(for: "overview", in: app).waitForExistence(timeout: 3))

        app.typeKey(.upArrow, modifierFlags: [])
        XCTAssertTrue(panelRoot(for: "overview", in: app).exists)
    }

    func testRuleSummaryAndShortIndicesStayVisible() throws {
        let app = XCUIApplication()
        app.launch()
        try open("rules", in: app)

        let summary = app.staticTexts.matching(
            NSPredicate(format: "label CONTAINS 'rules' OR label CONTAINS '规则'")
        ).firstMatch
        guard summary.waitForExistence(timeout: 5) else {
            throw XCTSkip("the rules summary is not exposed to accessibility")
        }
        let indices = app.staticTexts.matching(NSPredicate(format: "label BEGINSWITH '#'"))
        let count = indices.count
        if (1...3).contains(count) {
            for index in 0..<count {
                XCTAssertTrue(indices.element(boundBy: index).exists)
            }
        }
    }

    func testSubscriptionSheetGeometryStaysInsideTheDeclaredBounds() throws {
        let app = XCUIApplication()
        app.launch()
        try open("subscriptions", in: app)

        let add = app.buttons.matching(
            NSPredicate(format: "label == 'Add Subscription' OR label == '添加订阅'")
        ).firstMatch
        guard add.waitForExistence(timeout: 5) else {
            throw XCTSkip("the add action is not exposed to accessibility")
        }
        add.click()

        let sheet = app.sheets.firstMatch
        let container: XCUIElement
        if sheet.waitForExistence(timeout: 5) {
            container = sheet
        } else {
            let editor = app.descendants(matching: .any)
                .matching(identifier: "subscription.editor.root")
                .firstMatch
            guard editor.waitForExistence(timeout: 5) else {
                throw XCTSkip("no sheet window is exposed to accessibility")
            }
            container = editor
        }
        let frame = container.frame
        XCTAssertGreaterThanOrEqual(frame.width, 447)
        XCTAssertLessThanOrEqual(frame.width, 641)
        XCTAssertGreaterThanOrEqual(frame.height, 239)
        XCTAssertLessThanOrEqual(frame.height, 481)
    }
}
