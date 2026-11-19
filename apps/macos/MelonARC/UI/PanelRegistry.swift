import Foundation

/// One navigation entry, and the whole of the sidebar's knowledge.
///
/// The list is generated from `all` and nothing else: a new screen is one entry here
/// plus the view it names. Nothing counts the panels, so a build with more of them
/// needs no layout change — which is the extension point this milestone leaves for
/// the panels that follow.
struct PanelDescriptor: Identifiable, Equatable {
    /// Stable identifier: the selection value and the persistence key.
    let id: String
    /// Localization key of the navigation label.
    let titleKey: String
    /// SF Symbol drawn next to the label.
    let symbol: String
    /// Ascending order in the sidebar.
    let order: Int
    /// What this milestone can show for the panel.
    let availability: Availability

    enum Availability: Equatable {
        /// Implemented in this build.
        case ready
        /// Registered now so the navigation is final, with a placeholder body.
        case pendingMilestone
    }
}

enum PanelRegistry {
    static let overview = PanelDescriptor(
        id: "overview",
        titleKey: "panel.overview.title",
        symbol: "gauge",
        order: 10,
        availability: .ready
    )

    static let policies = PanelDescriptor(
        id: "policies",
        titleKey: "panel.policies.title",
        symbol: "arrow.triangle.branch",
        order: 20,
        availability: .ready
    )

    static let subscriptions = PanelDescriptor(
        id: "subscriptions",
        titleKey: "panel.subscriptions.title",
        symbol: "arrow.triangle.2.circlepath",
        order: 30,
        availability: .ready
    )

    static let connections = PanelDescriptor(
        id: "connections",
        titleKey: "panel.connections.title",
        symbol: "network",
        order: 40,
        availability: .ready
    )

    static let rules = PanelDescriptor(
        id: "rules",
        titleKey: "panel.rules.title",
        symbol: "list.bullet",
        order: 50,
        availability: .ready
    )

    static let logs = PanelDescriptor(
        id: "logs",
        titleKey: "panel.logs.title",
        symbol: "text.alignleft",
        order: 60,
        availability: .ready
    )

    /// Settings is a scene of its own — the app menu's "Settings…" and ⌘, open it —
    /// so it is not part of the sidebar, but it is registered here anyway: the
    /// settings screens are a panel like any other once they grow.
    static let settings = PanelDescriptor(
        id: "settings",
        titleKey: "panel.settings.title",
        symbol: "gearshape",
        order: 70,
        availability: .ready
    )

    static let all: [PanelDescriptor] = [
        overview, policies, subscriptions, connections, rules, logs, settings,
    ]

    /// The sidebar order.
    static func sorted() -> [PanelDescriptor] {
        all.sorted { $0.order < $1.order }
    }

    /// The panels the sidebar shows, in order.
    static func navigation() -> [PanelDescriptor] {
        sorted().filter { $0.id != settings.id }
    }

    static func panel(with id: String) -> PanelDescriptor? {
        all.first { $0.id == id }
    }
}
