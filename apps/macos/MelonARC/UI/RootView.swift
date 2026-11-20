import SwiftUI

/// The window: a sidebar generated from the registry and the panel it selects.
///
/// The navigation has no idea how many panels exist, which is what makes a new one a
/// registration instead of an edit here.
struct RootView: View {
    @EnvironmentObject private var environment: AppEnvironment
    @Environment(\.openWindow) private var openWindow
    @State private var selection: String? = PanelRegistry.overview.id

    var body: some View {
        NavigationSplitView {
            List(selection: $selection) {
                ForEach(PanelRegistry.navigation()) { panel in
                    Label {
                        Text(Localization.text(panel.titleKey))
                    } icon: {
                        Image(systemName: panel.symbol)
                    }
                    .tag(panel.id)
                    .accessibilityIdentifier("panel.\(panel.id)")
                }
            }
            .listStyle(.sidebar)
            .navigationSplitViewColumnWidth(min: 176, ideal: 196, max: 260)
        } detail: {
            detail
                .accessibilityElement(children: .contain)
                .accessibilityIdentifier("panel.\(selection ?? "none").root")
        }
        .onAppear {
            // Handed over so the delegate and the menu bar can reopen a window that
            // SwiftUI has already released, without either of them owning the list.
            environment.attachWindowOpener { identifier in
                openWindow(id: identifier)
            }
            environment.startPanel(selection)
        }
        .onChange(of: selection) { _ in
            // The sidebar is generated from the registry. Only the selected
            // page's timer runs, so logs and connections stop refreshing the
            // moment the user leaves them.
            environment.stopAllPanels()
            environment.startPanel(selection)
        }
        .onDisappear {
            // Leaving the window stops every poll. The menu bar item and the
            // core are unaffected.
            environment.stopAllPanels()
        }
    }

    @ViewBuilder
    private var detail: some View {
        if environment.settings == nil || environment.launchFailure != nil {
            UnavailableView(
                titleKey: "startup.failed.title",
                message: environment.launchFailure ?? environment.settingsFailure ?? "",
                symbol: "exclamationmark.triangle"
            )
        } else {
            switch selection {
            case PanelRegistry.overview.id:
                OverviewView(model: environment.overview, environment: environment)
            case PanelRegistry.policies.id:
                PoliciesView(model: environment.policies)
            case PanelRegistry.subscriptions.id:
                SubscriptionsView(model: environment.subscriptions)
            case PanelRegistry.rules.id:
                RulesView(model: environment.rules)
            case PanelRegistry.connections.id:
                ConnectionsView(model: environment.connections)
            case PanelRegistry.logs.id:
                LogsView(model: environment.logs)
            default:
                PanelPlaceholderView(panel: PanelRegistry.overview)
            }
        }
    }
}

/// A full-window message for a state that has nothing to draw.
struct UnavailableView: View {
    let titleKey: String
    let message: String
    let symbol: String

    var body: some View {
        VStack(spacing: 10) {
            Image(systemName: symbol)
                .font(.system(size: 32))
                .foregroundStyle(.secondary)
            Text(Localization.text(titleKey))
                .font(.title3.weight(.semibold))
            Text(message)
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .textSelection(.enabled)
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
