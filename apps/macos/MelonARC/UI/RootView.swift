import SwiftUI

struct RootView: View {
    @EnvironmentObject private var environment: AppEnvironment
    @Environment(\.openWindow) private var openWindow
    @State private var selection: String? = PanelRegistry.overview.id
    @State private var path = NavigationPath()

    var body: some View {
        NavigationSplitView {
            GeometryReader { geometry in
                ScrollView {
                    VStack(spacing: 8) {
                        ForEach(PanelRegistry.navigation()) { panel in
                            SidebarPanelButton(
                                identifier: "panel.\(panel.id)",
                                titleKey: panel.titleKey,
                                symbol: panel.symbol,
                                rowHeight: rowHeight(in: geometry.size.height),
                                selected: panel.id == selection
                            ) {
                                selection = panel.id
                            }
                        }
                    }
                    .padding(12)
                    .frame(maxWidth: .infinity, minHeight: geometry.size.height, alignment: .top)
                }
                .scrollContentBackground(.hidden)
            }
            .navigationSplitViewColumnWidth(min: 208, ideal: 236, max: 304)
            .onMoveCommand { direction in
                moveSelection(direction)
            }
        } detail: {
            NavigationStack(path: $path) {
                panelContent
                    .navigationDestination(for: PanelDetailRoute.self) { route in
                        PanelDetailView(route: route, environment: environment)
                    }
            }
            .accessibilityElement(children: .contain)
            .accessibilityIdentifier("panel.\(selection ?? "none").root")
        }
        .onAppear {
            environment.attachWindowOpener { identifier in
                openWindow(id: identifier)
            }
            environment.startPanel(selection)
        }
        .onChange(of: selection) { _ in
            path = NavigationPath()
            environment.stopAllPanels()
            environment.startPanel(selection)
        }
        .onDisappear {
            environment.stopAllPanels()
        }
    }

    @ViewBuilder
    private var panelContent: some View {
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
                PoliciesView(model: environment.policies, selection: $selection, path: $path)
            case PanelRegistry.subscriptions.id:
                SubscriptionsView(model: environment.subscriptions, path: $path)
            case PanelRegistry.rules.id:
                RulesView(model: environment.rules)
            case PanelRegistry.connections.id:
                ConnectionsView(model: environment.connections, path: $path)
            case PanelRegistry.logs.id:
                LogsView(model: environment.logs)
            default:
                PanelPlaceholderView(panel: PanelRegistry.overview)
            }
        }
    }

    private func rowHeight(in totalHeight: CGFloat) -> CGFloat {
        let count = PanelRegistry.navigation().count
        guard count > 0 else { return 56 }
        let spacing: CGFloat = 8 * CGFloat(count - 1)
        let available = (totalHeight - 24 - spacing) / CGFloat(count)
        return max(56, available)
    }

    private func moveSelection(_ direction: MoveCommandDirection) {
        let panels = PanelRegistry.navigation()
        guard !panels.isEmpty else { return }
        let current = panels.firstIndex { $0.id == selection } ?? 0
        let target: Int
        switch direction {
        case .up:
            target = max(0, current - 1)
        case .down:
            target = min(panels.count - 1, current + 1)
        case .left, .right:
            return
        @unknown default:
            return
        }
        selection = panels[target].id
    }
}

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
