import SwiftUI

struct RootView: View {
    @EnvironmentObject private var environment: AppEnvironment
    @Environment(\.openWindow) private var openWindow
    @Environment(\.sidebarRowSize) private var rowSize
    @State private var selection: String? = PanelRegistry.overview.id
    @State private var path = NavigationPath()

    private let panels = PanelRegistry.navigation()

    var body: some View {
        NavigationSplitView {
            GeometryReader { geometry in
                ScrollView {
                    ScrollViewReader { proxy in
                        VStack(spacing: sidebarLayout(in: geometry).gap) {
                            ForEach(panels) { panel in
                                SidebarPanelButton(
                                    identifier: "panel.\(panel.id)",
                                    titleKey: panel.titleKey,
                                    symbol: panel.symbol,
                                    rowHeight: sidebarLayout(in: geometry).row,
                                    selected: panel.id == selection
                                ) {
                                    selection = panel.id
                                }
                                .id(panel.id)
                            }
                        }
                        .padding(LayoutMetrics.Sidebar.inset)
                        .frame(maxWidth: .infinity, minHeight: geometry.size.height, alignment: .center)
                        .onChange(of: selection) { newValue in
                            if let newValue { proxy.scrollTo(newValue) }
                        }
                    }
                }
                .scrollContentBackground(.hidden)
            }
            .navigationSplitViewColumnWidth(
                min: LayoutMetrics.Sidebar.minWidth,
                ideal: LayoutMetrics.Sidebar.idealWidth,
                max: LayoutMetrics.Sidebar.maxWidth
            )
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
        .modifier(UpdateAlertModifier(model: environment.update))
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

    private func sidebarLayout(in geometry: GeometryProxy) -> (row: CGFloat, gap: CGFloat) {
        let count = panels.count
        guard count > 0 else { return (0, 0) }
        let lastGap = count - 1
        let height = geometry.size.height - geometry.safeAreaInsets.top - geometry.safeAreaInsets.bottom
        let limits = LayoutMetrics.Sidebar.limits(for: rowSize)
        let candidate = (height - 2 * LayoutMetrics.Sidebar.inset - LayoutMetrics.Sidebar.minimumGap * CGFloat(lastGap))
            / CGFloat(count)
        let row = min(max(candidate, limits.minimum), limits.maximum)
        let gap = lastGap > 0
            ? min(
                max(
                    (height - 2 * LayoutMetrics.Sidebar.inset - CGFloat(count) * row) / CGFloat(lastGap),
                    LayoutMetrics.Sidebar.minimumGap
                ),
                LayoutMetrics.Sidebar.maximumGap
            )
            : 0
        return (row, gap)
    }

    private func moveSelection(_ direction: MoveCommandDirection) {
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
