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
                }
            }
            .listStyle(.sidebar)
            .navigationSplitViewColumnWidth(min: 176, ideal: 196, max: 260)
        } detail: {
            detail
        }
        .onAppear {
            // Handed over so the delegate and the menu bar can reopen a window that
            // SwiftUI has already released, without either of them owning the list.
            environment.attachWindowOpener { identifier in
                openWindow(id: identifier)
            }
            environment.overview.start()
        }
        .onDisappear {
            // Leaving the window stops the two-second poll. The menu bar item and
            // the core are unaffected.
            environment.overview.stop()
        }
    }

    @ViewBuilder
    private var detail: some View {
        if environment.settings == nil {
            UnavailableView(
                titleKey: "startup.failed.title",
                message: environment.settingsFailure ?? "",
                symbol: "exclamationmark.triangle"
            )
        } else if selection == PanelRegistry.overview.id {
            OverviewView(model: environment.overview, environment: environment)
        } else if let panel = PanelRegistry.panel(with: selection ?? "") {
            PanelPlaceholderView(panel: panel)
        } else {
            PanelPlaceholderView(panel: PanelRegistry.overview)
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
