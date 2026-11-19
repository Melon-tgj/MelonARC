import SwiftUI

/// What a registered panel with no content yet shows.
///
/// The entry is in the navigation from the first build so the sidebar does not move
/// between milestones, and the body says so in one sentence rather than pretending
/// the panel is empty: an empty table reads as "nothing is happening", which is a
/// different claim from "this is not built yet".
struct PanelPlaceholderView: View {
    let panel: PanelDescriptor

    var body: some View {
        VStack(spacing: 10) {
            Image(systemName: panel.symbol)
                .font(.system(size: 34))
                .foregroundStyle(.secondary)
            Text(Localization.text(panel.titleKey))
                .font(.title3.weight(.semibold))
            Text("panel.pending.body")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 420)
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .navigationTitle(Text(Localization.text(panel.titleKey)))
    }
}
