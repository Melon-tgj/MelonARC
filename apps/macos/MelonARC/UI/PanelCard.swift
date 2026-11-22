import SwiftUI

private struct PanelCardBoxStyle: GroupBoxStyle {
    func makeBody(configuration: Configuration) -> some View {
        VStack(alignment: .leading, spacing: LayoutMetrics.fieldGap) {
            configuration.label
                .font(.headline)
            configuration.content
        }
        .padding(LayoutMetrics.cardInset)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .fill(Color(nsColor: .controlBackgroundColor))
        )
    }
}

struct PanelCard<Content: View, Actions: View>: View {
    let titleKey: String
    let symbol: String?
    let content: Content
    let actions: Actions

    init(
        titleKey: String,
        symbol: String? = nil,
        @ViewBuilder actions: () -> Actions,
        @ViewBuilder content: () -> Content
    ) {
        self.titleKey = titleKey
        self.symbol = symbol
        self.actions = actions()
        self.content = content()
    }

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: LayoutMetrics.fieldGap) {
                content
                if !(actions is EmptyView) {
                    Divider()
                    HStack(spacing: LayoutMetrics.actionGap) {
                        Spacer(minLength: 0)
                        actions
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        } label: {
            HStack(spacing: LayoutMetrics.actionGap) {
                if let symbol {
                    Image(systemName: symbol)
                }
                Text(Localization.text(titleKey))
                    .font(.headline)
            }
        }
        .groupBoxStyle(PanelCardBoxStyle())
    }
}
