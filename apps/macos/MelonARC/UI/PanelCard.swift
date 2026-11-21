import SwiftUI

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
            VStack(alignment: .leading, spacing: 10) {
                content
                if !(actions is EmptyView) {
                    Divider()
                    HStack(spacing: 8) {
                        Spacer(minLength: 0)
                        actions
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.top, 2)
        } label: {
            HStack(spacing: 8) {
                if let symbol {
                    Image(systemName: symbol)
                }
                Text(Localization.text(titleKey))
                    .font(.headline)
            }
        }
        .padding(16)
    }
}
