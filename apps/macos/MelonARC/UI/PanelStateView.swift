import SwiftUI

struct PanelStateView<Content: View, Actions: View>: View {
    let phase: PanelLoadPhase
    let titleKey: String
    let descriptionKey: String
    let symbol: String
    let retry: () -> Void
    let content: Content
    let actions: Actions

    init(
        phase: PanelLoadPhase,
        titleKey: String,
        descriptionKey: String,
        symbol: String,
        retry: @escaping () -> Void,
        @ViewBuilder content: () -> Content,
        @ViewBuilder actions: () -> Actions
    ) {
        self.phase = phase
        self.titleKey = titleKey
        self.descriptionKey = descriptionKey
        self.symbol = symbol
        self.retry = retry
        self.content = content()
        self.actions = actions()
    }

    var body: some View {
        Group {
            switch phase {
            case .idle, .loading:
                ProgressView(Localization.text("panel.state.loading"))
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            case .loaded:
                content
            case .empty:
                unavailable(
                    title: Localization.text(titleKey),
                    description: Localization.text(descriptionKey)
                )
            case .failed(let error):
                VStack(spacing: 0) {
                    Image(systemName: "exclamationmark.triangle")
                        .font(.system(size: 30))
                        .foregroundStyle(.orange)
                        .padding(.bottom, LayoutMetrics.formGap)
                    VStack(spacing: LayoutMetrics.detailGap) {
                        Text(Localization.format("panel.error", Localization.text("error.\(error.code)")))
                            .font(.headline)
                            .multilineTextAlignment(.center)
                        Text(Localization.text("panel.state.retry_hint"))
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    }
                    HStack(spacing: LayoutMetrics.actionGap) {
                        actions
                        Button(Localization.text("panel.state.retry"), action: retry)
                    }
                    .padding(.top, LayoutMetrics.headerGap)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    @ViewBuilder
    private func unavailable(title: String, description: String) -> some View {
        if #available(macOS 14.0, *) {
            ContentUnavailableView {
                Label(title, systemImage: symbol)
            } description: {
                Text(description)
            } actions: {
                actions
                Button(Localization.text("panel.state.retry"), action: retry)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else {
            VStack(spacing: 0) {
                Image(systemName: symbol)
                    .font(.system(size: 30))
                    .foregroundStyle(.secondary)
                    .padding(.bottom, LayoutMetrics.formGap)
                Text(title)
                    .font(.title3.weight(.semibold))
                    .padding(.bottom, LayoutMetrics.detailGap)
                Text(description)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 360)
                HStack(spacing: LayoutMetrics.actionGap) {
                    actions
                    Button(Localization.text("panel.state.retry"), action: retry)
                }
                .padding(.top, LayoutMetrics.headerGap)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }
}
