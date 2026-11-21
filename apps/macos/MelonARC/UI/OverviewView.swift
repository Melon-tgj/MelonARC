import SwiftUI

struct InfoRow: View {
    let titleKey: String
    let value: String
    var labelWidth: CGFloat = 132

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            Text(Localization.text(titleKey))
                .foregroundStyle(.secondary)
                .frame(width: labelWidth, alignment: .leading)
            Text(value)
                .textSelection(.enabled)
            Spacer(minLength: 0)
        }
    }
}

struct OverviewView: View {
    @ObservedObject var model: OverviewModel
    @ObservedObject var environment: AppEnvironment

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                header
                ViewThatFits(in: .horizontal) {
                    HStack(alignment: .top, spacing: 14) {
                        runtimeCard
                        takeoverCard
                        routingCard
                    }
                    VStack(alignment: .leading, spacing: 14) {
                        runtimeCard
                        takeoverCard
                        routingCard
                    }
                }
                if statusFailure != nil || configurationFailure != nil {
                    problemCard
                }
                footer
            }
            .padding(22)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .navigationTitle(Text("panel.overview.title"))
    }

    private var header: some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 8) {
                    Circle()
                        .fill(stateColor)
                        .frame(width: 9, height: 9)
                    Text(Localization.text(environment.snapshot.state.localizationKey))
                        .font(.title2.weight(.semibold))
                }
                Text(subtitle)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            NavigationLink(Localization.text("overview.action.details"), value: PanelDetailRoute.overview)
            .buttonStyle(.bordered)
            Button(Localization.text("overview.action.restart")) {
                environment.restartCore()
            }
            .disabled(environment.supervisor == nil)
        }
    }

    private var runtimeCard: some View {
        PanelCard(
            titleKey: "overview.section.runtime",
            symbol: "gauge",
            actions: { EmptyView() }
        ) {
            VStack(alignment: .leading, spacing: 8) {
                InfoRow(titleKey: "overview.field.version", value: model.status?.version ?? unknownValue)
                InfoRow(
                    titleKey: "overview.field.uptime",
                    value: model.status.map { Formatting.uptime($0.uptimeSeconds) } ?? unknownValue
                )
                if let statusFailure = model.statusFailure {
                    Text(Localization.format("overview.status.error", Localization.text("error.\(statusFailure.code)")))
                        .font(.caption)
                        .foregroundStyle(.red)
                }
                if let updated = model.lastStatusSuccess {
                    Text(Localization.format("overview.updated.status", timeString(updated)))
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                }
            }
        }
    }

    private var takeoverCard: some View {
        PanelCard(
            titleKey: "overview.section.takeover",
            symbol: "network",
            actions: { EmptyView() }
        ) {
            VStack(alignment: .leading, spacing: 8) {
                InfoRow(titleKey: "overview.field.system_proxy_state", value: proxyStateText)
                InfoRow(titleKey: "overview.field.inbound", value: inboundText)
                InfoRow(titleKey: "overview.field.tun", value: Localization.text("common.not_implemented"))
                if let configurationFailure = model.configurationFailure {
                    Text(Localization.format(
                        "overview.config.error",
                        Localization.text("error.\(configurationFailure.code)")
                    ))
                    .font(.caption)
                    .foregroundStyle(.red)
                }
                if let updated = model.lastConfigurationSuccess {
                    Text(Localization.format("overview.updated.config", timeString(updated)))
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                }
            }
        }
    }

    private var routingCard: some View {
        PanelCard(
            titleKey: "overview.section.routing",
            symbol: "arrow.triangle.branch",
            actions: { EmptyView() }
        ) {
            VStack(alignment: .leading, spacing: 8) {
                InfoRow(
                    titleKey: "overview.field.rules",
                    value: model.status.map { String($0.ruleCount) } ?? unknownValue
                )
                InfoRow(
                    titleKey: "overview.field.policies",
                    value: model.status.map { String($0.policyCount) } ?? unknownValue
                )
                InfoRow(
                    titleKey: "overview.field.pending_restart",
                    value: pendingRestartText
                )
            }
        }
    }

    private var problemCard: some View {
        PanelCard(
            titleKey: "overview.section.problem",
            symbol: "exclamationmark.triangle",
            actions: { EmptyView() }
        ) {
            VStack(alignment: .leading, spacing: 6) {
                if let statusFailure = model.statusFailure {
                    Text(Localization.format("overview.status.error", Localization.text("error.\(statusFailure.code)")))
                        .foregroundStyle(.red)
                }
                if let configurationFailure = model.configurationFailure {
                    Text(Localization.format(
                        "overview.config.error",
                        Localization.text("error.\(configurationFailure.code)")
                    ))
                    .foregroundStyle(.red)
                }
                if let failure = environment.snapshot.failure {
                    Text(environmentFailureText(failure))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    private var footer: some View {
        VStack(alignment: .leading, spacing: 4) {
            if let notice = environment.bootstrapNotice {
                Text(notice)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.top, 2)
    }

    private var unknownValue: String {
        Localization.text("overview.state.unknown")
    }

    private var subtitle: String {
        var parts: [String] = []
        if let pid = environment.snapshot.pid {
            parts.append("pid \(pid)")
        }
        if environment.snapshot.restarts > 0 {
            parts.append(Localization.format("overview.restarts", String(environment.snapshot.restarts)))
        }
        if environment.snapshot.state == .starting, environment.snapshot.failures > 0 {
            parts.append(Localization.format("overview.failures", String(environment.snapshot.failures)))
        }
        if parts.isEmpty {
            parts.append(Localization.text("overview.subtitle.idle"))
        }
        return parts.joined(separator: " · ")
    }

    private var stateColor: Color {
        switch environment.snapshot.state {
        case .running: return .green
        case .starting: return .orange
        case .crashed: return .red
        case .stopped: return .secondary
        }
    }

    private var proxyStateText: String {
        guard let state = model.configuration?.systemProxyState else {
            return model.configurationFailure == nil
                ? Localization.text("overview.proxy.unknown")
                : Localization.text("overview.state.unknown")
        }
        return Localization.text(state.state.localizationKey)
    }

    private var pendingRestartText: String {
        guard let pending = model.configuration?.pendingRestart, !pending.isEmpty else {
            return model.configuration == nil
                ? Localization.text("overview.state.unknown")
                : Localization.text("common.none")
        }
        return pending.joined(separator: ", ")
    }

    private var inboundText: String {
        guard let configuration = model.configuration else { return Localization.text("overview.state.unknown") }
        let http = configuration.httpListen ?? Localization.text("common.off")
        let socks = configuration.socks5Listen ?? Localization.text("common.off")
        return "HTTP \(http) · SOCKS5 \(socks)"
    }

    private func environmentFailureText(_ failure: CoreFailure) -> String {
        let reason = Localization.text(failure.localizationKey)
        return Localization.format("overview.core_failure", reason, failure.detail)
    }

    private func timeString(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateStyle = .none
        formatter.timeStyle = .medium
        return formatter.string(from: date)
    }
}
