import SwiftUI

/// One label/value pair. A fixed label column keeps the values aligned without a
/// grid, which is the kind of layout that survives a localization turning a label
/// into a longer word.
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

/// The overview: the one panel this milestone can fill, and the proof that the
/// native window reaches the real core with a real token.
///
/// Everything drawn here comes from an authenticated read. The state of the process
/// comes from the supervisor, which is the only thing that knows whether the child
/// exists; the numbers below it come from `/v1/status`, which is the only thing that
/// knows whether it is answering.
struct OverviewView: View {
    @ObservedObject var model: OverviewModel
    @ObservedObject var environment: AppEnvironment

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                header
                coreGroup
                systemProxyGroup
                if let failure = model.failure {
                    errorGroup(failure)
                }
                footer
            }
            .padding(22)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .navigationTitle(Text("panel.overview.title"))
    }

    // MARK: - Sections

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
            Button("overview.action.restart") {
                environment.restartCore()
            }
            .disabled(environment.supervisor == nil)
        }
    }

    private var coreGroup: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 7) {
                InfoRow(titleKey: "overview.field.version", value: model.status?.version ?? "—")
                InfoRow(titleKey: "overview.field.uptime",
                        value: model.status.map { Formatting.uptime($0.uptimeSeconds) } ?? "—")
                InfoRow(titleKey: "overview.field.rules",
                        value: model.status.map { String($0.ruleCount) } ?? "—")
                InfoRow(titleKey: "overview.field.policies",
                        value: model.status.map { String($0.policyCount) } ?? "—")
                InfoRow(titleKey: "overview.field.config",
                        value: Formatting.path(model.status?.configPath ?? model.configuration?.path))
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.top, 2)
        } label: {
            Label {
                Text("overview.section.core")
            } icon: {
                Image(systemName: "gauge")
            }
        }
    }

    private var systemProxyGroup: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 7) {
                InfoRow(titleKey: "overview.field.system_proxy",
                        value: booleanText(model.configuration?.systemProxy))
                InfoRow(titleKey: "overview.field.pending_restart", value: pendingRestartText)
                InfoRow(titleKey: "overview.field.inbound", value: inboundText)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.top, 2)
        } label: {
            Label {
                Text("overview.section.system_proxy")
            } icon: {
                Image(systemName: "network")
            }
        }
    }

    private func errorGroup(_ failure: APIError) -> some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 6) {
                Text(Localization.format("overview.error", Localization.text("error.\(failure.code)")))
                    .foregroundStyle(.red)
                Text(failure.detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.top, 2)
        } label: {
            Label {
                Text("overview.section.problem")
            } icon: {
                Image(systemName: "exclamationmark.triangle")
            }
        }
    }

    private var footer: some View {
        VStack(alignment: .leading, spacing: 4) {
            if let failure = environment.snapshot.failure {
                Text(environmentFailureText(failure))
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            if let notice = environment.bootstrapNotice {
                Text(notice)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
            if let updated = model.lastUpdated {
                Text(Localization.format("overview.updated", timeString(updated)))
                    .font(.caption)
                    .foregroundStyle(.tertiary)
            }
        }
        .padding(.top, 2)
    }

    // MARK: - Values

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

    private func booleanText(_ value: Bool?) -> String {
        guard let value else { return "—" }
        return Localization.text(value ? "common.on" : "common.off")
    }

    private var pendingRestartText: String {
        guard let pending = model.configuration?.pendingRestart, !pending.isEmpty else {
            return Localization.text("common.none")
        }
        return pending.joined(separator: ", ")
    }

    private var inboundText: String {
        guard let configuration = model.configuration else { return "—" }
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
