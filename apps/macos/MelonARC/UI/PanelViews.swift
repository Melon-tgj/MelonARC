import SwiftUI

/// The rows shared by the live panels. A failure keeps the last rows on screen:
/// a blank page would hide the fact that the core answered a moment ago.
struct PanelStatus: View {
    let failure: APIError?
    let lastUpdated: Date?

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            if let failure {
                Text(Localization.format("panel.error", Localization.text("error.\(failure.code)")))
                    .foregroundStyle(.red)
                Text(failure.detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
            if let lastUpdated {
                Text(Localization.format("panel.updated", timeString(lastUpdated)))
                    .font(.caption)
                    .foregroundStyle(.tertiary)
            }
        }
    }

    private func timeString(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateStyle = .none
        formatter.timeStyle = .medium
        return formatter.string(from: date)
    }
}

struct PoliciesView: View {
    @ObservedObject var model: PoliciesModel

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            List(model.policies) { group in
                Section {
                    ForEach(group.members) { member in
                        HStack {
                            Image(systemName: member.healthy ? "checkmark.circle" : "xmark.circle")
                                .foregroundStyle(member.healthy ? .green : .red)
                            Text(member.name)
                            Spacer()
                            if member.name == group.active {
                                Text(Localization.text("policies.active"))
                                    .foregroundStyle(.secondary)
                            } else {
                                Button(Localization.text("policies.use")) {
                                    Task { try? await model.select(group: group.name, member: member.name) }
                                }
                            }
                        }
                    }
                } header: {
                    HStack {
                        Text(group.name)
                        Spacer()
                        Text(Localization.format(
                            "policies.health",
                            String(group.healthyMembers),
                            String(group.members.count)
                        ))
                        .foregroundStyle(group.allUnhealthy ? .red : .secondary)
                    }
                }
            }
            .listStyle(.inset)
            PanelStatus(failure: model.failure, lastUpdated: model.lastUpdated)
                .padding(.horizontal)
                .padding(.bottom, 8)
        }
        .navigationTitle(Text("panel.policies.title"))
    }
}

struct SubscriptionsView: View {
    @ObservedObject var model: SubscriptionsModel

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            List(model.subscriptions) { subscription in
                VStack(alignment: .leading, spacing: 5) {
                    HStack {
                        Text(subscription.name)
                            .font(.headline)
                        Spacer()
                        if model.refreshing.contains(subscription.name) {
                            ProgressView()
                                .controlSize(.small)
                        }
                        Button(Localization.text("subscriptions.refresh")) {
                            Task { try? await model.refreshNow(subscription.name) }
                        }
                        .disabled(model.refreshing.contains(subscription.name))
                    }
                    Text(Localization.format(
                        "subscriptions.summary",
                        String(subscription.nodes),
                        String(subscription.skipped)
                    ))
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    if let error = subscription.error, !error.isEmpty {
                        Text(Localization.format("subscriptions.last_error", error))
                            .font(.caption)
                            .foregroundStyle(.orange)
                    }
                    if let result = model.lastResult, result.subscription == subscription.name {
                        Text(Localization.format(
                            result.error == nil ? "subscriptions.result" : "subscriptions.result_failed",
                            result.error ?? String(result.nodes)
                        ))
                        .font(.caption)
                        .foregroundStyle(result.error == nil ? Color.secondary : Color.orange)
                    }
                }
                .padding(.vertical, 4)
            }
            .listStyle(.inset)
            PanelStatus(failure: model.failure, lastUpdated: model.lastUpdated)
                .padding(.horizontal)
                .padding(.bottom, 8)
        }
        .navigationTitle(Text("panel.subscriptions.title"))
    }
}

struct RulesView: View {
    @ObservedObject var model: RulesModel

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(Localization.format("rules.total", String(model.total)))
                    .foregroundStyle(.secondary)
                Spacer()
            }
            .padding(.horizontal)
            List(model.rules) { rule in
                VStack(alignment: .leading, spacing: 3) {
                    HStack {
                        Text("#\(rule.index)")
                            .foregroundStyle(.tertiary)
                        Text(rule.type)
                            .font(.headline)
                        Spacer()
                        Text(rule.target)
                    }
                    if let payload = rule.payload, !payload.isEmpty {
                        Text(payload)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                    }
                }
            }
            .listStyle(.inset)
            PanelStatus(failure: model.failure, lastUpdated: model.lastUpdated)
                .padding(.horizontal)
                .padding(.bottom, 8)
        }
        .navigationTitle(Text("panel.rules.title"))
    }
}

struct ConnectionsView: View {
    @ObservedObject var model: ConnectionsModel

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            List(model.connections) { connection in
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Text(connection.protocolName)
                            .font(.headline)
                        Text(connection.network)
                            .foregroundStyle(.secondary)
                        Spacer()
                        Text(Localization.format("connections.bytes", bytesText(connection.up), bytesText(connection.down)))
                            .font(.caption)
                    }
                    Text(connection.target)
                        .font(.callout)
                        .textSelection(.enabled)
                    if let policy = connection.policy, !policy.isEmpty {
                        Text(Localization.format("connections.policy", policy))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                .padding(.vertical, 3)
            }
            .listStyle(.inset)
            PanelStatus(failure: model.failure, lastUpdated: model.lastUpdated)
                .padding(.horizontal)
                .padding(.bottom, 8)
        }
        .navigationTitle(Text("panel.connections.title"))
    }

    private func bytesText(_ value: Int64) -> String {
        Formatting.bytes(value)
    }
}

struct LogsView: View {
    @ObservedObject var model: LogsModel

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            List(model.events) { event in
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Image(systemName: event.ok ? "checkmark.circle" : "exclamationmark.triangle")
                        .foregroundStyle(event.ok ? .green : .orange)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(event.kind)
                            .font(.callout.weight(.semibold))
                        if let detail = event.detail, !detail.isEmpty {
                            Text(detail)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .textSelection(.enabled)
                        }
                    }
                    Spacer()
                    Text(event.time)
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                }
            }
            .listStyle(.inset)
            PanelStatus(failure: model.failure, lastUpdated: model.lastUpdated)
                .padding(.horizontal)
                .padding(.bottom, 8)
        }
        .navigationTitle(Text("panel.logs.title"))
    }
}
