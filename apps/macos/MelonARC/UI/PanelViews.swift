import SwiftUI

struct PanelStatus: View {
    let failure: APIError?
    let writeFailure: APIError?
    let lastUpdated: Date?

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            if let writeFailure {
                Text(Localization.format("panel.write_error", Localization.text("error.\(writeFailure.code)")))
                    .foregroundStyle(.orange)
            }
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
    @Binding var selection: String?
    @Binding var path: NavigationPath

    private var isInitialFailure: Bool {
        if case .failed = model.phase { return true }
        return false
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            PanelStateView(
                phase: model.phase,
                titleKey: "policies.empty.title",
                descriptionKey: "policies.empty.description",
                symbol: "arrow.triangle.branch",
                retry: { model.refresh(force: true) },
                content: {
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
                                            Task {
                                                do {
                                                    try await model.select(group: group.name, member: member.name)
                                                } catch {
                                                    model.recordWriteFailure(error)
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        } header: {
                            NavigationLink(value: PanelDetailRoute.policyGroup(group.name)) {
                                HStack {
                                    Text(group.name)
                                        .font(.headline)
                                    Text(group.type)
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
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
                    }
                    .listStyle(.inset)
                },
                actions: {
                    Button(Localization.text("policies.action.subscriptions")) {
                        selection = PanelRegistry.subscriptions.id
                    }
                }
            )
            if !isInitialFailure {
                PanelStatus(failure: model.failure, writeFailure: model.writeFailure, lastUpdated: model.lastUpdated)
                    .padding(.horizontal)
                    .padding(.bottom, 8)
            }
        }
        .navigationTitle(Text("panel.policies.title"))
    }
}

struct SubscriptionsView: View {
    @ObservedObject var model: SubscriptionsModel
    @Binding var path: NavigationPath

    @State private var showingEditor = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            PanelStateView(
                phase: model.phase,
                titleKey: "subscriptions.empty.title",
                descriptionKey: "subscriptions.empty.description",
                symbol: "arrow.triangle.2.circlepath",
                retry: { model.refresh(force: true) },
                content: {
                    List(model.subscriptions) { subscription in
                        HStack(alignment: .top, spacing: 8) {
                            NavigationLink(value: PanelDetailRoute.subscription(subscription.name)) {
                                VStack(alignment: .leading, spacing: 5) {
                                    HStack {
                                        Text(subscription.name)
                                            .font(.headline)
                                        if model.lastCreatedName == subscription.name {
                                            Text(Localization.text("subscriptions.new"))
                                                .font(.caption)
                                                .foregroundStyle(.green)
                                        }
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
                            }
                            Spacer(minLength: 0)
                            if model.refreshing.contains(subscription.name) {
                                ProgressView()
                                    .controlSize(.small)
                            }
                            Button(Localization.text("subscriptions.refresh")) {
                                Task {
                                    do {
                                        try await model.refreshNow(subscription.name)
                                    } catch {
                                        model.recordWriteFailure(error)
                                    }
                                }
                            }
                            .disabled(model.refreshing.contains(subscription.name))
                        }
                        .padding(.vertical, 4)
                    }
                    .listStyle(.inset)
                },
                actions: {
                    Button(Localization.text("subscriptions.action.add")) { showingEditor = true }
                }
            )
            PanelStatus(failure: model.failure, writeFailure: model.writeFailure, lastUpdated: model.lastUpdated)
                .padding(.horizontal)
                .padding(.bottom, 8)
        }
        .navigationTitle(Text("panel.subscriptions.title"))
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button(Localization.text("subscriptions.action.add")) { showingEditor = true }
                    .buttonStyle(.borderedProminent)
            }
        }
        .sheet(isPresented: $showingEditor) {
            SubscriptionEditorView(model: model)
        }
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
                if model.rules.count < model.total {
                    Text(Localization.format("rules.shown", String(model.rules.count)))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .padding(.horizontal)
            PanelStateView(
                phase: model.phase,
                titleKey: "rules.empty.title",
                descriptionKey: "rules.empty.description",
                symbol: "list.bullet",
                retry: { model.refresh(force: true) },
                content: {
                    List(model.rules) { rule in
                        VStack(alignment: .leading, spacing: 3) {
                            HStack(spacing: 8) {
                                Text("#\(rule.index)")
                                    .foregroundStyle(.tertiary)
                                if rule.type.lowercased() == "final" {
                                    Text(Localization.format("rules.final", rule.type.uppercased(), rule.target))
                                        .font(.headline)
                                } else {
                                    Text(rule.type)
                                        .font(.headline)
                                    Spacer()
                                    Text(rule.target)
                                }
                            }
                            if let payload = rule.payload, !payload.isEmpty {
                                Text(payload)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                    .textSelection(.enabled)
                            }
                            if let source = rule.source, !source.isEmpty {
                                Text(Localization.format("rules.source", source, String(rule.line ?? 0)))
                                    .font(.caption)
                                    .foregroundStyle(.tertiary)
                            }
                        }
                    }
                    .listStyle(.inset)
                },
                actions: { EmptyView() }
            )
            PanelStatus(failure: model.failure, writeFailure: nil, lastUpdated: model.lastUpdated)
                .padding(.horizontal)
                .padding(.bottom, 8)
        }
        .navigationTitle(Text("panel.rules.title"))
    }
}

struct ConnectionsView: View {
    @ObservedObject var model: ConnectionsModel
    @Binding var path: NavigationPath

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            PanelStateView(
                phase: model.phase,
                titleKey: "connections.empty.title",
                descriptionKey: "connections.empty.description",
                symbol: "network",
                retry: { model.refresh(force: true) },
                content: {
                    List(model.connections) { connection in
                        NavigationLink(value: PanelDetailRoute.connection(connection.id)) {
                            VStack(alignment: .leading, spacing: 4) {
                                HStack {
                                    Text(connection.protocolName)
                                        .font(.headline)
                                    Text(connection.network)
                                        .foregroundStyle(.secondary)
                                    Spacer()
                                    Text(Localization.format("connections.bytes", Formatting.bytes(connection.up), Formatting.bytes(connection.down)))
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
                    }
                    .listStyle(.inset)
                },
                actions: { EmptyView() }
            )
            PanelStatus(failure: model.failure, writeFailure: nil, lastUpdated: model.lastUpdated)
                .padding(.horizontal)
                .padding(.bottom, 8)
        }
        .navigationTitle(Text("panel.connections.title"))
    }
}

struct LogsView: View {
    @ObservedObject var model: LogsModel

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            PanelStateView(
                phase: model.phase,
                titleKey: "logs.empty.title",
                descriptionKey: "logs.empty.description",
                symbol: "text.alignleft",
                retry: { model.refresh(force: true) },
                content: {
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
                },
                actions: { EmptyView() }
            )
            PanelStatus(failure: model.failure, writeFailure: nil, lastUpdated: model.lastUpdated)
                .padding(.horizontal)
                .padding(.bottom, 8)
        }
        .navigationTitle(Text("panel.logs.title"))
    }
}
