import SwiftUI

enum PanelDetailRoute: Hashable {
    case overview
    case policyGroup(String)
    case subscription(String)
    case connection(String)
}

struct PanelDetailView: View {
    let route: PanelDetailRoute
    @ObservedObject var environment: AppEnvironment

    var body: some View {
        Group {
            switch route {
            case .overview:
                OverviewDetailView(environment: environment)
            case .policyGroup(let name):
                PolicyDetailView(name: name, model: environment.policies)
            case .subscription(let name):
                SubscriptionDetailView(name: name, model: environment.subscriptions)
            case .connection(let id):
                ConnectionDetailView(id: id, model: environment.connections)
            }
        }
    }
}

private struct OverviewDetailView: View {
    @ObservedObject var environment: AppEnvironment

    var body: some View {
        List {
            Section(Localization.text("overview.section.runtime")) {
                InfoRow(titleKey: "overview.detail.pid", value: environment.snapshot.pid.map(String.init) ?? Localization.text("common.none"), labelWidth: 120)
                InfoRow(titleKey: "overview.detail.restarts", value: String(environment.snapshot.restarts), labelWidth: 120)
                InfoRow(titleKey: "overview.detail.version", value: environment.overview.status?.version ?? Localization.text("common.none"), labelWidth: 120)
            }
            Section(Localization.text("overview.section.takeover")) {
                InfoRow(titleKey: "overview.detail.config", value: environment.settings?.configurationPath.path ?? Localization.text("common.none"), labelWidth: 120)
                InfoRow(titleKey: "overview.detail.system_proxy", value: Localization.text(environment.overview.configuration?.systemProxyState.state.localizationKey ?? "system_proxy.state.unknown"), labelWidth: 120)
                if let event = environment.bootstrapEvent {
                    InfoRow(titleKey: "overview.detail.bootstrap", value: event.path, labelWidth: 120)
                }
                if let failure = environment.snapshot.failure {
                    Text(Localization.format("overview.core_failure", Localization.text(failure.localizationKey), failure.detail))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .listStyle(.inset)
        .navigationTitle(Localization.text("overview.detail.title"))
    }
}

private struct PolicyDetailView: View {
    let name: String
    @ObservedObject var model: PoliciesModel

    var body: some View {
        Group {
            if let group = model.policies.first(where: { $0.name == name }) {
                List(group.members) { member in
                    HStack(alignment: .firstTextBaseline, spacing: 10) {
                        Image(systemName: member.healthy ? "checkmark.circle" : "xmark.circle")
                            .foregroundStyle(member.healthy ? .green : .orange)
                        VStack(alignment: .leading, spacing: 3) {
                            Text(member.name)
                            if let error = member.error, !error.isEmpty {
                                Text(error)
                                    .font(.caption)
                                    .foregroundStyle(.orange)
                            }
                        }
                        Spacer()
                        if member.checked {
                            Text(Formatting.latency(member.latencyMs))
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        } else {
                            Text("policies.unchecked")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
                .listStyle(.inset)
            } else {
                Text("detail.policy.missing")
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .navigationTitle(name)
    }
}

private struct SubscriptionDetailView: View {
    let name: String
    @ObservedObject var model: SubscriptionsModel

    @State private var detail: SubscriptionSkippedView?
    @State private var failure: APIError?
    @State private var loading = true
    @State private var refreshing = false

    var body: some View {
        List {
            Section {
                if let subscription = model.subscriptions.first(where: { $0.id == name }) {
                    InfoRow(
                        titleKey: "detail.subscription.nodes",
                        value: String(subscription.nodes),
                        labelWidth: 120
                    )
                    InfoRow(
                        titleKey: "detail.subscription.skipped",
                        value: String(subscription.skipped),
                        labelWidth: 120
                    )
                    InfoRow(
                        titleKey: "detail.subscription.fetched",
                        value: subscription.fetchedAt ?? Localization.text("common.none"),
                        labelWidth: 120
                    )
                    if let error = subscription.error, !error.isEmpty {
                        Text(error)
                            .font(.caption)
                            .foregroundStyle(.orange)
                    }
                }
                Button {
                    Task { await refresh() }
                } label: {
                    if refreshing {
                        ProgressView().controlSize(.small)
                    } else {
                        Text(Localization.text("subscriptions.refresh"))
                    }
                }
                .disabled(refreshing || model.refreshing.contains(name))
            } header: {
                Text(Localization.text("detail.subscription.summary"))
            }
            Section {
                if loading {
                    ProgressView(Localization.text("panel.state.loading"))
                } else if let failure {
                    Text(Localization.format("panel.error", Localization.text("error.\(failure.code)")))
                        .foregroundStyle(.red)
                } else if let detail, !detail.skipped.isEmpty {
                    ForEach(detail.skipped, id: \.item) { entry in
                        HStack(alignment: .firstTextBaseline, spacing: 10) {
                            Text("#\(entry.item)")
                                .foregroundStyle(.tertiary)
                            Text(entry.reason)
                                .font(.caption)
                        }
                    }
                } else {
                    Text(Localization.text("detail.subscription.no_skipped"))
                        .foregroundStyle(.secondary)
                }
            } header: {
                Text(Localization.text("detail.subscription.skipped"))
            }
        }
        .listStyle(.inset)
        .navigationTitle(name)
        .task { await load() }
    }

    private func load() async {
        guard let client = model.api else { return }
        loading = true
        failure = nil
        do {
            let value = try await client.subscriptionSkipped(name, offset: 0, limit: 50)
            await MainActor.run {
                detail = value
                loading = false
            }
        } catch let error as APIError {
            await MainActor.run {
                failure = error
                loading = false
            }
        } catch {
            await MainActor.run {
                failure = .unreachable(error.localizedDescription)
                loading = false
            }
        }
    }

    private func refresh() async {
        refreshing = true
        do {
            try await model.refreshNow(name)
            await load()
        } catch {
            model.recordWriteFailure(error)
        }
        await MainActor.run { refreshing = false }
    }
}

private struct ConnectionDetailView: View {
    let id: String
    @ObservedObject var model: ConnectionsModel

    var body: some View {
        Group {
            if let item = model.connections.first(where: { $0.id == id }) {
                List {
                    InfoRow(titleKey: "detail.connection.target", value: item.target, labelWidth: 120)
                    InfoRow(titleKey: "detail.connection.protocol", value: item.protocolName, labelWidth: 120)
                    InfoRow(titleKey: "detail.connection.network", value: item.network, labelWidth: 120)
                    InfoRow(titleKey: "detail.connection.rule", value: item.rule ?? Localization.text("common.none"), labelWidth: 120)
                    InfoRow(titleKey: "detail.connection.policy", value: item.policy ?? Localization.text("common.none"), labelWidth: 120)
                    InfoRow(titleKey: "detail.connection.outbound", value: item.outbound ?? Localization.text("common.none"), labelWidth: 120)
                    InfoRow(
                        titleKey: "detail.connection.bytes",
                        value: Localization.format(
                            "connections.bytes",
                            Formatting.bytes(item.up),
                            Formatting.bytes(item.down)
                        ),
                        labelWidth: 120
                    )
                    InfoRow(
                        titleKey: "detail.connection.duration",
                        value: Localization.format("detail.connection.duration_ms", String(Int(item.durationMs))),
                        labelWidth: 120
                    )
                    InfoRow(titleKey: "detail.connection.time", value: item.time, labelWidth: 120)
                }
                .listStyle(.inset)
            } else {
                Text("detail.connection.missing")
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .navigationTitle(Localization.text("detail.connection.title"))
    }
}
