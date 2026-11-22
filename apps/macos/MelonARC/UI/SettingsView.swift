import Combine
import SwiftUI

/// The settings window.
///
/// The data directory is shown but deliberately not editable: M4 fixed the
/// policy at "refuse a change" because the proxy snapshot, history, token and
/// subscription cache would otherwise be split across two directories. The
/// proxy switch is the setting that can be applied while the app is running:
/// save, reload, restart only when the core says a restart is needed, then read
/// the state back from the core.
struct SettingsView: View {
    @ObservedObject var environment: AppEnvironment
    @ObservedObject var update: UpdateModel
    @State private var proxyEnabled = false
    @State private var proxyState = SystemProxyStateView(state: .off)
    @State private var notice: String?
    @State private var failure: APIError?
    @State private var busy = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: LayoutMetrics.headerGap) {
                proxyGroup
                capabilitiesGroup
                if let settings = environment.settings {
                    pathsGroup(settings)
                    diagnosticsGroup
                    aboutGroup
                    if let notice = settings.notice {
                        Text(notice)
                            .font(.caption)
                            .foregroundStyle(.orange)
                            .textSelection(.enabled)
                    }
                } else {
                    UnavailableView(
                        titleKey: "startup.failed.title",
                        message: environment.launchFailure ?? environment.settingsFailure ?? "",
                        symbol: "exclamationmark.triangle"
                    )
                }
                Text("settings.footer")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(LayoutMetrics.pageInset)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .frame(width: 580, height: 480)
        .onAppear {
            adopt(environment.overview.configuration)
        }
        .onReceive(environment.overview.$configuration) { configuration in
            if !busy { adopt(configuration) }
        }
    }

    private var proxyGroup: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: LayoutMetrics.fieldGap) {
                Toggle(Localization.text("settings.system_proxy.enabled"), isOn: $proxyEnabled)
                    .disabled(busy || environment.apiClient == nil)
                InfoRow(
                    titleKey: "settings.system_proxy.state",
                    value: Localization.text(proxyState.state.localizationKey),
                    labelWidth: LayoutMetrics.infoLabelWidth
                )
                if !proxyState.detail.isEmpty {
                    Text(Localization.format("settings.system_proxy.detail", proxyState.detail))
                        .font(.caption)
                        .foregroundStyle(.orange)
                        .textSelection(.enabled)
                }
                Button(action: saveProxy) {
                    if busy {
                        ProgressView()
                            .controlSize(.small)
                    } else {
                        Text("settings.action.save")
                    }
                }
                .disabled(busy || environment.apiClient == nil)
                if let notice {
                    Text(notice)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                if let failure {
                    Text(Localization.format("settings.error", Localization.text("error.\(failure.code)")))
                        .foregroundStyle(.red)
                    Text(failure.detail)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.top, 2)
        } label: {
            Label {
                Text("settings.section.network")
            } icon: {
                Image(systemName: "network")
            }
        }
    }

    private var capabilitiesGroup: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: LayoutMetrics.fieldGap) {
                InfoRow(
                    titleKey: "overview.field.tun",
                    value: Localization.text("common.not_implemented"),
                    labelWidth: LayoutMetrics.infoLabelWidth
                )
                Text("settings.tun.note")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.top, 2)
        } label: {
            Label {
                Text("settings.section.capabilities")
            } icon: {
                Image(systemName: "info.circle")
            }
        }
    }

    private func pathsGroup(_ settings: ShellSettings) -> some View {
        GroupBox {
            VStack(alignment: .leading, spacing: LayoutMetrics.fieldGap) {
                InfoRow(titleKey: "settings.field.data_dir", value: settings.dataDirectory.path, labelWidth: 120)
                Text("settings.data_dir.note")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                InfoRow(titleKey: "settings.field.config", value: settings.configurationPath.path, labelWidth: 120)
                InfoRow(titleKey: "settings.field.token", value: settings.tokenPath.path, labelWidth: 120)
                InfoRow(titleKey: "settings.field.log", value: settings.logPath.path, labelWidth: 120)
                InfoRow(titleKey: "settings.field.core",
                        value: settings.corePath?.path ?? Localization.text("settings.missing"),
                        labelWidth: 120)
                InfoRow(titleKey: "settings.field.api", value: settings.apiAddress.label, labelWidth: 120)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.top, 2)
        } label: {
            Label {
                Text("settings.section.diagnostics")
            } icon: {
                Image(systemName: "folder")
            }
        }
    }

    private var diagnosticsGroup: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: LayoutMetrics.fieldGap) {
                if let event = environment.bootstrapEvent {
                    InfoRow(titleKey: "settings.field.bootstrap", value: event.path, labelWidth: 120)
                    Text(event.detail)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                } else {
                    Text("settings.bootstrap.none")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                if let failure = environment.overview.configurationFailure {
                    Text(Localization.format("settings.error", Localization.text("error.\(failure.code)")))
                        .foregroundStyle(.red)
                    Button(Localization.text("panel.state.retry")) {
                        environment.overview.refresh()
                    }
                }
                Button(Localization.text("panel.state.reopen")) {
                    environment.showMainWindow()
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.top, 2)
        } label: {
            Label {
                Text("settings.diagnostics.title")
            } icon: {
                Image(systemName: "wrench.and.screwdriver")
            }
        }
    }

    private var aboutGroup: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: LayoutMetrics.fieldGap) {
                InfoRow(
                    titleKey: "settings.about.channel",
                    value: Localization.text("settings.about.channel_value"),
                    labelWidth: 120
                )
                UpdateView(model: update)
                Text("settings.footer")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.top, 2)
        } label: {
            Label {
                Text("settings.section.about")
            } icon: {
                Image(systemName: "info.circle")
            }
        }
    }

    private func adopt(_ configuration: ConfigurationView?) {
        guard let configuration else { return }
        proxyEnabled = configuration.systemProxy
        proxyState = configuration.systemProxyState
    }

    private func saveProxy() {
        busy = true
        notice = nil
        failure = nil
        Task {
            do {
                let configuration = try await environment.setSystemProxy(proxyEnabled)
                await MainActor.run {
                    proxyEnabled = configuration.systemProxy
                    proxyState = configuration.systemProxyState
                    notice = Localization.text("settings.saved")
                    busy = false
                }
            } catch let error as APIError {
                await MainActor.run {
                    failure = error
                    busy = false
                }
            } catch {
                await MainActor.run {
                    failure = .unreachable(error.localizedDescription)
                    busy = false
                }
            }
        }
    }
}
