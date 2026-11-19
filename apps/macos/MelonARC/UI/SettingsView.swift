import SwiftUI

/// The settings window.
///
/// This milestone only has to prove that the paths are the ones the core uses, so
/// the window reports them and nothing else. The switches — system proxy, log level,
/// data directory — belong to the next milestone, and each of them will need the same
/// pair of rules the previous shell had: a change that only the next core can apply
/// is saved and then applied by a controlled restart, and a change the running API
/// client is bound to asks for a new shell.
struct SettingsView: View {
    @ObservedObject var environment: AppEnvironment

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                if let settings = environment.settings {
                    pathsGroup(settings)
                    if let notice = settings.notice {
                        Text(notice)
                            .font(.caption)
                            .foregroundStyle(.orange)
                            .textSelection(.enabled)
                    }
                } else {
                    UnavailableView(
                        titleKey: "startup.failed.title",
                        message: environment.settingsFailure ?? "",
                        symbol: "exclamationmark.triangle"
                    )
                }
                Text("settings.footer")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .frame(width: 580, height: 400)
    }

    private func pathsGroup(_ settings: ShellSettings) -> some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 7) {
                InfoRow(titleKey: "settings.field.data_dir", value: settings.dataDirectory.path, labelWidth: 120)
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
                Text("settings.section.paths")
            } icon: {
                Image(systemName: "folder")
            }
        }
    }
}
