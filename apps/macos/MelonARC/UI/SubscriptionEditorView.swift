import SwiftUI

struct SubscriptionEditorView: View {
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var model: SubscriptionsModel

    @State private var name = ""
    @State private var url = ""
    @State private var usesCustomInterval = false
    @State private var intervalMinutes = 360
    @State private var localError: String?
    @State private var submitting = false

    var body: some View {
        NavigationStack {
            Form {
                Section(Localization.text("subscriptions.form.title")) {
                    TextField(Localization.text("subscriptions.field.name"), text: $name)
                    TextField(Localization.text("subscriptions.field.url"), text: $url)
                        .autocorrectionDisabled()
                    Toggle(Localization.text("subscriptions.field.custom_interval"), isOn: $usesCustomInterval)
                    if usesCustomInterval {
                        Stepper(
                            value: $intervalMinutes,
                            in: 5...10080,
                            step: 5
                        ) {
                            Text(Localization.format("subscriptions.field.interval_minutes", String(intervalMinutes)))
                        }
                    }
                }
                if let localError {
                    Section {
                        Text(localError)
                            .foregroundStyle(.red)
                            .textSelection(.enabled)
                    }
                }
            }
            .navigationTitle(Localization.text("subscriptions.action.add"))
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(Localization.text("subscriptions.action.cancel")) { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    saveButton
                }
            }
        }
        .frame(minWidth: 420, minHeight: 300)
    }

    @ViewBuilder
    private var saveButton: some View {
        if #available(macOS 26.0, *) {
            Button(Localization.text("subscriptions.action.save"), action: save)
                .buttonStyle(.glassProminent)
                .disabled(submitting || !isValid)
        } else {
            Button(Localization.text("subscriptions.action.save"), action: save)
                .buttonStyle(.borderedProminent)
                .disabled(submitting || !isValid)
        }
    }

    private var isValid: Bool {
        !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && validURL
    }

    private var validURL: Bool {
        guard let components = URLComponents(string: url),
              let scheme = components.scheme?.lowercased(),
              scheme == "http" || scheme == "https",
              components.host != nil else { return false }
        return true
    }

    private func save() {
        guard isValid, !submitting else { return }
        localError = nil
        submitting = true
        let interval = usesCustomInterval ? Int64(intervalMinutes * 60) : nil
        Task {
            do {
                _ = try await model.create(
                    name: name.trimmingCharacters(in: .whitespacesAndNewlines),
                    url: url,
                    intervalSeconds: interval
                )
                await MainActor.run { dismiss() }
            } catch let error as APIError {
                await MainActor.run {
                    localError = message(for: error)
                    submitting = false
                }
            } catch {
                await MainActor.run {
                    localError = Localization.text("error.unreachable")
                    submitting = false
                }
            }
        }
    }

    private func message(for error: APIError) -> String {
        switch error.code {
        case "method_not_allowed", "not_found":
            return Localization.text("subscriptions.unsupported")
        case "subscription_conflict":
            return Localization.text("error.conflict")
        case "invalid_subscription", "bad_request":
            return Localization.text("error.bad_request")
        case "config_changed":
            return Localization.text("error.conflict")
        default:
            return Localization.format("subscriptions.create_failed", Localization.text("error.\(error.code)"))
        }
    }
}
