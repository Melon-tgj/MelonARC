import SwiftUI

struct UpdateView: View {
    @ObservedObject var model: UpdateModel

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 8) {
                InfoRow(
                    titleKey: "updates.field.status",
                    value: model.statusText,
                    labelWidth: 120
                )
                Text("updates.note.manual_install")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 8) {
                    Button(Localization.text(model.isBusy ? "updates.action.cancel" : "updates.action.check")) {
                        if model.isBusy {
                            model.cancel()
                        } else {
                            model.check()
                        }
                    }
                    if model.canDownload {
                        Button(Localization.text("updates.action.download")) {
                            model.download()
                        }
                    }
                    if model.canSave {
                        Button(Localization.text("updates.action.save")) {
                            Task { await model.saveDownload() }
                        }
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.top, 2)
        } label: {
            Label {
                Text("updates.section.title")
            } icon: {
                Image(systemName: "arrow.triangle.2.circlepath")
            }
        }
    }
}

struct UpdateAlertModifier: ViewModifier {
    @ObservedObject var model: UpdateModel

    func body(content: Content) -> some View {
        content.alert(Text(Localization.text("updates.alert.title")), isPresented: $model.alertPresented) {
            if model.canDownload {
                Button(Localization.text("updates.action.download")) {
                    model.download()
                }
            }
            if model.canSave {
                Button(Localization.text("updates.action.save")) {
                    Task { await model.saveDownload() }
                }
            }
            Button(Localization.text("common.close"), role: .cancel) {}
        } message: {
            Text(model.alertMessage)
        }
    }
}
