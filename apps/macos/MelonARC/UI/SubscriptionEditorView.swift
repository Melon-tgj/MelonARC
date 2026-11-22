import AppKit
import SwiftUI

private struct SheetSizing: NSViewRepresentable {
    let idealHeight: CGFloat

    func makeNSView(context: Context) -> SheetSizingNSView {
        SheetSizingNSView(idealHeight: idealHeight)
    }

    func updateNSView(_ nsView: SheetSizingNSView, context: Context) {
        nsView.idealHeight = idealHeight
        nsView.applyIfNeeded()
    }
}

private extension View {
    @ViewBuilder
    func fittedSheetSizing() -> some View {
        if #available(macOS 15.0, *) {
            presentationSizing(.fitted)
        } else {
            self
        }
    }
}

private final class SheetSizingNSView: NSView {
    var idealHeight: CGFloat = LayoutMetrics.Sheet.defaultHeight
    private var applied = false

    init(idealHeight: CGFloat) {
        self.idealHeight = idealHeight
        super.init(frame: .zero)
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        applyIfNeeded()
    }

    func applyIfNeeded() {
        guard !applied, let window else { return }
        applied = true
        window.contentMinSize = NSSize(
            width: LayoutMetrics.Sheet.minWidth,
            height: LayoutMetrics.Sheet.minHeight
        )
        window.contentMaxSize = NSSize(
            width: LayoutMetrics.Sheet.maxWidth,
            height: LayoutMetrics.Sheet.maxHeight
        )
        let size = NSSize(
            width: LayoutMetrics.Sheet.defaultWidth,
            height: min(max(idealHeight, LayoutMetrics.Sheet.minHeight), LayoutMetrics.Sheet.maxHeight)
        )
        window.setContentSize(size)
    }
}

struct SubscriptionEditorView: View {
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var model: SubscriptionsModel

    @State private var name = ""
    @State private var url = ""
    @State private var usesCustomInterval = false
    @State private var intervalMinutes = 360
    @State private var localError: String?
    @State private var submitting = false

    private var idealHeight: CGFloat {
        usesCustomInterval
            ? LayoutMetrics.Sheet.expandedHeight
            : LayoutMetrics.Sheet.defaultHeight
    }

    var body: some View {
        VStack(alignment: .leading, spacing: LayoutMetrics.headerGap) {
            Text(Localization.text("subscriptions.action.add"))
                .font(.title2.weight(.semibold))
                .frame(minHeight: 24)
            ScrollView {
                Grid(horizontalSpacing: LayoutMetrics.formGap, verticalSpacing: LayoutMetrics.formGap) {
                    GridRow {
                        Text(Localization.text("subscriptions.field.name"))
                            .gridColumnAlignment(.trailing)
                            .frame(width: LayoutMetrics.Sheet.labelColumn, alignment: .trailing)
                        TextField(Localization.text("subscriptions.field.name"), text: $name)
                            .frame(minWidth: LayoutMetrics.Sheet.minimumInputWidth)
                            .frame(minHeight: LayoutMetrics.Sheet.controlHeight)
                            .onSubmit { save() }
                    }
                    GridRow {
                        Text(Localization.text("subscriptions.field.url"))
                            .gridColumnAlignment(.trailing)
                            .frame(width: LayoutMetrics.Sheet.labelColumn, alignment: .trailing)
                        TextField(Localization.text("subscriptions.field.url"), text: $url)
                            .autocorrectionDisabled()
                            .frame(minWidth: LayoutMetrics.Sheet.minimumInputWidth)
                            .frame(minHeight: LayoutMetrics.Sheet.controlHeight)
                            .onSubmit { save() }
                    }
                    GridRow {
                        Color.clear
                            .frame(width: LayoutMetrics.Sheet.labelColumn)
                            .accessibilityHidden(true)
                        Toggle(Localization.text("subscriptions.field.custom_interval"), isOn: $usesCustomInterval)
                            .frame(minHeight: LayoutMetrics.Sheet.controlHeight)
                    }
                    if usesCustomInterval {
                        GridRow {
                            Color.clear
                                .frame(width: LayoutMetrics.Sheet.labelColumn)
                                .accessibilityHidden(true)
                            Stepper(
                                value: $intervalMinutes,
                                in: 5...10080,
                                step: 5
                            ) {
                                Text(Localization.format(
                                    "subscriptions.field.interval_minutes",
                                    String(intervalMinutes)
                                ))
                            }
                            .frame(minHeight: LayoutMetrics.Sheet.controlHeight)
                        }
                    }
                    if let localError {
                        GridRow {
                            Text(localError)
                                .foregroundStyle(.red)
                                .textSelection(.enabled)
                                .gridCellColumns(2)
                        }
                    }
                }
                .padding(.vertical, LayoutMetrics.detailGap)
            }
            HStack(spacing: LayoutMetrics.actionGap) {
                Spacer(minLength: 0)
                Button(Localization.text("subscriptions.action.cancel")) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                saveButton
            }
            .frame(minHeight: LayoutMetrics.Sheet.controlHeight)
        }
        .padding(LayoutMetrics.sheetInset)
        .frame(
            minWidth: LayoutMetrics.Sheet.minWidth,
            idealWidth: LayoutMetrics.Sheet.defaultWidth,
            maxWidth: LayoutMetrics.Sheet.maxWidth,
            minHeight: LayoutMetrics.Sheet.minHeight,
            idealHeight: idealHeight,
            maxHeight: LayoutMetrics.Sheet.maxHeight
        )
        .background(SheetSizing(idealHeight: idealHeight))
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("subscription.editor.root")
        .fittedSheetSizing()
    }

    @ViewBuilder
    private var saveButton: some View {
        if #available(macOS 26.0, *) {
            Button(Localization.text("subscriptions.action.save"), action: save)
                .buttonStyle(.glassProminent)
                .keyboardShortcut(.defaultAction)
                .disabled(submitting || !isValid)
        } else {
            Button(Localization.text("subscriptions.action.save"), action: save)
                .buttonStyle(.borderedProminent)
                .keyboardShortcut(.defaultAction)
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
