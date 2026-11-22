import SwiftUI

struct SidebarPanelButton: View {
    let identifier: String
    let titleKey: String
    let symbol: String
    let rowHeight: CGFloat
    let selected: Bool
    let action: () -> Void

    @Environment(\.sidebarRowSize) private var rowSize
    @State private var hovering = false

    private var iconSize: CGFloat {
        LayoutMetrics.Sidebar.limits(for: rowSize).icon
    }

    private var labelFont: Font {
        switch rowSize {
        case .small:
            return .callout
        case .large:
            return .title3
        case .medium:
            return .body
        @unknown default:
            return .body
        }
    }

    var body: some View {
        Button(action: action) {
            HStack(spacing: LayoutMetrics.Sidebar.iconGap) {
                Image(systemName: symbol)
                    .font(.system(size: iconSize, weight: .semibold))
                    .frame(width: LayoutMetrics.Sidebar.iconColumn)
                Text(Localization.text(titleKey))
                    .font(labelFont.weight(selected ? .semibold : .regular))
                    .lineLimit(2)
                Spacer(minLength: LayoutMetrics.Sidebar.iconGap)
                Image(systemName: "checkmark")
                    .font(.caption.weight(.bold))
                    .frame(width: LayoutMetrics.Sidebar.checkSlot)
                    .opacity(selected ? 1 : 0)
                    .allowsHitTesting(false)
                    .accessibilityHidden(true)
            }
            .padding(.leading, LayoutMetrics.Sidebar.labelLeading)
            .padding(.trailing, LayoutMetrics.Sidebar.labelTrailing)
            .padding(.vertical, LayoutMetrics.Sidebar.labelVertical)
            .frame(maxWidth: .infinity, minHeight: rowHeight, alignment: .leading)
            .contentShape(Rectangle())
        }
        .buttonStyle(SidebarPanelButtonStyle(selected: selected, hovering: hovering))
        .onHover { hovering = $0 }
        .foregroundStyle(Color.primary)
        .accessibilityIdentifier(identifier)
        .accessibilityLabel(Localization.text(titleKey))
        .accessibilityAddTraits(selected ? AccessibilityTraits.isSelected : AccessibilityTraits())
    }
}

struct SidebarPanelButtonStyle: ButtonStyle {
    let selected: Bool
    let hovering: Bool

    @Environment(\.colorSchemeContrast) private var contrast
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
    @Environment(\.isFocused) private var isFocused

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .background {
                backgroundLayers(pressed: configuration.isPressed)
            }
            .overlay {
                RoundedRectangle(cornerRadius: LayoutMetrics.Sidebar.cornerRadius, style: .continuous)
                    .strokeBorder(
                        borderColor(pressed: configuration.isPressed),
                        lineWidth: borderWidth(pressed: configuration.isPressed)
                    )
                    .allowsHitTesting(false)
            }
            .overlay(alignment: .leading) {
                if selected {
                    RoundedRectangle(cornerRadius: 1.5)
                        .fill(Color.accentColor)
                        .frame(
                            width: LayoutMetrics.Sidebar.markerWidth,
                            height: LayoutMetrics.Sidebar.markerHeight
                        )
                        .padding(.leading, LayoutMetrics.Sidebar.markerInset)
                        .allowsHitTesting(false)
                        .accessibilityHidden(true)
                }
            }
            .overlay {
                if isFocused {
                    RoundedRectangle(cornerRadius: LayoutMetrics.Sidebar.cornerRadius + 2, style: .continuous)
                        .stroke(Color.accentColor, lineWidth: 2)
                        .padding(-2)
                        .allowsHitTesting(false)
                }
            }
    }

    @ViewBuilder
    private func backgroundLayers(pressed: Bool) -> some View {
        let shape = RoundedRectangle(cornerRadius: LayoutMetrics.Sidebar.cornerRadius, style: .continuous)
        if usesOpaqueBase {
            shape.fill(Color(nsColor: .controlBackgroundColor))
        }
        shape.fill(baseFill(pressed: pressed))
        if let extra = selectedOverlay(pressed: pressed) {
            shape.fill(extra)
        }
    }

    private var usesOpaqueBase: Bool {
        if #available(macOS 26.0, *) {
            return reduceTransparency
        }
        return true
    }

    private func baseFill(pressed: Bool) -> Color {
        if selected {
            return Color.accentColor.opacity(usesOpaqueBase ? 0.16 : 0.14)
        }
        if pressed {
            return Color.primary.opacity(usesOpaqueBase ? 0.18 : 0.16)
        }
        if hovering {
            return Color.primary.opacity(usesOpaqueBase ? 0.10 : 0.09)
        }
        return Color.primary.opacity(usesOpaqueBase ? 0.06 : 0.04)
    }

    private func selectedOverlay(pressed: Bool) -> Color? {
        guard selected else { return nil }
        if pressed { return Color.primary.opacity(0.10) }
        if hovering { return Color.primary.opacity(0.05) }
        return nil
    }

    private func borderColor(pressed: Bool) -> Color {
        if contrast == .increased { return Color.primary }
        if selected { return Color.primary.opacity(0.80) }
        if pressed { return Color.primary.opacity(0.85) }
        if hovering { return Color.primary.opacity(0.72) }
        return Color.primary.opacity(0.60)
    }

    private func borderWidth(pressed: Bool) -> CGFloat {
        if contrast == .increased || selected { return 2 }
        return pressed ? 1.5 : 1
    }
}
