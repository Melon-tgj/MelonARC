import SwiftUI

enum LayoutMetrics {
    static let pageInset: CGFloat = 24
    static let sheetInset: CGFloat = 24
    static let sectionGap: CGFloat = 24

    static let headerGap: CGFloat = 16
    static let cardGap: CGFloat = 16
    static let cardInset: CGFloat = 16

    static let rowInsetX: CGFloat = 12
    static let statusGap: CGFloat = 12
    static let formGap: CGFloat = 12

    static let rowInsetY: CGFloat = 8
    static let fieldGap: CGFloat = 8
    static let actionGap: CGFloat = 8

    static let detailGap: CGFloat = 4

    static let cardOuterInset: CGFloat = 0
    static let listOuterInsetWithinPage: CGFloat = 0

    static let threeColumnThreshold: CGFloat = 872
    static let overviewColumnWidth: CGFloat = 280
    static let infoLabelWidth: CGFloat = 120

    enum Sidebar {
        static let minWidth: CGFloat = 208
        static let idealWidth: CGFloat = 236
        static let maxWidth: CGFloat = 304
        static let inset: CGFloat = 16
        static let minimumGap: CGFloat = 12
        static let maximumGap: CGFloat = 24
        static let cornerRadius: CGFloat = 10
        static let labelLeading: CGFloat = 20
        static let labelTrailing: CGFloat = 12
        static let labelVertical: CGFloat = 8
        static let iconColumn: CGFloat = 24
        static let iconGap: CGFloat = 8
        static let checkSlot: CGFloat = 16
        static let markerWidth: CGFloat = 3
        static let markerHeight: CGFloat = 24
        static let markerInset: CGFloat = 8

        static func limits(for size: SidebarRowSize) -> (minimum: CGFloat, maximum: CGFloat, icon: CGFloat) {
            switch size {
            case .small:
                return (48, 64, 16)
            case .large:
                return (64, 80, 20)
            case .medium:
                return (56, 72, 18)
            @unknown default:
                return (56, 72, 18)
            }
        }
    }

    enum Sheet {
        static let minWidth: CGFloat = 448
        static let minHeight: CGFloat = 240
        static let defaultWidth: CGFloat = 520
        static let defaultHeight: CGFloat = 248
        static let expandedHeight: CGFloat = 288
        static let maxWidth: CGFloat = 640
        static let maxHeight: CGFloat = 480
        static let labelColumn: CGFloat = 120
        static let minimumInputWidth: CGFloat = 240
        static let controlHeight: CGFloat = 28
    }
}

extension View {
    func panelPageInsets() -> some View {
        padding(.horizontal, LayoutMetrics.pageInset)
            .padding(.vertical, LayoutMetrics.pageInset)
    }
}
