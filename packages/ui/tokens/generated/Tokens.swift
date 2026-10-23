// SPDX-License-Identifier: AGPL-3.0-only

// GENERATED FILE — do not edit by hand. Source: packages/ui/tokens/tokens.json;
// regenerate with `cargo xtask generate-tokens` (ADR 0014 §5, ADR 0019 §13).

// No client in this repository consumes this file yet (ADR 0019 §6); it exists so
// the release workflow can ship it in the token bundle (ADR 0019 §7) once that
// client repository exists.

import Foundation
import SwiftUI

/// Design tokens generated from the platform-neutral source (ADR 0014 §5).
public enum RizzyTokens {
    public struct ColorPalette {
        public let bg: Color
        public let surface: Color
        public let surfaceRaised: Color
        public let surfaceHover: Color
        public let border: Color
        public let borderStrong: Color
        public let text: Color
        public let textMuted: Color
        public let accent: Color
        public let accentHover: Color
        public let accentSubtle: Color
        public let onAccent: Color
        public let danger: Color
        public let onDanger: Color
        public let success: Color
        public let onSuccess: Color
        public let warningBg: Color
        public let warningText: Color
        public let focus: Color
    }

    public static let light = ColorPalette(bg: Color(hex: "#f4f5f8"), surface: Color(hex: "#ffffff"), surfaceRaised: Color(hex: "#ffffff"), surfaceHover: Color(hex: "#eceef3"), border: Color(hex: "#dcdfe6"), borderStrong: Color(hex: "#858b99"), text: Color(hex: "#14161b"), textMuted: Color(hex: "#525866"), accent: Color(hex: "#4051d8"), accentHover: Color(hex: "#3242c2"), accentSubtle: Color(hex: "#e8ebff"), onAccent: Color(hex: "#ffffff"), danger: Color(hex: "#c0271d"), onDanger: Color(hex: "#ffffff"), success: Color(hex: "#147a4a"), onSuccess: Color(hex: "#ffffff"), warningBg: Color(hex: "#fff3d1"), warningText: Color(hex: "#4a3500"), focus: Color(hex: "#4051d8"))
    public static let dark = ColorPalette(bg: Color(hex: "#0e1014"), surface: Color(hex: "#161920"), surfaceRaised: Color(hex: "#1e222b"), surfaceHover: Color(hex: "#232833"), border: Color(hex: "#2b303b"), borderStrong: Color(hex: "#6f7686"), text: Color(hex: "#eceef3"), textMuted: Color(hex: "#a8aebb"), accent: Color(hex: "#8e9aff"), accentHover: Color(hex: "#a9b2ff"), accentSubtle: Color(hex: "#252b4f"), onAccent: Color(hex: "#0a0f33"), danger: Color(hex: "#ff9e94"), onDanger: Color(hex: "#3b0400"), success: Color(hex: "#6ad49c"), onSuccess: Color(hex: "#00341b"), warningBg: Color(hex: "#3a2c00"), warningText: Color(hex: "#ffe08a"), focus: Color(hex: "#8e9aff"))

    // Spacing, type and radius keep the web source's own CSS unit as a string (module
    // docs on `generate-tokens` in crates/xtask/src/tokens.rs).
    public static let space1 = "0.25rem"
    public static let space2 = "0.5rem"
    public static let space3 = "0.75rem"
    public static let space4 = "1rem"
    public static let space5 = "1.25rem"
    public static let space6 = "1.5rem"
    public static let space8 = "2rem"
    public static let space10 = "2.5rem"
    public static let space12 = "3rem"
    public static let fontBody = "system-ui, -apple-system, \"Segoe UI\", Roboto, sans-serif"
    public static let fontMono = "ui-monospace, \"SF Mono\", Menlo, Consolas, monospace"
    public static let fontSizeCaption = "0.75rem"
    public static let fontSizeSmall = "0.875rem"
    public static let fontSizeBody = "1rem"
    public static let fontSizeHeading = "1.125rem"
    public static let fontSizeTitle = "1.375rem"
    public static let fontSizeDisplay = "1.75rem"
    public static let fontWeightRegular = "400"
    public static let fontWeightMedium = "500"
    public static let fontWeightSemibold = "600"
    public static let lineHeightTight = "1.25"
    public static let lineHeightBody = "1.5"
    public static let radius1 = "6px"
    public static let radius2 = "10px"
    public static let radius3 = "14px"
    public static let radiusFull = "999px"

    public struct ShadowPalette {
        public let shadow1: String
        public let shadow2: String
        public let shadow3: String
    }
    public static let shadowLight = ShadowPalette(shadow1: "0 1px 2px rgba(16, 20, 32, 0.06), 0 1px 3px rgba(16, 20, 32, 0.08)", shadow2: "0 2px 4px rgba(16, 20, 32, 0.06), 0 8px 20px rgba(16, 20, 32, 0.1)", shadow3: "0 4px 8px rgba(16, 20, 32, 0.08), 0 20px 48px rgba(16, 20, 32, 0.18)")
    public static let shadowDark = ShadowPalette(shadow1: "0 1px 2px rgba(0, 0, 0, 0.5)", shadow2: "0 2px 6px rgba(0, 0, 0, 0.45), 0 8px 24px rgba(0, 0, 0, 0.4)", shadow3: "0 6px 12px rgba(0, 0, 0, 0.45), 0 24px 56px rgba(0, 0, 0, 0.55)")

    // Motion (docs/design/README.md "Motion"): durations in milliseconds (Swift: seconds),
    // easings as cubic-Bezier control points (x1, y1, x2, y2). Under the platform's reduce-motion
    // setting use motionDurationReduced for every transition, as a crossfade only: no distance,
    // scale, stagger or loop.
    public static let motionDurationInstant: TimeInterval = 0.09
    public static let motionDurationFast: TimeInterval = 0.15
    public static let motionDurationBase: TimeInterval = 0.22
    public static let motionDurationSlow: TimeInterval = 0.32
    public static let motionDurationShimmer: TimeInterval = 1.4
    public static let motionDurationReduced: TimeInterval = 0.12
    public static let motionEasingStandard: (Double, Double, Double, Double) = (0.2, 0, 0, 1)
    public static let motionEasingEmphasized: (Double, Double, Double, Double) = (0.16, 1, 0.3, 1)
    public static let motionEasingDecelerate: (Double, Double, Double, Double) = (0, 0, 0.2, 1)
    public static let motionEasingAccelerate: (Double, Double, Double, Double) = (0.4, 0, 1, 1)
    public static let motionDistance1 = "4px"
    public static let motionDistance2 = "8px"
    public static let motionDistance3 = "16px"
    public static let motionScaleEnter: Double = 0.96
    public static let motionScalePress: Double = 0.97
    public static let motionStaggerStep: TimeInterval = 0.03
    public static let motionStaggerMaxItems = 8
    public static let motionLoopMaxIterations = 3
}

/// Builds a `Color` from a `#rrggbb` string; the source only emits that form.
extension Color {
    init(hex: String) {
        let digits = hex.trimmingCharacters(in: CharacterSet(charactersIn: "#"))
        var value: UInt64 = 0
        Scanner(string: digits).scanHexInt64(&value)
        self.init(red: Double((value & 0xFF0000) >> 16) / 255,
                  green: Double((value & 0x00FF00) >> 8) / 255,
                  blue: Double(value & 0x0000FF) / 255)
    }
}
