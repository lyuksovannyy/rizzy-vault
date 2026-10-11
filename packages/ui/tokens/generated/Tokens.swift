// SPDX-License-Identifier: AGPL-3.0-only

// GENERATED FILE — do not edit by hand. Source: packages/ui/tokens/tokens.json;
// regenerate with `cargo xtask generate-tokens` (ADR 0014 §5, ADR 0019 §13).

// No client in this repository consumes this file yet (ADR 0019 §6); it exists so
// the release workflow can ship it in the token bundle (ADR 0019 §7) once that
// client repository exists.

import SwiftUI

/// Design tokens generated from the platform-neutral source (ADR 0014 §5).
public enum RizzyTokens {
    public struct ColorPalette {
        public let bg: Color
        public let surface: Color
        public let border: Color
        public let text: Color
        public let textMuted: Color
        public let accent: Color
        public let onAccent: Color
        public let danger: Color
        public let onDanger: Color
        public let warningBg: Color
        public let warningText: Color
        public let focus: Color
    }

    public static let light = ColorPalette(bg: Color(hex: "#f7f7f8"), surface: Color(hex: "#ffffff"), border: Color(hex: "#c9cad1"), text: Color(hex: "#17181c"), textMuted: Color(hex: "#4d505b"), accent: Color(hex: "#2f4fd6"), onAccent: Color(hex: "#ffffff"), danger: Color(hex: "#b3261e"), onDanger: Color(hex: "#ffffff"), warningBg: Color(hex: "#fff4d6"), warningText: Color(hex: "#4a3500"), focus: Color(hex: "#2f4fd6"))
    public static let dark = ColorPalette(bg: Color(hex: "#121317"), surface: Color(hex: "#1c1d23"), border: Color(hex: "#3b3d47"), text: Color(hex: "#ececf1"), textMuted: Color(hex: "#b4b6c2"), accent: Color(hex: "#8fa6ff"), onAccent: Color(hex: "#0b1030"), danger: Color(hex: "#ffb4ab"), onDanger: Color(hex: "#410002"), warningBg: Color(hex: "#3a2c00"), warningText: Color(hex: "#ffe08a"), focus: Color(hex: "#8fa6ff"))

    // Spacing, type and radius keep the web source's own CSS unit as a string (module
    // docs on `generate-tokens` in crates/xtask/src/tokens.rs).
    public static let space1 = "0.25rem"
    public static let space2 = "0.5rem"
    public static let space3 = "0.75rem"
    public static let space4 = "1rem"
    public static let space6 = "1.5rem"
    public static let space8 = "2rem"
    public static let fontBody = "system-ui, -apple-system, \"Segoe UI\", Roboto, sans-serif"
    public static let fontMono = "ui-monospace, \"SF Mono\", Menlo, Consolas, monospace"
    public static let fontSizeSmall = "0.875rem"
    public static let fontSizeBody = "1rem"
    public static let fontSizeTitle = "1.375rem"
    public static let radius1 = "4px"
    public static let radius2 = "8px"

    public struct ShadowPalette {
        public let shadow1: String
        public let shadow2: String
    }
    public static let shadowLight = ShadowPalette(shadow1: "0 1px 2px rgba(0, 0, 0, 0.12)", shadow2: "0 4px 12px rgba(0, 0, 0, 0.16)")
    public static let shadowDark = ShadowPalette(shadow1: "0 1px 2px rgba(0, 0, 0, 0.4)", shadow2: "0 4px 16px rgba(0, 0, 0, 0.55)")
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
