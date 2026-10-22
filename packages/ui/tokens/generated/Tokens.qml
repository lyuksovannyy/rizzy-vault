// SPDX-License-Identifier: AGPL-3.0-only

// GENERATED FILE — do not edit by hand. Source: packages/ui/tokens/tokens.json;
// regenerate with `cargo xtask generate-tokens` (ADR 0014 §5, ADR 0019 §13).

// No client in this repository consumes this file yet (ADR 0019 §6); it exists so
// the release workflow can ship it in the token bundle (ADR 0019 §7) once that
// client repository exists.

pragma Singleton
import QtQml 2.15

QtObject {
    readonly property QtObject light: QtObject {
        readonly property color bg: "#f7f7f8"
        readonly property color surface: "#ffffff"
        readonly property color border: "#c9cad1"
        readonly property color text: "#17181c"
        readonly property color textMuted: "#4d505b"
        readonly property color accent: "#2f4fd6"
        readonly property color onAccent: "#ffffff"
        readonly property color danger: "#b3261e"
        readonly property color onDanger: "#ffffff"
        readonly property color warningBg: "#fff4d6"
        readonly property color warningText: "#4a3500"
        readonly property color focus: "#2f4fd6"
    }
    readonly property QtObject dark: QtObject {
        readonly property color bg: "#121317"
        readonly property color surface: "#1c1d23"
        readonly property color border: "#3b3d47"
        readonly property color text: "#ececf1"
        readonly property color textMuted: "#b4b6c2"
        readonly property color accent: "#8fa6ff"
        readonly property color onAccent: "#0b1030"
        readonly property color danger: "#ffb4ab"
        readonly property color onDanger: "#410002"
        readonly property color warningBg: "#3a2c00"
        readonly property color warningText: "#ffe08a"
        readonly property color focus: "#8fa6ff"
    }

    // Spacing, type and radius keep the web source's own CSS unit as a string (module
    // docs on `generate-tokens` in crates/xtask/src/tokens.rs).
    readonly property string space1: "0.25rem"
    readonly property string space2: "0.5rem"
    readonly property string space3: "0.75rem"
    readonly property string space4: "1rem"
    readonly property string space6: "1.5rem"
    readonly property string space8: "2rem"
    readonly property string fontBody: "system-ui, -apple-system, \"Segoe UI\", Roboto, sans-serif"
    readonly property string fontMono: "ui-monospace, \"SF Mono\", Menlo, Consolas, monospace"
    readonly property string fontSizeSmall: "0.875rem"
    readonly property string fontSizeBody: "1rem"
    readonly property string fontSizeTitle: "1.375rem"
    readonly property string radius1: "4px"
    readonly property string radius2: "8px"

    readonly property QtObject shadowLight: QtObject {
        readonly property string shadow1: "0 1px 2px rgba(0, 0, 0, 0.12)"
        readonly property string shadow2: "0 4px 12px rgba(0, 0, 0, 0.16)"
    }
    readonly property QtObject shadowDark: QtObject {
        readonly property string shadow1: "0 1px 2px rgba(0, 0, 0, 0.4)"
        readonly property string shadow2: "0 4px 16px rgba(0, 0, 0, 0.55)"
    }
}
