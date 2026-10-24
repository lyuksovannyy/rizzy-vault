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
        readonly property color bg: "#f4f5f8"
        readonly property color surface: "#ffffff"
        readonly property color surfaceRaised: "#ffffff"
        readonly property color surfaceHover: "#eceef3"
        readonly property color border: "#dcdfe6"
        readonly property color borderStrong: "#858b99"
        readonly property color text: "#14161b"
        readonly property color textMuted: "#525866"
        readonly property color accent: "#4051d8"
        readonly property color accentHover: "#3242c2"
        readonly property color accentSubtle: "#e8ebff"
        readonly property color onAccent: "#ffffff"
        readonly property color danger: "#c0271d"
        readonly property color onDanger: "#ffffff"
        readonly property color success: "#147a4a"
        readonly property color onSuccess: "#ffffff"
        readonly property color warningBg: "#fff3d1"
        readonly property color warningText: "#4a3500"
        readonly property color focus: "#4051d8"
    }
    readonly property QtObject dark: QtObject {
        readonly property color bg: "#0e1014"
        readonly property color surface: "#161920"
        readonly property color surfaceRaised: "#1e222b"
        readonly property color surfaceHover: "#232833"
        readonly property color border: "#2b303b"
        readonly property color borderStrong: "#6f7686"
        readonly property color text: "#eceef3"
        readonly property color textMuted: "#a8aebb"
        readonly property color accent: "#8e9aff"
        readonly property color accentHover: "#a9b2ff"
        readonly property color accentSubtle: "#252b4f"
        readonly property color onAccent: "#0a0f33"
        readonly property color danger: "#ff9e94"
        readonly property color onDanger: "#3b0400"
        readonly property color success: "#6ad49c"
        readonly property color onSuccess: "#00341b"
        readonly property color warningBg: "#3a2c00"
        readonly property color warningText: "#ffe08a"
        readonly property color focus: "#8e9aff"
    }

    // Spacing, type and radius keep the web source's own CSS unit as a string (module
    // docs on `generate-tokens` in crates/xtask/src/tokens.rs).
    readonly property string space1: "0.25rem"
    readonly property string space2: "0.5rem"
    readonly property string space3: "0.75rem"
    readonly property string space4: "1rem"
    readonly property string space5: "1.25rem"
    readonly property string space6: "1.5rem"
    readonly property string space8: "2rem"
    readonly property string space10: "2.5rem"
    readonly property string space12: "3rem"
    readonly property string fontBody: "system-ui, -apple-system, \"Segoe UI\", Roboto, sans-serif"
    readonly property string fontMono: "ui-monospace, \"SF Mono\", Menlo, Consolas, monospace"
    readonly property string fontSizeCaption: "0.75rem"
    readonly property string fontSizeSmall: "0.875rem"
    readonly property string fontSizeBody: "1rem"
    readonly property string fontSizeHeading: "1.125rem"
    readonly property string fontSizeTitle: "1.375rem"
    readonly property string fontSizeDisplay: "1.75rem"
    readonly property string fontWeightRegular: "400"
    readonly property string fontWeightMedium: "500"
    readonly property string fontWeightSemibold: "600"
    readonly property string lineHeightTight: "1.25"
    readonly property string lineHeightBody: "1.5"
    readonly property string radius1: "6px"
    readonly property string radius2: "10px"
    readonly property string radius3: "14px"
    readonly property string radiusFull: "999px"

    readonly property QtObject shadowLight: QtObject {
        readonly property string shadow1: "0 1px 2px rgba(16, 20, 32, 0.06), 0 1px 3px rgba(16, 20, 32, 0.08)"
        readonly property string shadow2: "0 2px 4px rgba(16, 20, 32, 0.06), 0 8px 20px rgba(16, 20, 32, 0.1)"
        readonly property string shadow3: "0 4px 8px rgba(16, 20, 32, 0.08), 0 20px 48px rgba(16, 20, 32, 0.18)"
    }
    readonly property QtObject shadowDark: QtObject {
        readonly property string shadow1: "0 1px 2px rgba(0, 0, 0, 0.5)"
        readonly property string shadow2: "0 2px 6px rgba(0, 0, 0, 0.45), 0 8px 24px rgba(0, 0, 0, 0.4)"
        readonly property string shadow3: "0 6px 12px rgba(0, 0, 0, 0.45), 0 24px 56px rgba(0, 0, 0, 0.55)"
    }

    // Motion (docs/design/README.md "Motion"): durations in milliseconds (Swift: seconds),
    // easings as cubic-Bezier control points (x1, y1, x2, y2). Under the platform's reduce-motion
    // setting use motionDurationReduced for every transition, as a crossfade only: no distance,
    // scale, stagger or loop.
    readonly property int motionDurationInstant: 90
    readonly property int motionDurationFast: 150
    readonly property int motionDurationBase: 220
    readonly property int motionDurationSlow: 320
    readonly property int motionDurationShimmer: 1400
    readonly property int motionDurationReduced: 120
    readonly property var motionEasingStandard: [0.2, 0, 0, 1, 1, 1]
    readonly property var motionEasingEmphasized: [0.16, 1, 0.3, 1, 1, 1]
    readonly property var motionEasingDecelerate: [0, 0, 0.2, 1, 1, 1]
    readonly property var motionEasingAccelerate: [0.4, 0, 1, 1, 1, 1]
    readonly property string motionDistance1: "4px"
    readonly property string motionDistance2: "8px"
    readonly property string motionDistance3: "16px"
    readonly property real motionScaleEnter: 0.96
    readonly property real motionScalePress: 0.97
    readonly property int motionStaggerStep: 30
    readonly property int motionStaggerMaxItems: 8
    readonly property int motionLoopMaxIterations: 3
}
