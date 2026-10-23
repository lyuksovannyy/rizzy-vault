// SPDX-License-Identifier: AGPL-3.0-only

// GENERATED FILE — do not edit by hand. Source: packages/ui/tokens/tokens.json;
// regenerate with `cargo xtask generate-tokens` (ADR 0014 §5, ADR 0019 §13).

// No client in this repository consumes this file yet (ADR 0019 §6); it exists so
// the release workflow can ship it in the token bundle (ADR 0019 §7) once that
// client repository exists.

package com.rizzyvault.tokens

import androidx.compose.animation.core.CubicBezierEasing
import androidx.compose.ui.graphics.Color

/** Design tokens generated from the platform-neutral source (ADR 0014 §5). */
object RizzyTokens {
    data class ColorPalette(
        val bg: Color,
        val surface: Color,
        val surfaceRaised: Color,
        val surfaceHover: Color,
        val border: Color,
        val borderStrong: Color,
        val text: Color,
        val textMuted: Color,
        val accent: Color,
        val accentHover: Color,
        val accentSubtle: Color,
        val onAccent: Color,
        val danger: Color,
        val onDanger: Color,
        val success: Color,
        val onSuccess: Color,
        val warningBg: Color,
        val warningText: Color,
        val focus: Color,
    )

    val light = ColorPalette(bg = Color(0xFFF4F5F8), surface = Color(0xFFFFFFFF), surfaceRaised = Color(0xFFFFFFFF), surfaceHover = Color(0xFFECEEF3), border = Color(0xFFDCDFE6), borderStrong = Color(0xFF858B99), text = Color(0xFF14161B), textMuted = Color(0xFF525866), accent = Color(0xFF4051D8), accentHover = Color(0xFF3242C2), accentSubtle = Color(0xFFE8EBFF), onAccent = Color(0xFFFFFFFF), danger = Color(0xFFC0271D), onDanger = Color(0xFFFFFFFF), success = Color(0xFF147A4A), onSuccess = Color(0xFFFFFFFF), warningBg = Color(0xFFFFF3D1), warningText = Color(0xFF4A3500), focus = Color(0xFF4051D8))
    val dark = ColorPalette(bg = Color(0xFF0E1014), surface = Color(0xFF161920), surfaceRaised = Color(0xFF1E222B), surfaceHover = Color(0xFF232833), border = Color(0xFF2B303B), borderStrong = Color(0xFF6F7686), text = Color(0xFFECEEF3), textMuted = Color(0xFFA8AEBB), accent = Color(0xFF8E9AFF), accentHover = Color(0xFFA9B2FF), accentSubtle = Color(0xFF252B4F), onAccent = Color(0xFF0A0F33), danger = Color(0xFFFF9E94), onDanger = Color(0xFF3B0400), success = Color(0xFF6AD49C), onSuccess = Color(0xFF00341B), warningBg = Color(0xFF3A2C00), warningText = Color(0xFFFFE08A), focus = Color(0xFF8E9AFF))

    // Spacing, type and radius keep the web source's own CSS unit as a string (module
    // docs on `generate-tokens` in crates/xtask/src/tokens.rs).
    const val space1 = "0.25rem"
    const val space2 = "0.5rem"
    const val space3 = "0.75rem"
    const val space4 = "1rem"
    const val space5 = "1.25rem"
    const val space6 = "1.5rem"
    const val space8 = "2rem"
    const val space10 = "2.5rem"
    const val space12 = "3rem"
    const val fontBody = "system-ui, -apple-system, \"Segoe UI\", Roboto, sans-serif"
    const val fontMono = "ui-monospace, \"SF Mono\", Menlo, Consolas, monospace"
    const val fontSizeCaption = "0.75rem"
    const val fontSizeSmall = "0.875rem"
    const val fontSizeBody = "1rem"
    const val fontSizeHeading = "1.125rem"
    const val fontSizeTitle = "1.375rem"
    const val fontSizeDisplay = "1.75rem"
    const val fontWeightRegular = "400"
    const val fontWeightMedium = "500"
    const val fontWeightSemibold = "600"
    const val lineHeightTight = "1.25"
    const val lineHeightBody = "1.5"
    const val radius1 = "6px"
    const val radius2 = "10px"
    const val radius3 = "14px"
    const val radiusFull = "999px"

    data class ShadowPalette(
        val shadow1: String,
        val shadow2: String,
        val shadow3: String,
    )
    val shadowLight = ShadowPalette(shadow1 = "0 1px 2px rgba(16, 20, 32, 0.06), 0 1px 3px rgba(16, 20, 32, 0.08)", shadow2 = "0 2px 4px rgba(16, 20, 32, 0.06), 0 8px 20px rgba(16, 20, 32, 0.1)", shadow3 = "0 4px 8px rgba(16, 20, 32, 0.08), 0 20px 48px rgba(16, 20, 32, 0.18)")
    val shadowDark = ShadowPalette(shadow1 = "0 1px 2px rgba(0, 0, 0, 0.5)", shadow2 = "0 2px 6px rgba(0, 0, 0, 0.45), 0 8px 24px rgba(0, 0, 0, 0.4)", shadow3 = "0 6px 12px rgba(0, 0, 0, 0.45), 0 24px 56px rgba(0, 0, 0, 0.55)")

    // Motion (docs/design/README.md "Motion"): durations in milliseconds (Swift: seconds),
    // easings as cubic-Bezier control points (x1, y1, x2, y2). Under the platform's reduce-motion
    // setting use motionDurationReduced for every transition, as a crossfade only: no distance,
    // scale, stagger or loop.
    const val motionDurationInstant: Int = 90
    const val motionDurationFast: Int = 150
    const val motionDurationBase: Int = 220
    const val motionDurationSlow: Int = 320
    const val motionDurationShimmer: Int = 1400
    const val motionDurationReduced: Int = 120
    val motionEasingStandard = CubicBezierEasing(0.2f, 0f, 0f, 1f)
    val motionEasingEmphasized = CubicBezierEasing(0.16f, 1f, 0.3f, 1f)
    val motionEasingDecelerate = CubicBezierEasing(0f, 0f, 0.2f, 1f)
    val motionEasingAccelerate = CubicBezierEasing(0.4f, 0f, 1f, 1f)
    const val motionDistance1 = "4px"
    const val motionDistance2 = "8px"
    const val motionDistance3 = "16px"
    const val motionScaleEnter: Float = 0.96f
    const val motionScalePress: Float = 0.97f
    const val motionStaggerStep: Int = 30
    const val motionStaggerMaxItems: Int = 8
    const val motionLoopMaxIterations: Int = 3
}
