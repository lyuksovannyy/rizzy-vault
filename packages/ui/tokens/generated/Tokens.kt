// SPDX-License-Identifier: AGPL-3.0-only

// GENERATED FILE — do not edit by hand. Source: packages/ui/tokens/tokens.json;
// regenerate with `cargo xtask generate-tokens` (ADR 0014 §5, ADR 0019 §13).

// No client in this repository consumes this file yet (ADR 0019 §6); it exists so
// the release workflow can ship it in the token bundle (ADR 0019 §7) once that
// client repository exists.

package com.rizzyvault.tokens

import androidx.compose.ui.graphics.Color

/** Design tokens generated from the platform-neutral source (ADR 0014 §5). */
object RizzyTokens {
    data class ColorPalette(
        val bg: Color,
        val surface: Color,
        val border: Color,
        val text: Color,
        val textMuted: Color,
        val accent: Color,
        val onAccent: Color,
        val danger: Color,
        val onDanger: Color,
        val warningBg: Color,
        val warningText: Color,
        val focus: Color,
    )

    val light = ColorPalette(bg = Color(0xFFF7F7F8), surface = Color(0xFFFFFFFF), border = Color(0xFFC9CAD1), text = Color(0xFF17181C), textMuted = Color(0xFF4D505B), accent = Color(0xFF2F4FD6), onAccent = Color(0xFFFFFFFF), danger = Color(0xFFB3261E), onDanger = Color(0xFFFFFFFF), warningBg = Color(0xFFFFF4D6), warningText = Color(0xFF4A3500), focus = Color(0xFF2F4FD6))
    val dark = ColorPalette(bg = Color(0xFF121317), surface = Color(0xFF1C1D23), border = Color(0xFF3B3D47), text = Color(0xFFECECF1), textMuted = Color(0xFFB4B6C2), accent = Color(0xFF8FA6FF), onAccent = Color(0xFF0B1030), danger = Color(0xFFFFB4AB), onDanger = Color(0xFF410002), warningBg = Color(0xFF3A2C00), warningText = Color(0xFFFFE08A), focus = Color(0xFF8FA6FF))

    // Spacing, type and radius keep the web source's own CSS unit as a string (module
    // docs on `generate-tokens` in crates/xtask/src/tokens.rs).
    const val space1 = "0.25rem"
    const val space2 = "0.5rem"
    const val space3 = "0.75rem"
    const val space4 = "1rem"
    const val space6 = "1.5rem"
    const val space8 = "2rem"
    const val fontBody = "system-ui, -apple-system, \"Segoe UI\", Roboto, sans-serif"
    const val fontMono = "ui-monospace, \"SF Mono\", Menlo, Consolas, monospace"
    const val fontSizeSmall = "0.875rem"
    const val fontSizeBody = "1rem"
    const val fontSizeTitle = "1.375rem"
    const val radius1 = "4px"
    const val radius2 = "8px"

    data class ShadowPalette(
        val shadow1: String,
        val shadow2: String,
    )
    val shadowLight = ShadowPalette(shadow1 = "0 1px 2px rgba(0, 0, 0, 0.12)", shadow2 = "0 4px 12px rgba(0, 0, 0, 0.16)")
    val shadowDark = ShadowPalette(shadow1 = "0 1px 2px rgba(0, 0, 0, 0.4)", shadow2 = "0 4px 16px rgba(0, 0, 0, 0.55)")
}
