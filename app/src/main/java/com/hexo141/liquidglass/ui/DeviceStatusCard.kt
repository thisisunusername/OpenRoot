package com.hexo141.liquidglass.ui

import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.text.BasicText
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.Shadow
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.isSpecified
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.res.stringResource
import com.hexo141.liquidglass.R
import com.kyant.backdrop.Backdrop
import com.kyant.backdrop.drawBackdrop
import com.kyant.backdrop.effects.blur
import com.kyant.backdrop.effects.lens
import com.kyant.backdrop.effects.vibrancy
import com.kyant.shapes.RoundedRectangle

/** Whether the connected kernel has a bundled profile. */
enum class SupportState {
    NotConnected,
    /** Connected, but the engine decision has not come back yet. */
    Checking,
    /** A kernel profile matches this exact build. */
    Supported,
    /** An engine can be attempted but has never succeeded on this kernel. */
    Candidate,
    Unsupported,
}

/**
 * Status card for the connected device: a large state word, the kernel release and one line of
 * detail, with a matching badge on the right. Same liquid glass material as the rest of the
 * screen, tinted by [state].
 */
@Composable
fun DeviceStatusCard(
    backdrop: Backdrop,
    state: SupportState,
    release: String,
    engineLabel: String? = null,
    modifier: Modifier = Modifier,
    surfaceColor: Color = Color.Unspecified,
) {
    val accent = when (state) {
        SupportState.Supported -> Color(0xFF4ADE80)
        SupportState.Candidate -> Color(0xFFFBBF24)
        SupportState.Unsupported -> Color(0xFFF87171)
        SupportState.NotConnected -> Color.White.copy(alpha = 0.65f)
        SupportState.Checking -> Color(0xFF7DD3FC)
    }
    val title = when (state) {
        SupportState.Supported -> stringResource(R.string.support_supported)
        SupportState.Candidate -> stringResource(R.string.support_candidate)
        SupportState.Unsupported -> stringResource(R.string.support_unsupported)
        SupportState.NotConnected -> stringResource(R.string.support_not_connected)
        SupportState.Checking -> stringResource(R.string.support_checking)
    }
    val subtitle = when (state) {
        SupportState.NotConnected -> stringResource(R.string.support_no_adbd)
        SupportState.Checking ->
            release.ifEmpty { stringResource(R.string.support_reading_device) }
        else -> release.ifEmpty { stringResource(R.string.support_unknown_kernel) }
    }
    val detail = when (state) {
        SupportState.Supported -> engineLabel?.let {
            stringResource(R.string.support_engine_ready, it)
        } ?: stringResource(R.string.support_payload_ready)
        SupportState.Candidate -> engineLabel?.let {
            stringResource(R.string.support_engine_unverified, it)
        } ?: stringResource(R.string.support_not_verified_yet)
        // "Last run did not root" is the honest answer for a payload that ran but produced no su:
        // the engine exists, the run failed, and retrying is the only thing left to try.
        SupportState.Unsupported -> engineLabel?.let {
            stringResource(R.string.support_engine_failed, it)
        } ?: stringResource(R.string.support_no_payload)
        SupportState.NotConnected -> stringResource(R.string.support_connect_to_check)
        SupportState.Checking -> stringResource(R.string.support_looking_for_engine)
    }

    Box(
        modifier
            .fillMaxWidth()
            .drawBackdrop(
                backdrop = backdrop,
                shape = { RoundedRectangle(24.dp) },
                effects = {
                    vibrancy()
                    blur(4f.dp.toPx())
                    lens(10f.dp.toPx(), 22f.dp.toPx())
                },
                onDrawSurface = {
                    if (surfaceColor.isSpecified) drawRect(surfaceColor)
                    // Soft tinted wash so the state reads at a glance, then a light sheen.
                    drawRect(accent.copy(alpha = 0.10f))
                    drawRect(Color.Black.copy(alpha = 0.12f))
                    drawRect(Color.White.copy(alpha = 0.06f))
                }
            )
            .padding(start = 18.dp, end = 18.dp, top = 16.dp, bottom = 16.dp)
    ) {
        Column(modifier = Modifier.align(Alignment.CenterStart)) {
            BasicText(
                text = title,
                style = TextStyle(
                    color = accent,
                    fontSize = 24.sp,
                    fontWeight = FontWeight.SemiBold,
                    shadow = statusShadow
                )
            )
            Spacer(Modifier.height(6.dp))
            BasicText(
                text = subtitle,
                style = TextStyle(
                    color = Color.White.copy(alpha = 0.88f),
                    fontSize = 12.sp,
                    lineHeight = 16.sp,
                    shadow = statusShadow
                )
            )
            Spacer(Modifier.height(4.dp))
            BasicText(
                text = detail,
                style = TextStyle(
                    color = Color.White.copy(alpha = 0.6f),
                    fontSize = 11.sp,
                    lineHeight = 15.sp,
                    shadow = statusShadow
                )
            )
        }

        StatusBadge(
            state = state,
            accent = accent,
            modifier = Modifier
                .align(Alignment.CenterEnd)
                .size(66.dp)
        )
    }
}

@Composable
private fun StatusBadge(state: SupportState, accent: Color, modifier: Modifier = Modifier) {
    // 0 -> 1 while the ring is drawn in; two revolutions end on a complete track.
    val spin = remember { Animatable(if (state == SupportState.NotConnected) 1f else 0f) }
    LaunchedEffect(state) {
        if (state == SupportState.NotConnected) {
            spin.snapTo(1f)
            return@LaunchedEffect
        }
        spin.snapTo(0f)
        spin.animateTo(1f, tween(durationMillis = 1500, easing = LinearEasing))
    }

    val animated = state != SupportState.NotConnected
    val progress = if (animated) spin.value else 1f

    Canvas(modifier) {
        val stroke = size.minDimension * 0.09f
        val inset = stroke / 2f
        val diameter = size.minDimension - stroke
        val ringTopLeft = Offset(inset, inset)
        val ringSize = Size(diameter, diameter)
        val w = size.width
        val h = size.height

        // Faint track, then the bright arc sweeps around it twice and ends as a full ring.
        drawArc(
            color = accent.copy(alpha = 0.25f),
            startAngle = 0f,
            sweepAngle = 360f,
            useCenter = false,
            topLeft = ringTopLeft,
            size = ringSize,
            style = Stroke(width = stroke)
        )
        // The leading edge turns twice while the arc grows, so the track ends up complete.
        drawArc(
            color = accent,
            startAngle = -90f + 720f * progress,
            sweepAngle = 360f * progress,
            useCenter = false,
            topLeft = ringTopLeft,
            size = ringSize,
            style = Stroke(width = stroke, cap = StrokeCap.Round)
        )

        val glyph = accent
        val glyphStroke = Stroke(width = stroke * 1.1f, cap = StrokeCap.Round)
        when (state) {
            SupportState.Supported -> {
                val path = Path().apply {
                    moveTo(w * 0.30f, h * 0.52f)
                    lineTo(w * 0.44f, h * 0.66f)
                    lineTo(w * 0.72f, h * 0.36f)
                }
                drawPath(path = path, color = glyph, style = glyphStroke)
            }

            SupportState.Unsupported -> {
                val path = Path().apply {
                    moveTo(w * 0.36f, h * 0.36f)
                    lineTo(w * 0.64f, h * 0.64f)
                    moveTo(w * 0.64f, h * 0.36f)
                    lineTo(w * 0.36f, h * 0.64f)
                }
                drawPath(path = path, color = glyph, style = glyphStroke)
            }

            SupportState.Candidate -> {
                // Question mark: the engine can run but nobody has proved it on this kernel.
                val path = Path().apply {
                    moveTo(w * 0.40f, h * 0.40f)
                    cubicTo(w * 0.40f, h * 0.28f, w * 0.62f, h * 0.28f, w * 0.62f, h * 0.42f)
                    cubicTo(w * 0.62f, h * 0.52f, w * 0.50f, h * 0.52f, w * 0.50f, h * 0.62f)
                }
                drawPath(path = path, color = glyph, style = glyphStroke)
                drawCircle(
                    color = glyph,
                    radius = stroke * 0.55f,
                    center = Offset(w * 0.50f, h * 0.73f)
                )
            }

            SupportState.Checking, SupportState.NotConnected -> {
                drawLine(
                    color = glyph,
                    start = Offset(w * 0.36f, h * 0.5f),
                    end = Offset(w * 0.64f, h * 0.5f),
                    strokeWidth = stroke * 1.1f,
                    cap = StrokeCap.Round
                )
            }
        }
    }
}

private val statusShadow = Shadow(
    color = Color.Black.copy(alpha = 0.45f),
    offset = Offset(0f, 1f),
    blurRadius = 6f
)
