package com.hexo141.liquidglass.ui

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicText
import androidx.compose.foundation.verticalScroll
import androidx.compose.ui.draw.clip
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shadow
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.isSpecified
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.kyant.backdrop.Backdrop
import com.kyant.backdrop.drawBackdrop
import com.kyant.backdrop.effects.blur
import com.kyant.backdrop.effects.lens
import com.kyant.backdrop.effects.vibrancy
import com.kyant.shapes.RoundedRectangle

/** One row of the engine picker. Disabled rows stay visible and explain why they cannot run. */
data class ExploitChoice(
    val id: String,
    val title: String,
    val detail: String,
    val enabled: Boolean = true,
)

/**
 * Engine picker shown above the main screen when the exploit button is tapped.
 *
 * It lives inside the same composition instead of a Dialog so the rows keep refracting the
 * wallpaper like every other surface. Opening fades the scrim in and scales the card up from 92%;
 * closing runs the same animation backwards before the node leaves the tree.
 */
@Composable
fun EnginePicker(
    visible: Boolean,
    backdrop: Backdrop,
    choices: List<ExploitChoice>,
    onPick: (String) -> Unit,
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier,
    surfaceColor: Color = Color.Unspecified,
) {
    val progress by animateFloatAsState(
        targetValue = if (visible) 1f else 0f,
        animationSpec = tween(durationMillis = if (visible) 220 else 160),
        label = "engine-picker"
    )
    if (!visible && progress <= 0.01f) return

    Box(
        modifier
            .fillMaxSize()
            .background(Color.Black.copy(alpha = 0.5f * progress))
            .clickable(
                enabled = visible,
                indication = null,
                interactionSource = null,
                onClick = onDismiss
            ),
        contentAlignment = Alignment.Center
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 24.dp)
                .graphicsLayer {
                    val scale = 0.92f + 0.08f * progress
                    scaleX = scale
                    scaleY = scale
                    translationY = (1f - progress) * 28.dp.toPx()
                }
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
                        drawRect(Color.Black.copy(alpha = 0.82f))
                        drawRect(Color.White.copy(alpha = 0.05f))
                    }
                )
                .padding(vertical = 18.dp, horizontal = 18.dp)
        ) {
            BasicText(
                text = "Select vulnerability",
                style = TextStyle(
                    color = Color.White.copy(alpha = 0.95f),
                    fontSize = 19.sp,
                    fontWeight = FontWeight.SemiBold,
                    shadow = pickerShadow
                )
            )
            Spacer(Modifier.height(12.dp))
            // Every engine is listed, including the ones that cannot run, because the reason is the
            // useful part. Five rows do not fit on a short screen, so the list scrolls inside a
            // capped height while the title and Cancel stay put - otherwise the last rows sit below
            // the fold with nothing hinting that they exist.
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(max = 420.dp)
                    .verticalScroll(rememberScrollState())
            ) {
                choices.forEach { choice ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable(enabled = choice.enabled) { onPick(choice.id) }
                            .padding(vertical = 11.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(Modifier.weight(1f)) {
                            BasicText(
                                text = choice.title,
                                style = TextStyle(
                                    color = Color.White.copy(alpha = if (choice.enabled) 1f else 0.45f),
                                    fontSize = 15.sp,
                                    fontWeight = FontWeight.Medium,
                                    shadow = pickerShadow
                                )
                            )
                            Spacer(Modifier.height(3.dp))
                            BasicText(
                                text = choice.detail,
                                style = TextStyle(
                                    color = Color.White.copy(alpha = if (choice.enabled) 0.62f else 0.35f),
                                    fontSize = 11.sp,
                                    lineHeight = 15.sp,
                                    shadow = pickerShadow
                                )
                            )
                        }
                        Spacer(Modifier.width(12.dp))
                        if (choice.enabled) {
                            PickerButton(text = "Run") { onPick(choice.id) }
                        } else {
                            BasicText(
                                text = "Unavailable",
                                style = TextStyle(
                                    color = Color.White.copy(alpha = 0.3f),
                                    fontSize = 13.sp,
                                    shadow = pickerShadow
                                )
                            )
                        }
                    }
                }
            }
            Spacer(Modifier.height(4.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.End
            ) {
                PickerButton(text = "Cancel", onClick = onDismiss)
            }
        }
    }
}

/** Blue capsule, same accent as the exploit button, sized to its label. */
@Composable
private fun PickerButton(text: String, onClick: () -> Unit) {
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(percent = 50))
            .background(ExploitAccent)
            .clickable(onClick = onClick)
            .padding(horizontal = 18.dp, vertical = 9.dp)
    ) {
        BasicText(
            text = text,
            style = TextStyle(
                color = Color.White,
                fontSize = 13.sp,
                fontWeight = FontWeight.Medium
            )
        )
    }
}

private val pickerShadow = Shadow(
    color = Color.Black.copy(alpha = 0.45f),
    offset = Offset(0f, 1f),
    blurRadius = 6f
)

private val ExploitAccent = Color(0xFF0A84FF)
