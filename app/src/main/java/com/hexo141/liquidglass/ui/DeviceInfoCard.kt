package com.hexo141.liquidglass.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.BasicText
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shadow
import androidx.compose.ui.graphics.isSpecified
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.res.stringResource
import com.hexo141.liquidglass.device.DeviceInfo
import com.hexo141.liquidglass.R
import com.kyant.backdrop.Backdrop
import com.kyant.backdrop.drawBackdrop
import com.kyant.backdrop.effects.blur
import com.kyant.backdrop.effects.lens
import com.kyant.backdrop.effects.vibrancy
import com.kyant.shapes.RoundedRectangle

/**
 * Device identity, split into individual liquid glass tiles instead of one dense list:
 * device/chip side by side, then the (long) kernel string and the SELinux mode full width.
 *
 * Every tile reuses the refraction chain of [LiquidGlassButton] (`vibrancy -> blur -> lens`) so
 * the whole screen looks cut from the same sheet of glass.
 *
 * @param info details read over ADB; {@code null} while there is no connection yet, in which case
 *        a single tile shows [statusText] instead of stale local values.
 * @param backdrop layer backdrop owned by the screen; it must be drawn below these tiles.
 * @param surfaceColor optional tint used on API < 31 where RenderEffect (and therefore the
 *        refraction) is unavailable.
 */
@Composable
fun DeviceInfoCards(
    backdrop: Backdrop,
    info: DeviceInfo?,
    statusText: String,
    modifier: Modifier = Modifier,
    surfaceColor: Color = Color.Unspecified,
) {
    Column(
        modifier,
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        if (info == null) {
            InfoTile(
                label = stringResource(R.string.label_adb),
                value = statusText,
                backdrop = backdrop,
                surfaceColor = surfaceColor,
                modifier = Modifier.fillMaxWidth()
            )
            return@Column
        }
        Row(
            modifier = Modifier.height(IntrinsicSize.Min),
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            InfoTile(
                label = stringResource(R.string.label_device),
                value = info.deviceName,
                backdrop = backdrop,
                surfaceColor = surfaceColor,
                modifier = Modifier
                    .weight(1f)
                    .fillMaxHeight()
            )
            InfoTile(
                label = stringResource(R.string.label_chip),
                value = info.chipset,
                backdrop = backdrop,
                surfaceColor = surfaceColor,
                modifier = Modifier
                    .weight(1f)
                    .fillMaxHeight()
            )
        }
        Row(
            modifier = Modifier.height(IntrinsicSize.Min),
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            InfoTile(
                label = stringResource(R.string.label_android),
                value = info.androidVersion,
                backdrop = backdrop,
                surfaceColor = surfaceColor,
                modifier = Modifier
                    .weight(1f)
                    .fillMaxHeight()
            )
            InfoTile(
                label = stringResource(R.string.label_selinux),
                value = info.selinux,
                backdrop = backdrop,
                surfaceColor = surfaceColor,
                modifier = Modifier
                    .weight(1f)
                    .fillMaxHeight()
            )
        }
        InfoTile(
            label = stringResource(R.string.label_gpu),
            value = info.gpu,
            backdrop = backdrop,
            surfaceColor = surfaceColor,
            modifier = Modifier.fillMaxWidth()
        )
        InfoTile(
            label = stringResource(R.string.label_kernel),
            value = info.kernel,
            backdrop = backdrop,
            surfaceColor = surfaceColor,
            monospace = true,
            modifier = Modifier.fillMaxWidth()
        )
    }
}

@Composable
private fun InfoTile(
    label: String,
    value: String,
    backdrop: Backdrop,
    surfaceColor: Color,
    modifier: Modifier = Modifier,
    monospace: Boolean = false,
) {
    Column(
        modifier
            .drawBackdrop(
                backdrop = backdrop,
                shape = { RoundedRectangle(22.dp) },
                effects = {
                    vibrancy()
                    blur(4f.dp.toPx())
                    lens(10f.dp.toPx(), 22f.dp.toPx())
                },
                onDrawSurface = {
                    if (surfaceColor.isSpecified) {
                        drawRect(surfaceColor)
                    }
                    // On a bright wallpaper pure refraction washes the text out: add a faint dark
                    // layer under the highlight.
                    drawRect(Color.Black.copy(alpha = 0.22f))
                    drawRect(Color.White.copy(alpha = 0.08f))
                }
            )
            .padding(horizontal = 16.dp, vertical = 12.dp)
    ) {
        // Large label, small value: the same hierarchy as a settings group header.
        BasicText(
            text = label,
            style = TextStyle(
                color = Color.White.copy(alpha = 0.95f),
                fontSize = 19.sp,
                fontWeight = FontWeight.SemiBold,
                shadow = textShadow
            )
        )
        Spacer(Modifier.height(3.dp))
        BasicText(
            text = value,
            style = TextStyle(
                color = Color.White.copy(alpha = 0.8f),
                fontSize = if (monospace) 11.sp else 12.sp,
                fontFamily = if (monospace) FontFamily.Monospace else FontFamily.Default,
                lineHeight = if (monospace) 15.sp else 16.sp,
                shadow = textShadow
            )
        )
    }
}

private val textShadow = Shadow(
    color = Color.Black.copy(alpha = 0.45f),
    offset = Offset(0f, 1f),
    blurRadius = 6f
)
