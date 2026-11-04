package com.hexo141.liquidglass.ui

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
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shadow
import androidx.compose.ui.graphics.isSpecified
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.kyant.backdrop.Backdrop
import com.kyant.backdrop.drawBackdrop
import com.kyant.backdrop.effects.blur
import com.kyant.backdrop.effects.lens
import com.kyant.backdrop.effects.vibrancy

/**
 * Chooses which KernelSU-family manager the payload should hand off to, and lets the user point at
 * a `ksud` the resolver would never derive.
 *
 * Automatic detection stays the default; this screen only exists for the two cases detection cannot
 * cover — a fork whose package name is not in the built-in list, and a `ksud` that is not the
 * manager's own `libksud.so`. Both fields are free-form on purpose: guessing at the set of forks is
 * exactly what the override is there to avoid.
 */
@Composable
fun ManagerPicker(
    backdrop: Backdrop,
    surfaceColor: Color,
    /** Package currently in use, or the empty string when automatic detection is on. */
    packageName: String,
    /** `ksud` path currently in use, or the empty string to let the app derive it. */
    ksudPath: String,
    /** What detection found on its own, shown so an empty field is not mistaken for "nothing". */
    detected: String,
    onSave: (packageName: String, ksudPath: String) -> Unit,
    onDismiss: () -> Unit,
) {
    val pickerShadow = Shadow(color = Color.Black.copy(alpha = 0.45f), offset = androidx.compose.ui.geometry.Offset(0f, 1f), blurRadius = 3f)
    var pkg by remember { mutableStateOf(packageName) }
    var ksud by remember { mutableStateOf(ksudPath) }

    Box(
        modifier = Modifier.fillMaxSize().clickable(onClick = onDismiss),
        contentAlignment = Alignment.Center,
    ) {
        Column(
            modifier = Modifier
                .padding(horizontal = 24.dp)
                .drawBackdrop(
                    backdrop = backdrop,
                    shape = { RoundedCornerShape(24.dp) },
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
                .clickable(enabled = false) {}
        ) {
            BasicText(
                text = "KernelSU manager",
                style = TextStyle(
                    color = Color.White.copy(alpha = 0.95f),
                    fontSize = 19.sp,
                    fontWeight = FontWeight.SemiBold,
                    shadow = pickerShadow,
                ),
            )
            Spacer(Modifier.height(6.dp))
            BasicText(
                text = if (detected.isEmpty()) {
                    "Nothing detected on this device."
                } else {
                    "Detected: $detected"
                },
                style = TextStyle(
                    color = Color.White.copy(alpha = 0.55f),
                    fontSize = 11.sp,
                    lineHeight = 15.sp,
                    shadow = pickerShadow,
                ),
            )
            Spacer(Modifier.height(14.dp))

            Field(
                label = "Package name",
                hint = "leave empty for automatic detection",
                value = pkg,
                onValueChange = { pkg = it },
                keyboardType = KeyboardType.Ascii,
                shadow = pickerShadow,
            )
            Spacer(Modifier.height(12.dp))
            Field(
                label = "ksud path",
                hint = "/data/adb/ksu/bin/ksud",
                value = ksud,
                onValueChange = { ksud = it },
                keyboardType = KeyboardType.Ascii,
                shadow = pickerShadow,
            )

            Spacer(Modifier.height(16.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.End,
            ) {
                // Clearing both fields is the way back to automatic detection, so it is a first-class
                // action rather than something the user has to infer from empty inputs.
                PickerButton(text = "Auto") { onSave("", "") }
                Spacer(Modifier.width(10.dp))
                PickerButton(text = "Save") { onSave(pkg.trim(), ksud.trim()) }
            }
            Spacer(Modifier.height(4.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.End,
            ) {
                PickerButton(text = "Cancel", onClick = onDismiss)
            }
        }
    }
}

/** One labelled text field; scrolling is capped so a long path stays visible on a short screen. */
@Composable
private fun Field(
    label: String,
    hint: String,
    value: String,
    onValueChange: (String) -> Unit,
    keyboardType: KeyboardType,
    shadow: Shadow,
) {
    Column(Modifier.fillMaxWidth()) {
        BasicText(
            text = label,
            style = TextStyle(
                color = Color.White.copy(alpha = 0.85f),
                fontSize = 13.sp,
                fontWeight = FontWeight.Medium,
                shadow = shadow,
            ),
        )
        Spacer(Modifier.height(6.dp))
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = 40.dp)
                .clip(RoundedCornerShape(10.dp))
                .background(Color.White.copy(alpha = 0.08f))
                .padding(horizontal = 12.dp, vertical = 10.dp),
        ) {
            if (value.isEmpty()) {
                BasicText(
                    text = hint,
                    style = TextStyle(
                        color = Color.White.copy(alpha = 0.28f),
                        fontSize = 12.sp,
                        shadow = shadow,
                    ),
                )
            }
            BasicTextField(
                value = value,
                onValueChange = onValueChange,
                textStyle = TextStyle(
                    color = Color.White.copy(alpha = 0.95f),
                    fontSize = 12.sp,
                ),
                keyboardOptions = KeyboardOptions(keyboardType = keyboardType),
                modifier = Modifier.fillMaxWidth(),
            )
        }
    }
}

/** Blue capsule, same accent as the exploit button, sized to its label. */
@Composable
private fun PickerButton(text: String, onClick: () -> Unit) {
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(percent = 50))
            .background(Color(0xFF0A84FF))
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 8.dp),
    ) {
        BasicText(
            text = text,
            style = TextStyle(
                color = Color.White,
                fontSize = 13.sp,
                fontWeight = FontWeight.Medium,
            ),
        )
    }
}