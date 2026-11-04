package com.hexo141.liquidglass.ui

import android.os.Handler
import android.os.Looper
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicText
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shadow
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.res.stringResource
import com.hexo141.liquidglass.R
import com.hexo141.liquidglass.consent.LicenseText

/**
 * First-start gate: two documents, accepted one after the other, with a progress bar on top.
 *
 * Step 1 is the GNU GPL v3.0 that covers the source; it is fetched from two mirrors in parallel
 * (see [LicenseText]) and falls back to the bundled copy, so the screen never needs the network to
 * show the licence. Step 2 is the temporary-root disclaimer, which ships in the APK.
 *
 * The flow is strictly sequential: step 2 is not reachable until step 1 is accepted, and the main
 * screen is not composed at all until [onAccept] fires.
 */
@Composable
fun ConsentScreen(
    onAccept: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current

    /** 0 = licence, 1 = disclaimer. Never jumps forward without the previous acceptance. */
    var step by remember { mutableStateOf(0) }
    var license by remember { mutableStateOf<LicenseText.Loaded?>(null) }
    var licenseAccepted by remember { mutableStateOf(false) }
    var disclaimerAccepted by remember { mutableStateOf(false) }

    val disclaimer = remember {
        runCatching {
            context.assets.open(DISCLAIMER_ASSET).bufferedReader().use { it.readText() }
        }.getOrDefault("")
    }

    // Blocking download on a worker thread; the UI shows the loading line meanwhile.
    LaunchedEffect(Unit) {
        if (license != null) return@LaunchedEffect
        Thread({
            val loaded = LicenseText.load(context)
            Handler(Looper.getMainLooper()).post { license = loaded }
        }, "gpl-fetch").start()
    }

    val onLicenseStep = step == 0
    val document = if (onLicenseStep) license?.text.orEmpty() else disclaimer
    val lines = remember(document) { document.lines() }
    val acceptedHere = if (onLicenseStep) licenseAccepted else disclaimerAccepted
    val readyHere = if (onLicenseStep) license != null else disclaimer.isNotEmpty()

    val progress by animateFloatAsState(
        targetValue = if (onLicenseStep) 0.5f else 1f,
        animationSpec = tween(durationMillis = 320),
        label = "consent-progress"
    )

    Box(modifier.fillMaxSize()) {
        Image(
            painter = painterResource(R.drawable.bg),
            contentDescription = null,
            contentScale = ContentScale.Crop,
            modifier = Modifier.fillMaxSize()
        )
        Box(Modifier.fillMaxSize().background(Color.Black.copy(alpha = 0.74f)))

        Column(
            modifier = Modifier
                .fillMaxSize()
                // The wallpaper runs edge to edge; the content stays clear of both bars.
                .windowInsetsPadding(WindowInsets.safeDrawing)
                .padding(start = 20.dp, end = 20.dp, top = 12.dp, bottom = 16.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                BasicText(
                    text = stringResource(R.string.app_name),
                    style = TextStyle(
                        color = Color.White,
                        fontSize = 26.sp,
                        fontWeight = FontWeight.SemiBold,
                        shadow = Shadow(Color.Black.copy(alpha = 0.45f), Offset(0f, 2f), 8f)
                    )
                )
                Spacer(Modifier.weight(1f))
                BasicText(
                    text = "Step ${step + 1} of 2",
                    style = TextStyle(
                        color = Color.White.copy(alpha = 0.6f),
                        fontSize = 12.sp
                    )
                )
            }
            Spacer(Modifier.height(8.dp))

            // Progress bar: half way after the licence, full after the disclaimer.
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(3.dp)
                    .clip(RoundedCornerShape(2.dp))
                    .background(Color.White.copy(alpha = 0.14f))
            ) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth(progress)
                        .fillMaxHeight()
                        .clip(RoundedCornerShape(2.dp))
                        .background(ConsentAccent)
                )
            }
            Spacer(Modifier.height(12.dp))

            BasicText(
                text = if (onLicenseStep) {
                    "Document 1 of 2 · licence of this software"
                } else {
                    "Document 2 of 2 · what temporary root means for your device"
                },
                style = TextStyle(
                    color = Color.White.copy(alpha = 0.72f),
                    fontSize = 12.sp,
                    lineHeight = 16.sp
                )
            )
            Spacer(Modifier.height(10.dp))

            // key(step) gives each document its own scroll position, starting at the top.
            key(step) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(1f)
                        .clip(RoundedCornerShape(18.dp))
                        .background(Color.White.copy(alpha = 0.06f))
                        .border(1.dp, Color.White.copy(alpha = 0.12f), RoundedCornerShape(18.dp))
                        .padding(horizontal = 14.dp, vertical = 12.dp)
                ) {
                    BasicText(
                        text = if (onLicenseStep) {
                            stringResource(R.string.consent_gpl_title)
                        } else {
                            stringResource(R.string.consent_disclaimer_title)
                        },
                        style = TextStyle(
                            color = Color.White.copy(alpha = 0.92f),
                            fontSize = 12.sp,
                            fontWeight = FontWeight.SemiBold,
                            lineHeight = 16.sp
                        )
                    )
                    BasicText(
                        text = when {
                            !onLicenseStep -> stringResource(R.string.consent_license_hint)
                            license == null -> "Fetching the licence text from both mirrors…"
                            else -> "Text source: ${license?.source}"
                        },
                        style = TextStyle(
                            color = Color.White.copy(alpha = 0.5f),
                            fontSize = 10.sp,
                            lineHeight = 13.sp
                        )
                    )
                    Spacer(Modifier.height(8.dp))
                    if (document.isEmpty()) {
                        Spacer(Modifier.weight(1f))
                    } else {
                        LazyColumn(modifier = Modifier.fillMaxWidth().weight(1f)) {
                            items(lines) { line ->
                                BasicText(
                                    text = line.ifEmpty { " " },
                                    style = TextStyle(
                                        color = Color.White.copy(alpha = 0.8f),
                                        fontSize = 10.sp,
                                        lineHeight = 14.sp,
                                        fontFamily = FontFamily.Monospace
                                    )
                                )
                            }
                        }
                    }
                    Spacer(Modifier.height(6.dp))
                    CheckRow(
                        checked = acceptedHere,
                        enabled = readyHere,
                        label = if (onLicenseStep) {
                            stringResource(R.string.consent_accept_gpl)
                        } else {
                            stringResource(R.string.consent_accept_disclaimer)
                        },
                        onChecked = {
                            if (onLicenseStep) licenseAccepted = it else disclaimerAccepted = it
                        },
                    )
                }
            }

            Spacer(Modifier.height(12.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                if (!onLicenseStep) {
                    Box(
                        modifier = Modifier
                            .height(48.dp)
                            .clip(RoundedCornerShape(percent = 50))
                            .background(Color.White.copy(alpha = 0.12f))
                            .clickable { step = 0 }
                            .padding(horizontal = 20.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        BasicText(
                            text = stringResource(R.string.consent_back),
                            style = TextStyle(
                                color = Color.White.copy(alpha = 0.85f),
                                fontSize = 14.sp,
                                fontWeight = FontWeight.Medium
                            )
                        )
                    }
                }
                Box(
                    modifier = Modifier
                        .weight(1f)
                        .height(48.dp)
                        .clip(RoundedCornerShape(percent = 50))
                        .background(if (acceptedHere) ConsentAccent else Color.White.copy(alpha = 0.14f))
                        .clickable(enabled = acceptedHere) {
                            if (onLicenseStep) {
                                step = 1
                            } else {
                                onAccept()
                            }
                        },
                    contentAlignment = Alignment.Center
                ) {
                    BasicText(
                        text = if (onLicenseStep) stringResource(R.string.consent_continue)
                            else stringResource(R.string.consent_accept_and_continue),
                        style = TextStyle(
                            color = Color.White.copy(alpha = if (acceptedHere) 1f else 0.45f),
                            fontSize = 15.sp,
                            fontWeight = FontWeight.Medium
                        )
                    )
                }
            }
            Spacer(Modifier.height(6.dp))
            BasicText(
                text = if (onLicenseStep) {
                    stringResource(R.string.consent_need_license_first)
                } else {
                    stringResource(R.string.consent_stored_locally)
                },
                style = TextStyle(
                    color = Color.White.copy(alpha = 0.45f),
                    fontSize = 10.sp,
                    lineHeight = 13.sp
                )
            )
        }
    }
}

private const val DISCLAIMER_ASSET = "licenses/temporary-root-disclaimer.txt"

private val ConsentAccent = Color(0xFF0A84FF)

/** Square checkbox drawn by hand; the app does not pull in Material for anything else. */
@Composable
private fun CheckRow(
    checked: Boolean,
    enabled: Boolean,
    label: String,
    onChecked: (Boolean) -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(10.dp))
            .clickable(enabled = enabled) { onChecked(!checked) }
            .padding(vertical = 8.dp, horizontal = 2.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(
            modifier = Modifier
                .size(18.dp)
                .clip(RoundedCornerShape(5.dp))
                .background(if (checked) ConsentAccent else Color.Transparent)
                .border(
                    1.5.dp,
                    if (checked) ConsentAccent else Color.White.copy(alpha = 0.4f),
                    RoundedCornerShape(5.dp)
                ),
            contentAlignment = Alignment.Center
        ) {
            if (checked) {
                BasicText(
                    text = "✓",
                    style = TextStyle(
                        color = Color.White,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold
                    )
                )
            }
        }
        Spacer(Modifier.width(10.dp))
        BasicText(
            text = label,
            style = TextStyle(
                color = Color.White.copy(alpha = if (enabled) 0.9f else 0.4f),
                fontSize = 12.sp,
                lineHeight = 16.sp
            )
        )
    }
}
