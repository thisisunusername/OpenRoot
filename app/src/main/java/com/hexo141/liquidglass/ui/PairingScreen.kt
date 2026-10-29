package com.hexo141.liquidglass.ui

import android.os.Build
import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.text.BasicText
import androidx.compose.runtime.Composable
import androidx.compose.runtime.key
import androidx.compose.runtime.remember
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shadow
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.graphics.drawscope.withTransform
import androidx.compose.ui.graphics.vector.PathParser
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.hexo141.liquidglass.R
import com.hexo141.liquidglass.adb.ShizukuShell
import com.hexo141.liquidglass.device.DeviceInfo
import com.kyant.backdrop.Backdrop

/**
 * Main screen: full-screen wallpaper, the device cards and the centred liquid glass buttons.
 *
 * The wallpaper doubles as the refraction source for the glass, so the whole screen is one
 * ComposeView: the image is drawn through `layerBackdrop` and everything on top refracts it.
 *
 * After a successful pairing adbd already holds our public key, so the pairing button is hidden
 * entirely ([paired] true and no [needsPairing]); the screen only reconnects and shows the device.
 * The button comes back only when a direct connect fails. Once connected, **Exploit** below runs a
 * temporary root payload.
 */
@Composable
fun PairingScreen(
    running: Boolean,
    paired: Boolean,
    connecting: Boolean,
    connected: Boolean,
    needsPairing: Boolean,
    /** State of the Shizuku link; drives whether the primary button grants Shizuku or pairs. */
    shizukuStatus: ShizukuShell.Status,
    supportState: SupportState,
    engineLabel: String?,
    deviceInfo: DeviceInfo?,
    exploiting: Boolean,
    exploitLog: List<String>,
    exploitStatus: String?,
    exploitChoices: List<ExploitChoice>,
    pickerVisible: Boolean,
    backdrop: Backdrop,
    onToggle: () -> Unit,
    onExploit: () -> Unit,
    onPickEngine: (String) -> Unit,
    onDismissPicker: () -> Unit,
    onOpenLog: () -> Unit,
    modifier: Modifier = Modifier
) {
    // API < 31 has no RenderEffect, so refraction does nothing; a translucent surface keeps the
    // buttons readable on the wallpaper.
    val glassSurfaceColor =
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) Color.Black.copy(alpha = 0.3f)
        else Color.Unspecified

    // Shizuku is the preferred route: it needs no wireless debugging and no pairing code, so when
    // it is usable the ADB pairing button is never shown at all. `UNUSABLE` is the exception: the
    // grant is already in place, the server simply will not start a process, so offering the grant
    // again would be a dead end and the pairing route has to be shown instead.
    val shizukuUsable = shizukuStatus == ShizukuShell.Status.READY ||
        shizukuStatus == ShizukuShell.Status.PERMISSION_REQUIRED
    // Hidden once paired; only a failed direct connect (needsPairing) brings it back.
    // UNUSABLE overrides "paired": a Shizuku connection marks the app paired because it needs no
    // code, so leaving the flag in charge would hide the only route that still works.
    val showPairingButton = (shizukuStatus == ShizukuShell.Status.UNUSABLE ||
        !paired ||
        needsPairing) && !shizukuUsable

    val statusText = when {
        connecting -> "Connecting…"
        connected -> "Connected"
        shizukuStatus == ShizukuShell.Status.READY -> "Shizuku ready"
        shizukuStatus == ShizukuShell.Status.PERMISSION_REQUIRED -> "Shizuku access needed"
        shizukuStatus == ShizukuShell.Status.PERMISSION_DENIED -> "Shizuku access denied"
        shizukuStatus == ShizukuShell.Status.UNUSABLE -> "Shizuku cannot run commands"
        shizukuStatus == ShizukuShell.Status.NOT_RUNNING -> "Shizuku not running"
        paired -> "Waiting for adbd"
        else -> "Not paired"
    }

    Box(modifier.fillMaxSize()) {
        Column(
            modifier = Modifier
                .align(Alignment.TopStart)
                .fillMaxSize()
                // Leave room below the status bar so the title and cards sit lower.
                // The wallpaper runs edge to edge; the content stays clear of both bars, so the
                // bottom cards are never hidden behind the navigation bar.
                .windowInsetsPadding(WindowInsets.safeDrawing)
                .padding(start = 20.dp, end = 20.dp, top = 12.dp, bottom = 16.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                BasicText(
                    text = "OpenRoot",
                    style = TextStyle(
                        color = Color.White,
                        fontSize = 30.sp,
                        fontWeight = FontWeight.SemiBold,
                        shadow = Shadow(
                            color = Color.Black.copy(alpha = 0.45f),
                            offset = Offset(0f, 2f),
                            blurRadius = 8f
                        )
                    )
                )
                Spacer(Modifier.weight(1f))
                val context = LocalContext.current
                GitHubIcon(
                    modifier = Modifier
                        .size(24.dp)
                        .clickable {
                            runCatching {
                                context.startActivity(
                                    Intent(Intent.ACTION_VIEW, Uri.parse(PROJECT_URL))
                                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                                )
                            }
                        }
                )
            }
            Spacer(Modifier.height(14.dp))
            DeviceStatusCard(
                backdrop = backdrop,
                state = supportState,
                release = deviceInfo?.kernel.orEmpty(),
                engineLabel = engineLabel,
                surfaceColor = glassSurfaceColor
            )
            // Without a connection there is no trustworthy device info, so the cards stay hidden.
            if (connected && deviceInfo != null) {
                Spacer(Modifier.height(10.dp))
                DeviceInfoCards(
                    backdrop = backdrop,
                    info = deviceInfo,
                    statusText = statusText,
                    surfaceColor = glassSurfaceColor
                )
            }
            // Exploit appears only once adbd is paired and connected; without a connection the
            // payload cannot even be pushed.
            if (connected) {
                Spacer(Modifier.height(14.dp))
                LiquidGlassButton(
                    onClick = onExploit,
                    backdrop = backdrop,
                    tint = ExploitBlue,
                    surfaceColor = glassSurfaceColor,
                    height = 46.dp,
                    horizontalPadding = 22.dp,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    BasicText(
                        text = stringResource(
                            if (exploiting) R.string.exploit_running else R.string.exploit_button
                        ),
                        style = buttonTextStyle()
                    )
                }
            }
            // The log lives on its own page; this is only the way in (and the last status line).
            if (connected && (exploiting || exploitLog.isNotEmpty() || exploitStatus != null)) {
                Spacer(Modifier.height(10.dp))
                LiquidGlassButton(
                    onClick = onOpenLog,
                    backdrop = backdrop,
                    surfaceColor = glassSurfaceColor,
                    height = 46.dp,
                    horizontalPadding = 22.dp,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    BasicText(
                        text = if (exploiting) "Exploit running - open log" else "Open exploit log",
                        style = buttonTextStyle()
                    )
                }
                if (exploitStatus != null) {
                    Spacer(Modifier.height(6.dp))
                    BasicText(
                        text = exploitStatus,
                        style = TextStyle(
                            color = Color.White.copy(alpha = 0.78f),
                            fontSize = 11.sp,
                            lineHeight = 15.sp,
                            shadow = Shadow(
                                color = Color.Black.copy(alpha = 0.45f),
                                offset = Offset(0f, 1f),
                                blurRadius = 6f
                            )
                        ),
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }
            Spacer(Modifier.weight(1f))
        }

        Column(
            modifier = Modifier.align(Alignment.Center),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // One primary action: grant Shizuku when it is the transport, otherwise the pairing
            // button, which is the only route on devices that have wireless debugging.
            if (shizukuStatus == ShizukuShell.Status.PERMISSION_REQUIRED && !connected) {
                LiquidGlassButton(
                    onClick = onToggle,
                    backdrop = backdrop,
                    surfaceColor = glassSurfaceColor,
                    height = 50.dp,
                    horizontalPadding = 22.dp
                ) {
                    BasicText(
                        text = stringResource(R.string.shizuku_grant),
                        style = buttonTextStyle()
                    )
                }
            } else if (showPairingButton) {
                LiquidGlassButton(
                    onClick = onToggle,
                    backdrop = backdrop,
                    surfaceColor = glassSurfaceColor,
                    height = 50.dp,
                    horizontalPadding = 22.dp
                ) {
                    BasicText(
                        text = stringResource(
                            if (running) R.string.adb_pairing_stop_button else R.string.adb_pairing_start
                        ),
                        style = buttonTextStyle()
                    )
                }
            } else if (shizukuStatus == ShizukuShell.Status.NOT_RUNNING && !connected) {
                // Shizuku is installed but stopped; the only thing the user can do is start it.
                BasicText(
                    text = stringResource(R.string.shizuku_not_running),
                    style = TextStyle(
                        color = Color.White.copy(alpha = 0.78f),
                        fontSize = 12.sp,
                        shadow = Shadow(
                            color = Color.Black.copy(alpha = 0.45f),
                            offset = Offset(0f, 1f),
                            blurRadius = 6f
                        )
                    )
                )
            }
        }

        EnginePicker(
            visible = pickerVisible,
            backdrop = backdrop,
            choices = exploitChoices,
            onPick = onPickEngine,
            onDismiss = onDismissPicker,
            surfaceColor = glassSurfaceColor
        )

    }
}

@Composable
private fun buttonTextStyle() = TextStyle(
    color = Color.White,
    fontSize = 15.sp,
    // The wallpaper varies in brightness, so a soft shadow keeps the text readable.
    shadow = Shadow(
        color = Color.Black.copy(alpha = 0.45f),
        offset = Offset(0f, 1f),
        blurRadius = 6f
    )
)

/** Accent colour of the Exploit button. */
private val ExploitBlue = Color(0xFF0A84FF)

/** Repository link shown next to the title. */
private const val PROJECT_URL = "https://github.com/thisisunusername/OpenRoot"

/** GitHub mark, drawn straight from the source path so no extra drawable is needed. */
@Composable
private fun GitHubIcon(modifier: Modifier = Modifier) {
    val path = remember {
        PathParser().parsePathString(GITHUB_PATH).toPath().apply {
            translate(Offset(GITHUB_OFFSET_X, GITHUB_OFFSET_Y))
        }
    }
    Canvas(modifier) {
        withTransform({ scale(size.width / 20f, size.height / 20f, Offset.Zero) }) {
            drawPath(path, color = Color.White.copy(alpha = 0.9f))
        }
    }
}

private const val GITHUB_OFFSET_X = -84f
private const val GITHUB_OFFSET_Y = -7399f

private const val GITHUB_PATH =
    "M94,7399 C99.523,7399 104,7403.59 104,7409.253 C104,7413.782 101.138,7417.624 " +
        "97.167,7418.981 C96.66,7419.082 96.48,7418.762 96.48,7418.489 C96.48,7418.151 " +
        "96.492,7417.047 96.492,7415.675 C96.492,7414.719 96.172,7414.095 95.813,7413.777 " +
        "C98.04,7413.523 100.38,7412.656 100.38,7408.718 C100.38,7407.598 99.992,7406.684 " +
        "99.35,7405.966 C99.454,7405.707 99.797,7404.664 99.252,7403.252 C99.252,7403.252 " +
        "98.414,7402.977 96.505,7404.303 C95.706,7404.076 94.85,7403.962 94,7403.958 " +
        "C93.15,7403.962 92.295,7404.076 91.497,7404.303 C89.586,7402.977 88.746,7403.252 " +
        "88.746,7403.252 C88.203,7404.664 88.546,7405.707 88.649,7405.966 C88.01,7406.684 " +
        "87.619,7407.598 87.619,7408.718 C87.619,7412.646 89.954,7413.526 92.175,7413.785 " +
        "C91.889,7414.041 91.63,7414.493 91.54,7415.156 C90.97,7415.418 89.522,7415.871 " +
        "88.63,7414.304 C88.63,7414.304 88.101,7413.319 87.097,7413.247 C87.097,7413.247 " +
        "86.122,7413.234 87.029,7413.87 C87.029,7413.87 87.684,7414.185 88.139,7415.37 " +
        "C88.139,7415.37 88.726,7417.2 91.508,7416.58 C91.513,7417.437 91.522,7418.245 " +
        "91.522,7418.489 C91.522,7418.76 91.338,7419.077 90.839,7418.982 C86.865,7417.627 " +
        "84,7413.783 84,7409.253 C84,7403.59 88.478,7399 94,7399"
