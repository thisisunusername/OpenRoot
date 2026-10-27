package com.hexo141.liquidglass.ui

import android.content.Context
import android.content.Intent
import android.graphics.BitmapFactory
import android.net.Uri
import android.os.Build
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.BasicText
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.Shadow
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.isSpecified
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.hexo141.liquidglass.R
import com.kyant.backdrop.Backdrop
import com.kyant.backdrop.drawBackdrop
import com.kyant.backdrop.effects.blur
import com.kyant.backdrop.effects.lens
import com.kyant.backdrop.effects.vibrancy
import com.kyant.shapes.RoundedRectangle
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import org.json.JSONArray
import org.json.JSONObject
import java.net.URL
import kotlin.math.absoluteValue

/**
 * About tab: what the app is, the build number, the people behind it and the repository link,
 * on the same glass material as the rest of the app.
 *
 * The contributor row never grows past the card: [ContributorRow] measures itself and collapses
 * the extra people into a "+N" bubble, so the avatars cannot push the layout off screen.
 */
@Composable
fun AboutScreen(
    backdrop: Backdrop,
    modifier: Modifier = Modifier
) {
    val surfaceColor =
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) Color.Black.copy(alpha = 0.3f)
        else Color.Unspecified

    val context = LocalContext.current

    val installedVersion = remember(context) { installedVersionName(context) }
    // The badge only exists when GitHub publishes a release newer than this build.
    val update by produceState<AppUpdate?>(initialValue = null, installedVersion) {
        value = UpdateChecker.check(installedVersion)
    }

    fun openUrl(url: String) {
        runCatching {
            context.startActivity(
                Intent(Intent.ACTION_VIEW, Uri.parse(url)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            )
        }
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .windowInsetsPadding(WindowInsets.safeDrawing)
            .verticalScroll(rememberScrollState())
            .padding(start = 20.dp, end = 20.dp, top = 12.dp, bottom = BottomBarSpace + 16.dp)
    ) {
        BasicText(
            text = "About",
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
        Spacer(Modifier.height(14.dp))
        Column(
            Modifier
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
                        drawRect(Color.Black.copy(alpha = 0.14f))
                        drawRect(Color.White.copy(alpha = 0.06f))
                    }
                )
                .padding(horizontal = 18.dp, vertical = 16.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                BasicText(
                    text = "OpenRoot",
                    style = TextStyle(
                        color = Color.White,
                        fontSize = 22.sp,
                        fontWeight = FontWeight.SemiBold,
                        shadow = aboutShadow
                    )
                )
                if (installedVersion.isNotEmpty()) {
                    Spacer(Modifier.width(8.dp))
                    BasicText(
                        text = installedVersion,
                        style = TextStyle(
                            color = Color.White.copy(alpha = 0.6f),
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Medium,
                            shadow = aboutShadow
                        )
                    )
                }
                update?.let { available ->
                    Spacer(Modifier.width(10.dp))
                    UpdateBadge(onClick = { openUrl(available.url) })
                }
            }
            Spacer(Modifier.height(10.dp))
            listOf(
                "Wireless ADB pairing, no cable and no PC.",
                "Or Shizuku: no pairing code at all, just grant access.",
                "Runs a temporary root payload on supported kernels."
            ).forEach { line ->
                BasicText(
                    text = line,
                    style = TextStyle(
                        color = Color.White.copy(alpha = 0.85f),
                        fontSize = 12.sp,
                        lineHeight = 17.sp,
                        shadow = aboutShadow
                    )
                )
                Spacer(Modifier.height(6.dp))
            }

            Spacer(Modifier.height(6.dp))
            BasicText(
                text = "Contributors",
                style = TextStyle(
                    color = Color.White.copy(alpha = 0.62f),
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Medium
                )
            )
            Spacer(Modifier.height(8.dp))
            // Ask the GitHub API once; the row falls back to the project owner when offline.
            val contributors by produceState(initialValue = GitHubContributors.fallback) {
                value = GitHubContributors.load()
            }
            ContributorRow(
                contributors = contributors,
                onOpen = { openUrl("https://github.com/$it") }
            )
            Spacer(Modifier.height(16.dp))

            LiquidGlassButton(
                onClick = { openUrl(ABOUT_URL) },
                backdrop = backdrop,
                surfaceColor = surfaceColor,
                height = 46.dp,
                horizontalPadding = 22.dp,
                modifier = Modifier.fillMaxWidth()
            ) {
                BasicText(
                    text = "Open on GitHub",
                    style = TextStyle(
                        color = Color.White,
                        fontSize = 15.sp,
                        shadow = aboutShadow
                    )
                )
            }
        }
        Spacer(Modifier.height(12.dp))
        BasicText(
            text = "Use it only on hardware you own.",
            style = TextStyle(
                color = Color.White.copy(alpha = 0.55f),
                fontSize = 11.sp,
                shadow = aboutShadow
            )
        )
    }
}

/**
 * Overlapping avatar stack that fits the available width: it asks for at most as many circles as
 * fit, and folds the rest into a "+N" bubble instead of overflowing.
 */
@Composable
private fun ContributorRow(
    contributors: List<Contributor>,
    onOpen: (String) -> Unit,
    modifier: Modifier = Modifier
) {
    if (contributors.isEmpty()) return
    BoxWithConstraints(modifier.fillMaxWidth()) {
        val avatarSize = 40.dp
        // Overlap of 10dp: the visible step between two avatars is 30dp.
        val step = 30.dp
        val slots = (((maxWidth - avatarSize) / step).toInt() + 1)
            .coerceIn(1, contributors.size)
        val hidden = contributors.size - slots

        Box(
            Modifier
                .width(step * (slots - 1) + avatarSize)
                .height(avatarSize)
        ) {
            val visible = if (hidden > 0) contributors.take(slots - 1) else contributors
            visible.forEachIndexed { index, contributor ->
                ContributorAvatar(
                    contributor = contributor,
                    modifier = Modifier
                        .offset(x = step * index)
                        .size(avatarSize)
                        .clickable { onOpen(contributor.login) }
                )
            }
            if (hidden > 0) {
                Box(
                    modifier = Modifier
                        .offset(x = step * (slots - 1))
                        .size(avatarSize)
                        .clip(CircleShape)
                        .background(Color.Black.copy(alpha = 0.35f))
                        .border(1.5.dp, Color.White.copy(alpha = 0.28f), CircleShape),
                    contentAlignment = Alignment.Center
                ) {
                    BasicText(
                        text = "+${hidden + 1}",
                        style = TextStyle(
                            color = Color.White.copy(alpha = 0.92f),
                            fontSize = 12.sp,
                            fontWeight = FontWeight.SemiBold
                        )
                    )
                }
            }
        }
    }
}

/** One round GitHub avatar with a ring; falls back to the initial when the image cannot load. */
@Composable
private fun ContributorAvatar(contributor: Contributor, modifier: Modifier = Modifier) {
    val login = contributor.login
    val avatar by produceState<ImageBitmap?>(initialValue = null, contributor.avatarUrl) {
        value = AvatarCache.load(contributor.avatarUrl)
    }
    val fallback = remember(login) { avatarColor(login) }

    Box(
        modifier
            .clip(CircleShape)
            .background(fallback)
            .border(1.5.dp, Color.White.copy(alpha = 0.28f), CircleShape),
        contentAlignment = Alignment.Center
    ) {
        val bitmap = avatar
        if (bitmap != null) {
            Image(
                bitmap = bitmap,
                contentDescription = login,
                contentScale = ContentScale.Crop,
                modifier = Modifier.fillMaxSize()
            )
        } else {
            BasicText(
                text = login.take(1).uppercase(),
                style = TextStyle(
                    color = Color.White,
                    fontSize = 15.sp,
                    fontWeight = FontWeight.SemiBold
                )
            )
        }
    }
}

/** One GitHub account from the contributors endpoint. */
private data class Contributor(val login: String, val avatarUrl: String)

/** Blue circular badge shown beside the title while a newer release exists. */
@Composable
private fun UpdateBadge(onClick: () -> Unit, modifier: Modifier = Modifier) {
    Box(
        modifier = modifier
            .size(28.dp)
            .clip(CircleShape)
            .background(updateBlue)
            .border(1.dp, Color.White.copy(alpha = 0.35f), CircleShape)
            .clickable(onClick = onClick),
        contentAlignment = Alignment.Center
    ) {
        Image(
            painter = painterResource(R.drawable.ic_arrow_up),
            contentDescription = "Download update",
            modifier = Modifier.size(15.dp)
        )
    }
}

/** The APK's own version, written by Gradle as `vYYYYMMDD`. */
@Suppress("DEPRECATION")
private fun installedVersionName(context: Context): String =
    runCatching {
        context.packageManager.getPackageInfo(context.packageName, 0).versionName
    }.getOrNull().orEmpty()

/** One newer release: its tag (`vYYYYMMDD`) and where tapping the badge should go. */
private data class AppUpdate(val version: String, val url: String)

/**
 * Latest release of this fork, from `GET /repos/thisisunusername/OpenRoot/releases/latest`.
 *
 * Gradle stamps the APK with the build date and CI publishes the same date as the tag, so a
 * numeric tag comparison is an exact update test. The answer is cached for a few minutes, and a
 * failed request simply hides the badge until the next check.
 *
 * Pointing this at upstream would be wrong: this build carries the Shizuku transport, which
 * upstream does not, so every upstream release would look like a downgrade-free update.
 */
private object UpdateChecker {
    private const val LATEST_RELEASE_URL =
        "https://api.github.com/repos/thisisunusername/OpenRoot/releases/latest"
    private const val CHECK_INTERVAL_MS = 10 * 60 * 1000L

    @Volatile
    private var checkedAt = 0L

    @Volatile
    private var latest: AppUpdate? = null

    suspend fun check(installedVersion: String): AppUpdate? {
        val installed = versionNumber(installedVersion) ?: return null
        val now = System.currentTimeMillis()
        if (now - checkedAt > CHECK_INTERVAL_MS) {
            latest = withContext(Dispatchers.IO) {
                runCatching { fetchLatest() }
                    .onFailure { android.util.Log.w("About", "release request failed", it) }
                    .getOrNull()
            }
            checkedAt = now
        }
        val update = latest ?: return null
        val version = versionNumber(update.version) ?: return null
        return update.takeIf { version > installed }
    }

    private fun fetchLatest(): AppUpdate? {
        val connection = URL(LATEST_RELEASE_URL).openConnection() as HttpURLConnection
        connection.connectTimeout = 6_000
        connection.readTimeout = 6_000
        connection.setRequestProperty("User-Agent", "OpenRoot")
        connection.setRequestProperty("Accept", "application/vnd.github+json")
        val code = connection.responseCode
        val stream = if (code in 200..299) connection.inputStream else connection.errorStream
        val body = stream?.bufferedReader()?.use { it.readText() }.orEmpty()
        connection.disconnect()
        if (code !in 200..299) return null

        val release = JSONObject(body)
        val tag = release.optString("tag_name")
        if (tag.isEmpty()) return null
        // Prefer the APK asset so the badge downloads the update in one tap.
        val assets = release.optJSONArray("assets")
        var apkUrl: String? = null
        if (assets != null) {
            for (index in 0 until assets.length()) {
                val asset = assets.optJSONObject(index) ?: continue
                if (asset.optString("name").endsWith(".apk", ignoreCase = true)) {
                    apkUrl = asset.optString("browser_download_url").takeIf { it.isNotEmpty() }
                    break
                }
            }
        }
        val url = apkUrl ?: release.optString("html_url")
        if (url.isEmpty()) return null
        return AppUpdate(tag, url)
    }

    /** Build dates are `vYYYYMMDD`; other tags cannot be ordered against the installed build. */
    private fun versionNumber(version: String): Int? =
        Regex("""(\d{8})""").find(version)?.groupValues?.get(1)?.toIntOrNull()
}

/**
 * Contributors of the repository, from `GET /repos/hexo141/OpenRoot/contributors`.
 *
 * The result is kept for the process lifetime (60 unauthenticated requests an hour is plenty for
 * one load) and the owner is used when the request cannot be made, so the row is never empty.
 */
private object GitHubContributors {
    val fallback = listOf(Contributor("hexo141", "https://github.com/hexo141.png?size=144"))

    @Volatile
    private var cache: List<Contributor>? = null

    suspend fun load(): List<Contributor> {
        cache?.let { return it }
        val fetched = withContext(Dispatchers.IO) {
            runCatching { fetch() }
                .onFailure { android.util.Log.w("About", "contributors request failed", it) }
                .getOrNull()
        }
        val list = fetched?.takeIf { it.isNotEmpty() } ?: cache ?: fallback
        cache = list
        return list
    }

    private fun fetch(): List<Contributor> {
        val connection = URL(CONTRIBUTORS_URL).openConnection() as HttpURLConnection
        connection.connectTimeout = 6_000
        connection.readTimeout = 6_000
        connection.setRequestProperty("User-Agent", "OpenRoot")
        connection.setRequestProperty("Accept", "application/vnd.github+json")
        val code = connection.responseCode
        val stream = if (code in 200..299) connection.inputStream else connection.errorStream
        val body = stream?.bufferedReader()?.use { it.readText() }.orEmpty()
        connection.disconnect()
        if (code !in 200..299) return emptyList()

        val array = JSONArray(body)
        return buildList {
            for (index in 0 until array.length()) {
                val item = array.optJSONObject(index) ?: continue
                val login = item.optString("login")
                val avatar = item.optString("avatar_url")
                if (login.isNotEmpty() && avatar.isNotEmpty()) add(Contributor(login, avatar))
            }
        }
    }
}

/** Deterministic fallback colour per login, so the circles look intentional while loading. */
private fun avatarColor(login: String): Color {
    val palette = listOf(
        Color(0xFF3B82F6),
        Color(0xFF8B5CF6),
        Color(0xFFEC4899),
        Color(0xFFF59E0B),
        Color(0xFF10B981),
        Color(0xFF06B6D4),
        Color(0xFFEF4444)
    )
    return palette[login.hashCode().absoluteValue % palette.size]
}

/**
 * Tiny avatar loader: one HTTPS request per login, kept in memory for the process lifetime.
 * No image library, no disk cache - a failed load simply leaves the initial in place.
 */
private object AvatarCache {
    private val entries = HashMap<String, ImageBitmap?>()

    suspend fun load(url: String): ImageBitmap? {
        synchronized(entries) {
            if (entries.containsKey(url)) return entries[url]
        }
        val bitmap = withContext(Dispatchers.IO) {
            runCatching {
                val connection = URL(url).openConnection() as HttpURLConnection
                connection.connectTimeout = 5_000
                connection.readTimeout = 5_000
                connection.instanceFollowRedirects = true
                val bytes = connection.inputStream.use { it.readBytes() }
                connection.disconnect()
                BitmapFactory.decodeByteArray(bytes, 0, bytes.size)?.asImageBitmap()
            }.getOrNull()
        }
        synchronized(entries) { entries[url] = bitmap }
        return bitmap
    }
}

private val updateBlue = Color(0xFF0A84FF)

private val aboutShadow = Shadow(
    color = Color.Black.copy(alpha = 0.45f),
    offset = Offset(0f, 1f),
    blurRadius = 6f
)

private const val ABOUT_URL = "https://github.com/thisisunusername/OpenRoot"
private const val CONTRIBUTORS_URL =
    "https://api.github.com/repos/thisisunusername/OpenRoot/contributors?per_page=100"
