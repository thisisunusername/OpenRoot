package com.hexo141.liquidglass.consent

import android.content.Context
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.Executors
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

/**
 * Loads the GNU GPL v3.0 text shown on the first start.
 *
 * Two mirrors are requested **at the same time** and the first usable answer wins, so a slow or
 * blocked mirror costs nothing but the other request's timeout. The copy shipped in
 * `assets/licenses/gpl-3.0.txt` is the last resort: the licence has to be readable even with no
 * network at all, and it is the exact text that covers this source tree.
 */
object LicenseText {
    /** The text plus where it came from, so the screen can say which copy is on display. */
    data class Loaded(val text: String, val source: String)

    const val MIRROR_GNU = "https://gnu.net.cn/licenses/gpl-3.0.txt"
    const val MIRROR_REPO =
        "https://raw.githubusercontent.com/thisisunusername/OpenRoot/refs/heads/main/LICENSE"

    private const val ASSET = "licenses/gpl-3.0.txt"
    private const val CONNECT_TIMEOUT_MS = 4_000
    private const val READ_TIMEOUT_MS = 6_000
    private const val WAIT_MS = 7_000L

    /** GPL-3.0 is ~35 KB; anything much shorter is an error page, not the licence. */
    private const val MIN_LENGTH = 20_000

    private const val LABEL_GNU = "gnu.net.cn"
    private const val LABEL_REPO = "github.com/thisisunusername/OpenRoot"
    private const val LABEL_BUNDLED = "bundled copy"

    /** Blocking: call from a worker thread. Never throws, always returns a usable text. */
    fun load(context: Context): Loaded = fastestMirror() ?: bundled(context)

    private fun fastestMirror(): Loaded? {
        val results = LinkedBlockingQueue<Loaded>()
        val pool = Executors.newFixedThreadPool(2)
        try {
            listOf(MIRROR_GNU to LABEL_GNU, MIRROR_REPO to LABEL_REPO).forEach { (url, label) ->
                pool.execute {
                    val text = runCatching { download(url) }.getOrNull() ?: return@execute
                    if (looksLikeLicense(text)) results.offer(Loaded(text, label))
                }
            }
            return results.poll(WAIT_MS, TimeUnit.MILLISECONDS)
        } finally {
            // The loser is cut off instead of being waited for.
            pool.shutdownNow()
        }
    }

    private fun bundled(context: Context): Loaded {
        val text = runCatching {
            context.assets.open(ASSET).bufferedReader().use { it.readText() }
        }.getOrDefault("")
        return Loaded(text, LABEL_BUNDLED)
    }

    private fun download(url: String): String? {
        val connection = (URL(url).openConnection() as HttpURLConnection).apply {
            connectTimeout = CONNECT_TIMEOUT_MS
            readTimeout = READ_TIMEOUT_MS
            instanceFollowRedirects = true
            requestMethod = "GET"
            setRequestProperty("Accept", "text/plain")
            setRequestProperty("User-Agent", "OpenRoot")
        }
        try {
            if (connection.responseCode != HttpURLConnection.HTTP_OK) return null
            return connection.inputStream.use { it.readBytes() }.toString(Charsets.UTF_8)
        } finally {
            runCatching { connection.disconnect() }
        }
    }

    private fun looksLikeLicense(text: String): Boolean =
        text.length >= MIN_LENGTH &&
            text.contains("GNU GENERAL PUBLIC LICENSE") &&
            text.contains("Version 3")
}
