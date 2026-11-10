package com.hexo141.liquidglass.root

import com.hexo141.liquidglass.adb.AbsAdbConnectionManager
import com.hexo141.liquidglass.adb.AdbShell

/**
 * The two Magisk managers this app can put on a device, and why there are two.
 *
 * Both APKs ship with the same package name (`com.topjohnwu.magisk`), so a device can only hold one
 * of them at a time: installing the other one replaces it. That is why this is a *choice* and not a
 * bundle, and why [install] is told explicitly which one to put down.
 *
 * **Legacy (`manager-v8.0.4`)** pairs with the Magisk 20.4 payload that the MediaTek path deploys to
 * `/sbin` (`mtk-easy-su`'s `magisk-boot.sh` + `magiskinit`). A modern manager refuses to talk to a
 * Magisk this old and nags to "update" itself, and updating it on a device whose bootloader is still
 * locked leaves the user with a Magisk it can no longer bootstrap. mtk-easy-su's own instructions
 * pin manager v8.0.4 for exactly this reason, so the pairing is not cosmetic.
 *
 * **Modern (`v31.1`)** pairs with a Magisk or KernelSU deployed by a kernel exploit engine, where the
 * manager has to match the daemon it talks to.
 *
 * Sources are the official `topjohnwu/Magisk` releases. Downloads go through the same mirror the
 * KernelSU install already uses, because `github.com` is not reachable from every network this app
 * runs on.
 */
object MagiskManager {
    enum class Flavor {
        /** Pairs with the Magisk 20.4 payload the MediaTek path deploys. */
        LEGACY,

        /** Pairs with a modern Magisk / KernelSU deployed by a kernel exploit engine. */
        MODERN,
    }

    data class Release(val flavor: Flavor, val tag: String, val asset: String, val size: Long) {
        /** The name the file is staged as on the device, so the two never collide on disk. */
        val stagedName: String get() = "magisk-${flavor.name.lowercase()}.apk"

        val remotePath: String get() = "$STAGE_DIR/$stagedName"
    }

    val LEGACY = Release(Flavor.LEGACY, "manager-v8.0.4", "MagiskManager-v8.0.4.apk", 3_191_190L)
    val MODERN = Release(Flavor.MODERN, "v31.1", "Magisk-v31.1.apk", 10_679_283L)

    fun releaseOf(flavor: Flavor): Release = when (flavor) {
        Flavor.LEGACY -> LEGACY
        Flavor.MODERN -> MODERN
    }

    /** Package name both releases use; kept as a constant so callers never hard-code it. */
    const val PACKAGE = "com.topjohnwu.magisk"

    private const val REPO = "topjohnwu/Magisk"
    private const val STAGE_DIR = "/data/local/tmp/openroot"

    /**
     * Which flavor a payload just deployed should be matched with.
     *
     * The MediaTek payload loads Magisk 20.4 into `/sbin`, which only the legacy manager understands.
     * Everything else follows whatever manager the KernelSU/Magisk daemon reports.
     */
    fun flavorFor(payload: RootHandoff.Payload): Flavor = when (payload) {
        RootHandoff.Payload.MEDIATEK -> Flavor.LEGACY
        RootHandoff.Payload.KERNEL_SU,
        RootHandoff.Payload.MAGISK,
        RootHandoff.Payload.COMMAND,
        RootHandoff.Payload.NONE -> Flavor.MODERN
    }

    /** What is actually installed right now, as far as the shell user can tell. */
    data class Installed(val present: Boolean, val versionCode: Int, val versionName: String) {
        val flavor: Flavor? get() = when {
            !present -> null
            // v8.0.4 is versionCode 4768; anything in the modern line is far above that.
            versionCode < 10_000 -> Flavor.LEGACY
            else -> Flavor.MODERN
        }
    }

    /**
     * Reads the installed manager.
     *
     * `dumpsys package` is used instead of `pm list packages` because the version is what tells the
     * two flavors apart, and it is available to the shell user without any extra permission.
     */
    fun installed(manager: AbsAdbConnectionManager, log: (String) -> Unit = {}): Installed {
        val command = "dumpsys package $PACKAGE 2>/dev/null | grep -m1 versionName; " +
            "dumpsys package $PACKAGE 2>/dev/null | grep -m1 versionCode"
        log("$ $command")
        val out = runCatching { AdbShell.exec(manager, command) }.getOrDefault("")
        if (out.isNotBlank()) log(out.trimEnd())

        if (out.isBlank() || !out.contains("versionCode")) {
            return Installed(false, 0, "")
        }
        val code = Regex("versionCode=(\\d+)").find(out)?.groupValues?.get(1)?.toIntOrNull() ?: 0
        val name = Regex("versionName=([^\\s]+)").find(out)?.groupValues?.get(1).orEmpty()
        return Installed(code > 0, code, name)
    }

    /**
     * Downloads and installs [flavor], replacing whatever `com.topjohnwu.magisk` is already there.
     *
     * The shell user only holds `INSTALL_PACKAGES` on a debuggable or userdebug build, so this is
     * attempted rather than promised and every step reports itself. When it fails the caller is told
     * where the APK was left, so the user can tap it in a file manager instead.
     */
    fun install(
        manager: AbsAdbConnectionManager,
        flavor: Flavor,
        onLine: (String) -> Unit,
    ): KsuManager.InstallResult {
        val release = releaseOf(flavor)

        val current = installed(manager, onLine)
        if (current.present && current.flavor == flavor) {
            onLine("<i> ${release.asset} is already installed (${current.versionName})")
            return KsuManager.InstallResult(true, "already installed")
        }
        if (current.present && current.flavor != flavor) {
            // Both releases share a package name, so this is a replace, not a second install.
            onLine("<w> replacing ${current.versionName} with ${release.tag}")
        }

        onLine("<i> fetching ${release.asset} (${release.size / 1024 / 1024} MB)")
        var downloaded = false
        for (url in urlsOf(release)) {
            onLine("$ curl -L -o ${release.remotePath} '$url'")
            val fetch = runCatching {
                AdbShell.exec(
                    manager,
                    "mkdir -p $STAGE_DIR && " +
                        "curl -sSL --max-time 300 -o ${release.remotePath} '$url' && " +
                        "ls -l ${release.remotePath}",
                    360_000L,
                )
            }.getOrDefault("")
            if (fetch.isNotBlank()) onLine(fetch.trimEnd())
            // A mirror that answers 404 writes an HTML page, so check the archive magic, not the size.
            val magic = runCatching {
                AdbShell.exec(manager, "head -c 2 ${release.remotePath} 2>/dev/null")
            }.getOrDefault("")
            if (!magic.startsWith("PK")) {
                onLine("<e> $url did not return an APK; trying the next mirror")
                continue
            }
            downloaded = true
            break
        }
        if (!downloaded) {
            return KsuManager.InstallResult(false, "every mirror failed; ${release.remotePath} is not an APK")
        }

        onLine("$ pm install -r ${release.remotePath}")
        val pm = runCatching {
            AdbShell.exec(manager, "pm install -r ${release.remotePath} 2>&1", 240_000L)
        }.getOrDefault("")
        if (pm.isNotBlank()) onLine(pm.trimEnd())

        val after = installed(manager, onLine)
        return when {
            pm.contains("Success") && after.present ->
                KsuManager.InstallResult(true, "installed ${after.versionName}")
            pm.contains("Success") ->
                KsuManager.InstallResult(true, "installed")
            pm.contains("INSTALL_FAILED_VERSION_DOWNGRADE") ->
                KsuManager.InstallResult(
                    false,
                    "the newer manager is installed; uninstall it first, then retry",
                )
            pm.contains("INSTALL_FAILED") ->
                KsuManager.InstallResult(
                    false,
                    pm.lineSequence().firstOrNull { it.contains("INSTALL_FAILED") }.orEmpty(),
                )
            pm.contains("Permission denied", ignoreCase = true) ||
                pm.contains("SecurityException", ignoreCase = true) ->
                KsuManager.InstallResult(
                    false,
                    "the shell user cannot install packages on this build; " +
                        "the APK is at ${release.remotePath}",
                )
            else -> KsuManager.InstallResult(
                false,
                pm.trim().ifEmpty { "pm install said nothing" } + "; APK at ${release.remotePath}",
            )
        }
    }

    /** Brings the installed manager to the foreground so the user can finish setup by hand. */
    fun launch(manager: AbsAdbConnectionManager, log: (String) -> Unit = {}): Boolean {
        val command = "monkey -p $PACKAGE -c android.intent.category.LAUNCHER 1 2>&1"
        log("$ $command")
        val out = runCatching { AdbShell.exec(manager, command) }.getOrDefault("")
        if (out.isNotBlank()) log(out.trimEnd())
        return !out.contains("No activities found", ignoreCase = true) &&
            !out.contains("monkey aborted", ignoreCase = true)
    }

    /**
     * Removes the other flavor so a downgrade can happen.
     *
     * `pm install -r` refuses to put v8.0.4 over v31.1 (`INSTALL_FAILED_VERSION_DOWNGRADE`), so
     * switching from modern to legacy has to uninstall first. Called only when the user asked for it.
     */
    fun uninstall(manager: AbsAdbConnectionManager, log: (String) -> Unit = {}): Boolean {
        val command = "pm uninstall $PACKAGE 2>&1"
        log("$ $command")
        val out = runCatching { AdbShell.exec(manager, command, 120_000L) }.getOrDefault("")
        if (out.isNotBlank()) log(out.trimEnd())
        return out.contains("Success")
    }

    /**
     * Mirrors to try, in order.
     *
     * The proxy is first because it is the one path that survives a network where `github.com` is
     * unreachable; the direct URLs are kept as a fallback for networks where the proxy is not.
     */
    private fun urlsOf(release: Release): List<String> = listOf(
        "https://v6.gh-proxy.org/https://github.com/$REPO/releases/download/${release.tag}/${release.asset}",
        "https://github.com/$REPO/releases/download/${release.tag}/${release.asset}",
    )
}
