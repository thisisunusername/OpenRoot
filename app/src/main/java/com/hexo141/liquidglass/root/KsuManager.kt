package com.hexo141.liquidglass.root

import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.util.Log
import com.hexo141.liquidglass.adb.AbsAdbConnectionManager
import com.hexo141.liquidglass.adb.AdbShell
import java.io.File

/**
 * Locates the installed KernelSU family manager and its `ksud` binary.
 *
 * The payload late-loads `ksud` once it holds temporary root, which is what turns the temporary
 * root into a usable KernelSU.
 *
 * Resolution order:
 * 1. `find /data/app -name libksud.so` over the ADB connection. This is the reliable one: it does
 *    not depend on package visibility and it finds renamed forks.
 * 2. The built-in package list.
 * 3. Every app with a launcher icon.
 */
object KsuManager {
    private const val TAG = "KsuManager"

    /** Same set the payload looks for, in priority order. */
    val BUILTIN = listOf(
        "me.weishu.kernelsu.pr",
        "me.weishu.kernelsu",
        "com.resukisu.resukisu",
        "org.bakasu.bakasu",
        "com.kowx712.supermanager",
    )

    data class Target(
        val packageName: String,
        /** Absolute path of the manager's `libksud.so`, readable and executable by the shell user. */
        val ksudPath: String,
    )

    /**
     * @param manager live ADB connection used for the `/data/app` scan, or {@code null}
     * @param log receives the ADB commands and their output, so the UI can show what was tried
     */
    fun resolve(
        context: Context,
        manager: AbsAdbConnectionManager? = null,
        log: (String) -> Unit = {},
    ): Target? {
        if (manager != null) {
            resolveViaAdb(manager, log)?.let { return it }
        }
        return resolveViaPackageManager(context, log)
    }

    /** `find /data/app` over ADB: works for forks and ignores package visibility rules. */
    private fun resolveViaAdb(manager: AbsAdbConnectionManager, log: (String) -> Unit): Target? {
        val findCommand = "find /data/app -name libksud.so -type f 2>/dev/null"
        log("$ $findCommand")
        val found = runCatching { AdbShell.exec(manager, findCommand) }.getOrElse { error ->
            log("<e> ${error.message}")
            return null
        }
        val path = found.lineSequence()
            .map { it.trim() }
            .firstOrNull { it.endsWith("/libksud.so") }
        if (found.isNotBlank()) {
            // Real device output, exactly as the daemon printed it.
            found.trimEnd().lineSequence().forEach(log)
        }
        if (path == null) return null

        log("$ pm list packages")
        val packages = runCatching { AdbShell.exec(manager, "pm list packages") }.getOrDefault("")
        val packageName = packages.lineSequence()
            .map { it.removePrefix("package:").trim() }
            .filter { it.isNotEmpty() }
            .firstOrNull { path.contains("/$it-") }

        Log.i(TAG, "resolved via adb: ${packageName ?: "?"} -> $path")
        return Target(packageName.orEmpty(), path)
    }

    private fun resolveViaPackageManager(context: Context, log: (String) -> Unit): Target? {
        val pm = context.packageManager
        for (pkg in BUILTIN) {
            val info = runCatching { pm.getApplicationInfo(pkg, 0) }.getOrNull() ?: continue
            val ksud = ksudOf(info) ?: continue
            Log.i(TAG, "resolved builtin $pkg -> $ksud")

            return Target(pkg, ksud)
        }

        val launcherIntent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        val scanned = runCatching { pm.queryIntentActivities(launcherIntent, 0) }.getOrDefault(emptyList())
        for (entry in scanned) {
            val pkg = entry.activityInfo?.packageName ?: continue
            if (pkg == context.packageName) continue
            val info = runCatching { pm.getApplicationInfo(pkg, 0) }.getOrNull() ?: continue
            val ksud = ksudOf(info) ?: continue
            Log.i(TAG, "resolved scanned $pkg -> $ksud")

            return Target(pkg, ksud)
        }


        return null
    }

    private fun ksudOf(info: ApplicationInfo): String? {
        val dir = info.nativeLibraryDir ?: return null
        val ksud = File(dir, "libksud.so")
        return if (ksud.isFile) ksud.absolutePath else null
    }

    /**
     * Reads the manager's `libksud.so` *as this app*, not as the shell user.
     *
     * Staging ksud by running `cp` on the device is fragile: some ROMs refuse the copy outright
     * (`/system/bin/sh: shell:cp: inaccessible or not found`), and a Shizuku pipe can swallow the
     * result even when the copy works. The app already holds the bytes by virtue of the path
     * [resolve] handed out, so the caller can push them over the same channel it uses for every
     * other staged file - `cat > path` - which needs no external command at all.
     *
     * @return the file contents, or null when the manager's library cannot be read after all
     */
    fun readKsud(path: String): ByteArray? = runCatching {
        val file = File(path)
        if (!file.isFile) return null
        file.readBytes()
    }.onFailure { Log.w(TAG, "cannot read ksud at $path", it) }.getOrNull()

    /** Why the manager could not be brought to the foreground. */
    enum class LaunchResult { OK, NO_PACKAGE, NO_INTENT, FAILED }

    /** Brings the manager to the foreground so the user can grant access or install modules. */
    fun launchManager(context: Context, packageName: String): LaunchResult {
        if (packageName.isEmpty()) return LaunchResult.NO_PACKAGE
        val intent = context.packageManager.getLaunchIntentForPackage(packageName)
            ?: return LaunchResult.NO_INTENT
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_RESET_TASK_IF_NEEDED)
        return if (runCatching { context.startActivity(intent) }.isSuccess) {
            LaunchResult.OK
        } else {
            LaunchResult.FAILED
        }
    }

    /**
     * Opens the manager once the KernelSU module is really visible, and retries a few times.
     *
     * The `dfm6` marker only says `ksud late-load` returned 0; the module still has to appear in
     * `/proc/modules` and the manager has to accept the launch. Every failed attempt is logged with
     * its reason, so "root acquired but the manager did not open" is visible instead of silent.
     */
    fun launchWithRetry(
        context: Context,
        manager: AbsAdbConnectionManager?,
        packageName: String,
        log: (String) -> Unit = {},
        attempts: Int = 3,
        delayMs: Long = 1_000,
    ): Boolean {
        if (packageName.isEmpty()) {
            log("<e> no manager package resolved; open KernelSU by hand")
            return false
        }
        for (attempt in 1..attempts) {
            if (manager != null && !moduleVisible(manager)) {
                log("<i> waiting for kernelsu module (attempt $attempt/$attempts)")
                Thread.sleep(delayMs)
                continue
            }
            when (val result = launchManager(context, packageName)) {
                LaunchResult.OK -> {
                    log("<i> opened $packageName")
                    return true
                }
                else -> log(
                    "<e> cannot open $packageName: " +
                        result.name.lowercase().replace('_', ' ') + " (attempt $attempt/$attempts)"
                )
            }
            Thread.sleep(delayMs)
        }
        return false
    }

    /** {@code true} when `/proc/modules` lists kernelsu; unknown output does not block the launch. */
    private fun moduleVisible(manager: AbsAdbConnectionManager): Boolean {
        val output = runCatching {
            AdbShell.exec(manager, "grep -c '^kernelsu ' /proc/modules 2>/dev/null")
        }.getOrDefault("")
        val count = output.trim().toIntOrNull() ?: return true
        return count > 0
    }

    /** Preference store for the manager choice and the `ksud` override. */
    private const val PREF_NAME = "ksu_manager"
    private const val KEY_PACKAGE = "package"
    private const val KEY_KSUD = "ksud"

    /**
     * A manager the user picked by hand, which always wins over automatic resolution.
     *
     * Both halves are optional. A package name alone is enough when the manager is installed; the
     * `ksud` path is what makes a fork the resolver would never recognise usable, and it is also the
     * only way to point the payload at a copy that lives outside `/data/app`.
     */
    data class Override(val packageName: String, val ksudPath: String) {
        val isEmpty: Boolean get() = packageName.isEmpty() && ksudPath.isEmpty()
    }

    fun override(context: Context): Override {
        val prefs = context.applicationContext
            .getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE)
        return Override(
            packageName = prefs.getString(KEY_PACKAGE, "").orEmpty(),
            ksudPath = prefs.getString(KEY_KSUD, "").orEmpty(),
        )
    }

    fun setOverride(context: Context, override: Override) {
        context.applicationContext
            .getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_PACKAGE, override.packageName)
            .putString(KEY_KSUD, override.ksudPath)
            .apply()
    }

    /**
     * The manager to use, honouring [override] first.
     *
     * A hand-picked `ksud` is trusted as given: the caller only has to be able to read it, and the
     * payload only has to be able to execute it, so a path the resolver would never derive is
     * accepted on purpose.
     */
    fun resolveWithOverride(
        context: Context,
        manager: AbsAdbConnectionManager?,
        log: (String) -> Unit,
    ): Target? {
        val picked = override(context)
        if (!picked.isEmpty) {
            log("<i> using the manager chosen in Settings: ${picked.packageName.ifEmpty { "(no package)" }}")
            val ksud = picked.ksudPath.ifEmpty {
                // Package given but no path: ask the resolver for that package's library.
                manager?.let { ksudPathOf(it, picked.packageName, log) }.orEmpty()
            }
            if (ksud.isNotEmpty()) return Target(picked.packageName, ksud)
            log("<e> the chosen manager has no readable libksud.so; falling back to detection")
        }
        return resolve(context, manager, log)
    }

    /** `ls` the manager's own library directory, so a package name is enough to find `ksud`. */
    private fun ksudPathOf(
        manager: AbsAdbConnectionManager,
        packageName: String,
        log: (String) -> Unit,
    ): String? {
        if (packageName.isEmpty()) return null
        val command = "find /data/app -path \"*/$packageName-*/lib/*/libksud.so\" 2>/dev/null | head -n 1"
        log("$ $command")
        val found = runCatching { AdbShell.exec(manager, command) }.getOrDefault("").trim()
        if (found.isEmpty()) return null
        log(found)
        return found.lineSequence().firstOrNull { it.endsWith("/libksud.so") }
    }

    /** Official KernelSU release, fetched through the same proxy the app already uses. */
    const val MANAGER_REPO = "tiann/KernelSU"

    /**
     * Downloads the official manager APK and installs it as the shell user.
     *
     * The shell user holds `INSTALL_PACKAGES` only on a debuggable or userdebug build, so this is
     * attempted rather than promised: the result says exactly which step failed and the UI can fall
     * back to "install it yourself". Downloads go through a mirror because `github.com` is not
     * always reachable, and the release URL is resolved through the API first so a renamed asset
     * still works.
     */
    data class InstallResult(val ok: Boolean, val message: String)

    fun downloadAndInstallManager(
        manager: AbsAdbConnectionManager,
        onLine: (String) -> Unit,
    ): InstallResult {
        val remote = "/data/local/tmp/openroot/kernelsu-manager.apk"
        onLine("<i> looking up the latest KernelSU release")
        val tag = latestManagerTag() ?: return InstallResult(false, "cannot read the release list")
        onLine("<i> latest release: $tag")
        val urls = MANAGER_URLS.map { it.replace("\$TAG", tag) }
        var downloaded = false
        for (url in urls) {
            onLine("$ curl -L -o $remote '$url'")
            val fetch = runCatching {
                AdbShell.exec(
                    manager,
                    "mkdir -p /data/local/tmp/openroot && " +
                        "curl -sSL --max-time 180 -o $remote '$url' && ls -l $remote",
                    240_000L,
                )
            }.getOrDefault("")
            onLine(fetch.trimEnd())
            // A mirror that answers 404 writes an HTML page, so check the magic rather than the size.
            val magic = runCatching {
                AdbShell.exec(manager, "head -c 2 $remote 2>/dev/null")
            }.getOrDefault("")
            if (!magic.startsWith("PK")) {
                onLine("<e> $url did not return an APK; trying the next mirror")
                continue
            }
            downloaded = true
            break
        }
        if (!downloaded) return InstallResult(false, "every mirror failed")

        onLine("$ pm install -r $remote")
        val pm = runCatching {
            AdbShell.exec(manager, "pm install -r $remote 2>&1", 180_000L)
        }.getOrDefault("")
        onLine(pm.trimEnd())
        return when {
            pm.contains("Success") -> InstallResult(true, "installed")
            pm.contains("INSTALL_FAILED") ->
                InstallResult(false, pm.lineSequence().firstOrNull { it.contains("INSTALL_FAILED") }.orEmpty())
            pm.contains("Permission denied", ignoreCase = true) ->
                InstallResult(false, "the shell user cannot install packages on this build")
            else -> InstallResult(false, pm.trim().ifEmpty { "pm install said nothing" })
        }
    }

    /** Tags the app tries, in order: raw GitHub first, then the mirror used for everything else. */
    private val MANAGER_URLS = listOf(
        "https://v6.gh-proxy.org/https://github.com/$MANAGER_REPO/releases/download/\$TAG/KernelSU_\$TAG.apk",
        "https://v6.gh-proxy.org/https://github.com/$MANAGER_REPO/releases/latest/download/KernelSU.apk",
        "https://github.com/$MANAGER_REPO/releases/download/\$TAG/KernelSU_\$TAG.apk",
    )

    /** Newest release tag from the GitHub API, or null when the list cannot be read. */
    private fun latestManagerTag(): String? = runCatching {
        val endpoint = "https://api.github.com/repos/$MANAGER_REPO/releases/latest"
        val connection = java.net.URL(endpoint).openConnection() as java.net.HttpURLConnection
        connection.connectTimeout = 15_000
        connection.readTimeout = 15_000
        connection.setRequestProperty("Accept", "application/vnd.github+json")
        val body = connection.inputStream.bufferedReader().use { it.readText() }
        Regex("\"tag_name\"\\s*:\\s*\"([^\"]+)\"").find(body)?.groupValues?.get(1)
    }.getOrNull()
}
