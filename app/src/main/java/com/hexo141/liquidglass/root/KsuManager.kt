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
}
