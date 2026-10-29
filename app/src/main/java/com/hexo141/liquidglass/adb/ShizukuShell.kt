// SPDX-License-Identifier: GPL-3.0-or-later OR Apache-2.0

package com.hexo141.liquidglass.adb

import android.content.Context
import android.content.pm.PackageManager
import android.util.Log
import rikka.shizuku.Shizuku
import java.io.IOException

/**
 * Runs shell commands through Shizuku instead of wireless debugging.
 *
 * Why this exists: pairing needs a wireless-debugging entry in Developer options (Android 11+),
 * which many devices either lack entirely (older releases) or have had stripped out by the OEM.
 * Shizuku instead starts one privileged process and lends it to apps, so this app never touches
 * `adbd`, mDNS or a pairing code.
 *
 * The privilege is whatever the user started Shizuku with: `uid 0` from root, or `uid 2000` from
 * ADB. The payloads only ever needed the `shell` user, so either startup works.
 */
object ShizukuShell {

    private const val TAG = "ShizukuShell"

    /** `Shizuku.getUid()` value while the server runs as the shell user. */
    const val UID_SHELL = 2000

    /**
     * Environment handed to every `sh -c` child.
     *
     * `envp = null` happens to work on mksh because it falls back to a built-in PATH, but the
     * payloads inherit whatever is here and several of them read `HOME` and `TMPDIR` before they
     * have root. Declaring the values explicitly also keeps the child from inheriting anything from
     * the Shizuku server that this app did not ask for.
     */
    private val ENV = arrayOf(
        "PATH=/product/bin:/apex/com.android.runtime/bin:/apex/com.android.art/bin" +
            ":/system_ext/bin:/system/bin:/system/xbin:/odm/bin:/vendor/bin:/vendor/xbin",
        "ANDROID_ROOT=/system",
        "ANDROID_DATA=/data",
        "HOME=/data/local/tmp",
        "TMPDIR=/data/local/tmp",
    )

    /** Whatever state the Shizuku link is in, so the UI can say something useful. */
    enum class Status {
        /** The Shizuku app is not installed (or Sui is not available). */
        NOT_INSTALLED,

        /** Installed, but the server was not started (or died). */
        NOT_RUNNING,

        /** Running, but this app was never granted access. */
        PERMISSION_REQUIRED,

        /** The user denied and ticked "don't ask again"; only Settings can undo that. */
        PERMISSION_DENIED,

        /** Running and granted. */
        READY,
    }

    fun status(): Status {
        if (!isBinderAlive()) {
            return if (isShizukuInstalled()) Status.NOT_RUNNING else Status.NOT_INSTALLED
        }
        return when {
            Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED -> Status.READY
            Shizuku.shouldShowRequestPermissionRationale() -> Status.PERMISSION_DENIED
            else -> Status.PERMISSION_REQUIRED
        }
    }

    fun isBinderAlive(): Boolean = runCatching { Shizuku.pingBinder() }.getOrDefault(false)

    /**
     * `true` when the server is reachable *and* this app is allowed to use it.
     *
     * Deliberately does not prompt: callers decide when a dialog is appropriate.
     */
    fun isReady(): Boolean = status() == Status.READY

    /** Shows the Shizuku permission dialog; the answer arrives on the listener below. */
    fun requestPermission(requestCode: Int) {
        if (!isBinderAlive() || Shizuku.isPreV11()) return
        if (Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED) return
        runCatching { Shizuku.requestPermission(requestCode) }
            .onFailure { Log.w(TAG, "requestPermission failed", it) }
    }

    fun addPermissionListener(listener: Shizuku.OnRequestPermissionResultListener) {
        runCatching { Shizuku.addRequestPermissionResultListener(listener) }
    }

    fun removePermissionListener(listener: Shizuku.OnRequestPermissionResultListener) {
        runCatching { Shizuku.removeRequestPermissionResultListener(listener) }
    }

    fun addBinderAliveListener(listener: Shizuku.OnBinderReceivedListener) {
        runCatching { Shizuku.addBinderReceivedListenerSticky(listener) }
    }

    fun removeBinderAliveListener(listener: Shizuku.OnBinderReceivedListener) {
        runCatching { Shizuku.removeBinderReceivedListener(listener) }
    }

    fun addBinderDeadListener(listener: Shizuku.OnBinderDeadListener) {
        runCatching { Shizuku.addBinderDeadListener(listener) }
    }

    fun removeBinderDeadListener(listener: Shizuku.OnBinderDeadListener) {
        runCatching { Shizuku.removeBinderDeadListener(listener) }
    }

    /** `0` for a root-started Shizuku, `2000` for an ADB-started one, `-1` when unknown. */
    fun serverUid(): Int = runCatching { Shizuku.getUid() }.getOrDefault(-1)

    /** Human readable privilege, for the UI and the payload logs. */
    fun describePrivilege(): String = when (val uid = serverUid()) {
        0 -> "root (uid 0)"
        UID_SHELL -> "shell (uid 2000)"
        -1 -> "unknown"
        else -> "uid $uid"
    }

    /**
     * Starts `command` through the Shizuku server.
     *
     * The command always goes through `/system/bin/sh -c` so redirections, `;`, `&&` and `$?`
     * behave exactly like they do on an ADB `shell:` service.
     *
     * The caller speaks the ADB service vocabulary, where `shell:cmd` means "run cmd". Shizuku has
     * no service layer, so that prefix has to come off here - handing `shell:ls` to `sh` makes it
     * look for a binary literally named `shell:ls` and report `inaccessible or not found`, which
     * silently broke every diagnostic that used an external command while builtins (`test`, `echo`)
     * kept working.
     *
     * @throws IOException when Shizuku is not usable, so callers can treat it like a dead channel.
     */
    @Throws(IOException::class)
    fun openStream(destination: String): ShellStream {
        val command = stripServicePrefix(destination)
        if (!isBinderAlive()) {
            throw IOException("Shizuku is not running; start it and grant this app access")
        }
        if (Shizuku.isPreV11()) {
            throw IOException("Shizuku v11 or newer is required")
        }
        if (Shizuku.checkSelfPermission() != PackageManager.PERMISSION_GRANTED) {
            throw IOException("Shizuku permission has not been granted")
        }

        val process = try {
            @Suppress("DEPRECATION")
            Shizuku.newProcess(arrayOf("/system/bin/sh", "-c", command), null, ENV)
        } catch (e: IllegalStateException) {
            throw IOException("Shizuku binder is gone", e)
        } catch (e: RuntimeException) {
            throw IOException("Shizuku could not start the process", e)
        }

        if (process == null) {
            throw IOException("Shizuku returned no process for $command")
        }
        Log.d(TAG, "started (${describePrivilege()}): $command")
        return ShizukuStream(process, command)
    }

    /**
     * Drops the ADB service prefix the callers use, so `shell:ls -l /tmp` becomes `ls -l /tmp`.
     *
     * Anything that is not a shell service is passed through untouched: a future caller asking for
     * a different service should fail loudly when Shizuku cannot honour it rather than have its
     * request quietly reinterpreted.
     */
    private fun stripServicePrefix(destination: String): String = when {
        destination.startsWith("shell,pty:") -> destination.removePrefix("shell,pty:")
        destination.startsWith("shell:") -> destination.removePrefix("shell:")
        else -> destination
    }

    private fun isShizukuInstalled(): Boolean = try {
        val context = appContext ?: return false
        context.packageManager.getPackageInfo("moe.shizuku.privileged.api", 0)
        true
    } catch (_: PackageManager.NameNotFoundException) {
        false
    } catch (_: Exception) {
        false
    }

    /**
     * Set once from the Activity so [status] can tell "not installed" from "not running".
     * Only the application context is kept, so this cannot leak an Activity.
     */
    @Volatile
    private var appContext: Context? = null

    fun attach(context: Context) {
        appContext = context.applicationContext
    }
}