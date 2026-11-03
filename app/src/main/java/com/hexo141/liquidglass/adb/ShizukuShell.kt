// SPDX-License-Identifier: GPL-3.0-or-later OR Apache-2.0

package com.hexo141.liquidglass.adb

import android.content.Context
import android.content.pm.PackageManager
import android.os.RemoteException
import android.util.Log
import rikka.shizuku.Shizuku
import rikka.shizuku.ShizukuRemoteProcess
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
     * How long the [probe] waits for its echo.
     *
     * Short on purpose: the command is one word, so a server that needs longer than this is not
     * going to answer at all, and the caller is waiting on the answer to pick a transport.
     */
    private const val PROBE_TIMEOUT_MS = 4_000L

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

    /**
     * Result of the last [probe]: `true` ran, `false` did not, `null` never tried.
     *
     * Cached because a probe is a round trip, and because [status] is read on every recomposition.
     */
    @Volatile
    private var usable: Boolean? = null

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

        /**
         * Granted, but the server would not start a process.
         *
         * Permission state says nothing about whether the server can actually fork a shell, and a
         * server that cannot is worse than none: the UI would keep offering the grant flow, which
         * is already complete, and never mention the transport that does work.
         */
        UNUSABLE,
    }

    fun status(): Status {
        if (!isBinderAlive()) {
            usable = null
            return if (isShizukuInstalled()) Status.NOT_RUNNING else Status.NOT_INSTALLED
        }
        return when {
            Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED ->
                // The probe costs a round trip, so it runs once and the answer is reused until
                // something asks for it again. A `null` here means "granted, not yet tried".
                if (usable == false) Status.UNUSABLE else Status.READY
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

    /**
     * Runs one harmless command through the server to prove shells actually work.
     *
     * [isReady] only asks whether the binder is reachable and the permission is granted, which
     * stays `true` for a server that cannot start a process at all - the app then reports a
     * connected transport and every later step silently produces nothing. A single `true` costs one
     * round trip and distinguishes "allowed" from "usable".
     *
     * @return `true` when the server started a process and that process reported success.
     */
    fun probe(): Boolean {
        if (!isReady()) {
            usable = null
            return false
        }
        val ok = try {
            // A marker the server has to echo back proves three things at once: a process was
            // started, its stdout reaches this side, and its exit status came through. The
            // deadline matters: an unhealthy server accepts the request and then says nothing, and
            // without a cap the probe would hang the caller instead of reporting a failure.
            val stream = openStream("shell:echo openroot-probe")
            val seen = StringBuilder()
            val deadline = System.currentTimeMillis() + PROBE_TIMEOUT_MS
            try {
                val buffer = ByteArray(256)
                while (System.currentTimeMillis() < deadline) {
                    val read = runCatching { stream.read(buffer, 0, buffer.size) }.getOrDefault(-1)
                    if (read <= 0) break
                    seen.append(String(buffer, 0, read, Charsets.UTF_8))
                    if (seen.contains("openroot-probe")) break
                }
            } finally {
                runCatching { stream.close() }
            }
            seen.contains("openroot-probe")
        } catch (e: Exception) {
            Log.w(TAG, "probe failed", e)
            false
        }
        usable = ok
        if (!ok) Log.w(TAG, "granted but the server will not start a process")
        return ok
    }

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
            startProcess(arrayOf("/system/bin/sh", "-c", command))
        } catch (e: RemoteException) {
            throw IOException("Shizuku refused to start a process: ${e.message}", e)
        } catch (e: IllegalStateException) {
            throw IOException("Shizuku binder is gone: ${e.message}", e)
        } catch (e: RuntimeException) {
            // Shizuku wraps a server-side SecurityException or IllegalStateException in a plain
            // RuntimeException, so `e.message` alone just says "java.lang.SecurityException" with no
            // detail. The cause carries the sentence that says which check failed.
            val cause = e.cause
            val detail = cause?.let { "${it::class.java.simpleName}: ${it.message}" }
                ?: e.message
            throw IOException("Shizuku could not start the process: $detail", e)
        }

        Log.d(TAG, "started (${describePrivilege()}): $command")
        return ShizukuStream(process, command)
    }

    /**
     * Asks the Shizuku server to fork a process.
     *
     * `Shizuku.newProcess` is still public in API 13.0.0, so this calls it directly instead of
     * replaying the `IShizukuService` transaction by hand. The hand-rolled version depended on the
     * transaction number and the parcel layout of one particular server build, and a server that
     * implemented `newProcess` differently produced "returned no process" with nothing to go on.
     *
     * Failures are rethrown as [IOException] with the cause spelled out: Shizuku wraps a
     * server-side rejection in a plain `RuntimeException`, so the message alone only names the
     * exception type.
     *
     * @param cmd argv, `cmd[0]` an absolute path
     * @param env the child's whole environment; null inherits the server's
     * @param dir working directory, or null to inherit the server's
     */
    @Throws(IOException::class)
    private fun startProcess(
        cmd: Array<String>,
        env: Array<String>? = ENV,
        dir: String? = null,
    ): ShizukuRemoteProcess {
        val process = try {
            Shizuku.newProcess(cmd, env, dir)
        } catch (e: RemoteException) {
            throw IOException("Shizuku refused to start a process: ${e.message}", e)
        } catch (e: RuntimeException) {
            val cause = e.cause
            val detail = cause?.let { "${it::class.java.simpleName}: ${it.message}" } ?: e.message
            throw IOException("Shizuku could not start the process: $detail", e)
        }
        return process ?: throw IOException("Shizuku returned no process for ${cmd.joinToString(" ")}")
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