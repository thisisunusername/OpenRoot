// SPDX-License-Identifier: GPL-3.0-or-later OR Apache-2.0

package com.hexo141.liquidglass.adb

import android.content.Context
import android.content.pm.PackageManager
import android.os.IBinder
import android.os.Parcel
import android.os.RemoteException
import android.util.Log
import rikka.shizuku.Shizuku
import rikka.shizuku.ShizukuBinderWrapper
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
     * Asks the Shizuku server to fork a process, then wraps the returned binder.
     *
     * `Shizuku.newProcess` was public until API 13 and private afterwards, so it cannot be called
     * from here any more. The service call it used is still there - `IShizukuService.newProcess`
     * with transaction code [TRANSACTION_NEW_PROCESS] - so this talks to that directly.
     *
     * The reply parcel holds a binder (the `IRemoteProcess`) followed by its AIDL interface token;
     * both are read here so the parcel is left in a consistent state before it is recycled.
     *
     * @param cmd argv, `cmd[0]` an absolute path
     * @param env the child's whole environment; Android's `sh` adds its own PATH when this is null
     * @param dir working directory, or null to inherit the server's
     */
    @Throws(RemoteException::class)
    private fun startProcess(
        cmd: Array<String>,
        env: Array<String>? = ENV,
        dir: String? = null,
    ): ShizukuRemoteProcess {
        val binder = Shizuku.getBinder()
            ?: throw IOException("Shizuku is not running; start it and grant this app access")
        // `Shizuku.getBinder()` is the local proxy for the service, not the service itself: a
        // transaction sent to it directly is answered by nobody and simply returns false, which is
        // what "Shizuku refused to start a process" used to mean. Wrapping it makes every
        // transaction travel to the server process, which is where `newProcess` actually lives.
        val service = ShizukuBinderWrapper(binder)
        val data = Parcel.obtain()
        val reply = Parcel.obtain()
        try {
            // Two interface tokens are involved. `ShizukuBinderWrapper` writes the outer one, which
            // is how the server knows the transaction is a `transactRemote` request. The inner one
            // is written here: the server re-dispatches `data` to the wrapped binder, and that
            // binder's `onTransact` starts with `enforceInterface`, so without this line it fails
            // with "Binder invocation to an incorrect interface".
            data.writeInterfaceToken(SHIZUKU_DESCRIPTOR)
            data.writeStringArray(cmd)
            data.writeStringArray(env)
            data.writeString(dir)

            if (!service.transact(TRANSACTION_NEW_PROCESS, data, reply, 0)) {
                throw RemoteException("Shizuku rejected newProcess")
            }
            reply.readException()
            val remote = reply.readStrongBinder()
                ?: throw RemoteException("Shizuku returned no process for ${cmd.joinToString(" ")}")
            return wrap(remote)
        } finally {
            reply.recycle()
            data.recycle()
        }
    }

    /**
     * Rebuilds a [ShizukuRemoteProcess] around an `IRemoteProcess` binder.
     *
     * Its constructor takes an `IRemoteProcess` and is package private inside `rikka.shizuku`, so
     * this app cannot call it. The `Parcelable` half of the class is public, though, and its
     * `CREATOR` reads exactly one binder back out - so a throwaway parcel gets there without
     * reflection, which would break under an obfuscated or shrunk Shizuku build.
     */
    private fun wrap(binder: IBinder): ShizukuRemoteProcess {
        val parcel = Parcel.obtain()
        try {
            parcel.writeStrongBinder(binder)
            parcel.setDataPosition(0)
            return ShizukuRemoteProcess.CREATOR.createFromParcel(parcel)
        } finally {
            parcel.recycle()
        }
    }

    /**
     * Descriptor `IShizukuService` checks on every transaction it receives.
     *
     * It is needed twice over: once by [ShizukuBinderWrapper] for the outer request, and once inside
     * [startProcess] for the arguments the server re-dispatches to `newProcess`.
     */
    private const val SHIZUKU_DESCRIPTOR = "moe.shizuku.server.IShizukuService"

    /** `IRemoteProcess newProcess(in String[] cmd, in String[] env, in String dir) = 7`. */
    private const val TRANSACTION_NEW_PROCESS = 7

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