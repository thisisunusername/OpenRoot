package com.hexo141.liquidglass.root

import android.content.Context
import com.hexo141.liquidglass.adb.AbsAdbConnectionManager
import com.hexo141.liquidglass.adb.AdbShell
import com.hexo141.liquidglass.device.DeviceInfo

/**
 * The OGKI port from JokerLock 1.4.9.
 *
 * JokerLock wraps the same CVE as [PctRunner] — CVE-2026-64560, the posix-cpu-timers
 * use-after-free on a non-leader `exec()` — but its build is aimed at a different family:
 * `6.6.118-android15-8` on Oppo/Realme/OnePlus GKI kernels, fingerprinted `gc4127a25dcf3` or
 * `g9bc34d5b0c79`. The two engines therefore share a CVE but not a payload, and the picker lists
 * them separately so a run is never credited to the wrong build.
 *
 * What JokerLock adds over the shipped [PctRunner] payload is the addressing strategy: it does not
 * read a profile, it recovers `init_task`, the `cred` layout and the physical page of its victim at
 * run time through KernelSnitch, and it keeps the kernel state it touches reversible so a failed
 * attempt leaves the device bootable. Its own log is the report — STAGE0 through STAGE8 — so this
 * runner forwards it instead of interpreting it.
 *
 * The payload runs with no arguments; its working directory and `TMPDIR` are the deploy directory,
 * and `su -c id` is the only thing this code has to check afterwards.
 */
object JokerRunner {

    private const val REMOTE_DIR = "/data/local/tmp/jokerlock"
    private const val ASSET_DIR = "joker"

    /** The one payload this engine ships; the Okgi variant is the general GKI build. */
    const val PAYLOAD = "libpayload_ogki.so"

    /** The temp-su shim that survives the handoff, so `id` can be checked after the run. */
    private const val TEMP_SU = "libtempsu.so"
    private const val TEMP_SU_REMOTE = "/data/local/tmp/su"

    /**
     * Kernels the Okgi payload was built against.
     *
     * The payload gates itself on the full fingerprint, so this list is only used to decide whether
     * the row is worth enabling; a match here does not promise the gate will pass.
     */
    private val RELEASE_PREFIXES = listOf("6.6.118-android15-8")

    /** Build hashes JokerLock names in its own UI as the supported firmware. */
    private val RELEASE_HASHES = listOf("gc4127a25dcf3", "g9bc34d5b0c79")

    /** The payload is told to give up after roughly five minutes; past that it is not coming back. */
    private const val TIMEOUT_MS = 285_000L

    /** How long to keep asking `su -c id` after the payload exits. */
    private const val VERIFY_WINDOW_MS = 90_000L
    private const val VERIFY_STEP_MS = 3_000L

    data class Result(
        val exitCode: Int,
        val output: String,
        /** True when the payload never started, e.g. the kernel family did not match. */
        val refused: Boolean = false,
        /** True when `su -c id` came back as uid 0 inside the verify window. */
        val rooted: Boolean = false,
    )

    fun isPayloadPresent(context: Context): Boolean =
        runCatching {
            context.assets.open("$ASSET_DIR/$PAYLOAD").close()
            context.assets.open("$ASSET_DIR/$TEMP_SU").close()
            true
        }.getOrDefault(false)

    /** Whether this kernel is in the family the Okgi payload was built for. */
    fun isSupported(kernel: String): Boolean =
        RELEASE_PREFIXES.any { kernel.startsWith(it) } ||
            RELEASE_HASHES.any { kernel.contains(it) }

    fun run(
        context: Context,
        manager: AbsAdbConnectionManager,
        info: DeviceInfo,
        onLine: (String) -> Unit,
    ): Result {
        if (!isSupported(info.kernel)) {
            onLine(
                "The Okgi payload was built for ${RELEASE_PREFIXES.joinToString(" / ")} " +
                    "(firmware ${RELEASE_HASHES.joinToString(" / ")}); this kernel is ${info.kernel}.",
            )
            return Result(exitCode = 1, output = "", refused = true)
        }

        onLine("$ mkdir -p $REMOTE_DIR")
        AdbShell.exec(manager, "mkdir -p $REMOTE_DIR")

        for (name in listOf(PAYLOAD, TEMP_SU)) {
            val bytes = runCatching { context.assets.open("$ASSET_DIR/$name").use { it.readBytes() } }
                .getOrNull()
            if (bytes == null) {
                onLine("Missing $ASSET_DIR/$name in the APK; this engine cannot run.")
                return Result(exitCode = 1, output = "", refused = true)
            }
            val remote = if (name == TEMP_SU) TEMP_SU_REMOTE else "$REMOTE_DIR/$name"
            onLine("$ push $remote (${bytes.size} bytes)")
            val staged = "$remote.part"
            if (!AdbShell.push(manager, staged, bytes)) {
                onLine("Could not write $staged")
                return Result(exitCode = 1, output = "", refused = true)
            }
            AdbShell.exec(manager, "mv -f $staged $remote && chmod 755 $remote")
        }

        // The payload takes no arguments; everything it needs comes from its working directory.
        val output = StringBuilder()
        onLine("$ cd $REMOTE_DIR && TMPDIR=$REMOTE_DIR HOME=$REMOTE_DIR ./$PAYLOAD")
        val exit = AdbShell.stream(
            manager,
            "cd $REMOTE_DIR && TMPDIR=$REMOTE_DIR HOME=$REMOTE_DIR ./$PAYLOAD 2>&1",
            onLine = { line ->
                output.append(line).append('\n')
                onLine(line)
            },
            idleTimeoutMs = TIMEOUT_MS,
        )
        onLine("<i> payload exited with $exit")

        // The payload hands off to KernelSU late-load and returns; the handoff shows up as `su`.
        val deadline = System.currentTimeMillis() + VERIFY_WINDOW_MS
        while (System.currentTimeMillis() < deadline) {
            val probe = AdbShell.exec(manager, "timeout 10 su -c id 2>/dev/null || true")
            if (probe.contains("uid=0")) {
                onLine("<b> ROOT_SUCCESS identity=${probe.trim()}")
                return Result(exitCode = exit, output = output.toString(), rooted = true)
            }
            Thread.sleep(VERIFY_STEP_MS)
        }
        onLine("<s> su -c id never returned uid=0; the late-load did not take")
        return Result(exitCode = exit, output = output.toString())
    }
}