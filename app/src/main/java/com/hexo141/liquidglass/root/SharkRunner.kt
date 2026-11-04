package com.hexo141.liquidglass.root

import android.content.Context
import com.hexo141.liquidglass.adb.AbsAdbConnectionManager
import com.hexo141.liquidglass.adb.AdbShell
import com.hexo141.liquidglass.device.DeviceInfo
import java.io.File

/**
 * Engines ported from the Shark one-key tool (com.pyb110.onekey 1.49).
 *
 * Shark ships three independent kernel payloads, each as a set of static arm64 binaries plus a
 * shell driver that ties them together. They were built for the vendor kernels that Shark itself
 * targets, so each one gates on its own `uname -r` family and refuses anything else rather than
 * guessing an address:
 *
 * - [Engine.CVE_64560] posix-cpu-timers UAF, 6.18 family, driver `run.sh`
 * - [Engine.CVE_98260] 6.18 family, driver `run98260.sh`
 * - [Engine.CVE_61269] 6.12 family, driver `run612.sh`
 *
 * The flows are all file-driven, which is why they port cleanly: `prep_solve` reads `syms.txt` and
 * writes `target.txt` / `slide.txt`, the attack binaries read those, and `t64560_w2` takes the
 * `TARGET_CRED 0x...` line that `t64560_loader2` printed. Nothing is passed through a private
 * channel, so running the shipped driver script unchanged is enough.
 *
 * The Shark bundle also carried its own KernelSU kernels and `ksud` copies; those are deliberately
 * not shipped here. OpenRoot already resolves the manager the user installed and hands its `ksud`
 * to the payload, which keeps one code path for the late-load handoff instead of five.
 */
object SharkRunner {

    private const val REMOTE_DIR = "/data/local/tmp/openroot/shark"
    private const val ASSET_DIR = "shark"

    /**
     * The three ports, each with the driver script that runs it and the release family it accepts.
     *
     * [releasePrefixes] is a coarse gate only: it keeps an obviously wrong kernel from being handed
     * a payload that would just crash, while the real check stays inside the payload.
     */
    enum class Engine(
        val id: String,
        val label: String,
        val script: String,
        val releasePrefixes: List<String>,
        val files: List<String>,
    ) {
        CVE_64560(
            id = "cve-2026-64560-shark",
            label = "CVE-2026-64560 (Shark, 6.18)",
            script = "run.sh",
            releasePrefixes = listOf("6.18."),
            files = listOf(
                "prep_solve", "prep_patch", "t64560_v36", "t64560_loader2", "t64560_w2",
                "forker", "syms.txt", "run.sh",
            ),
        ),
        CVE_98260(
            id = "cve-2026-98260-shark",
            label = "CVE-2026-98260 (Shark, 6.18)",
            script = "run98260.sh",
            releasePrefixes = listOf("6.18."),
            files = listOf(
                "t98260_plant", "t98260_su", "prep_patch", "syms.txt", "run98260.sh",
            ),
        ),
        CVE_61269(
            id = "cve-2026-61269-shark",
            label = "CVE-2026-61269 (Shark, 6.12)",
            script = "run612.sh",
            releasePrefixes = listOf("6.12."),
            files = listOf(
                "t61269", "t61269_su", "syms.txt", "run612.sh",
            ),
        ),
        ;

        /** Whether the running kernel is in the family this port was built against. */
        fun matches(kernel: String): Boolean =
            releasePrefixes.any { kernel.startsWith(it) }

        companion object {
            fun ofId(id: String): Engine? = entries.firstOrNull { it.id == id }
        }
    }

    /** One run: the driver's exit status and how much of its output was captured. */
    data class Result(
        val exitCode: Int,
        val output: String,
        /** True when the driver never started, e.g. the kernel family did not match. */
        val refused: Boolean = false,
    )

    /** Whether the payload for [engine] is packaged for this ABI. */
    fun isPayloadPresent(context: Context, engine: Engine): Boolean =
        engine.files.all { name ->
            runCatching {
                context.assets.open("$ASSET_DIR/$name").close()
                true
            }.getOrDefault(false)
        }

    /** Picks the engine for [info], or null when no port covers this kernel. */
    fun engineFor(info: DeviceInfo): Engine? =
        Engine.entries.firstOrNull { it.matches(info.kernel) }

    /**
     * Copies the driver's files next to each other under [REMOTE_DIR] and runs the script there.
     *
     * The assets are streamed straight to the device, so the bundle never has to fit in memory and
     * a partial copy cannot leave a half-written binary behind: each file is written to a `.part`
     * name and renamed once it is complete.
     */
    fun run(
        context: Context,
        manager: AbsAdbConnectionManager,
        engine: Engine,
        info: DeviceInfo,
        ksudPath: String?,
        onLine: (String) -> Unit,
    ): Result {
        if (!engine.matches(info.kernel)) {
            onLine(
                "This port was built for ${engine.releasePrefixes.joinToString(" / ")}; " +
                    "the device reports ${info.kernel}.",
            )
            return Result(exitCode = 1, output = "", refused = true)
        }

        onLine("$ mkdir -p $REMOTE_DIR")
        AdbShell.exec(manager, "mkdir -p $REMOTE_DIR")

        for (name in engine.files) {
            val bytes = runCatching { context.assets.open("$ASSET_DIR/$name").use { it.readBytes() } }
                .getOrNull()
            if (bytes == null) {
                onLine("Missing $ASSET_DIR/$name in the APK; this engine cannot run.")
                return Result(exitCode = 1, output = "", refused = true)
            }
            val remote = "$REMOTE_DIR/$name"
            onLine("$ push $name (${bytes.size} bytes)")
            val staged = "$remote.part"
            if (!AdbShell.push(manager, staged, bytes)) {
                onLine("Could not write $staged")
                return Result(exitCode = 1, output = "", refused = true)
            }
            AdbShell.exec(manager, "mv -f $staged $remote && chmod 755 $remote")
        }

        val env = buildString {
            append("PYB110_DIR=").append(REMOTE_DIR)
            append(" PATH=/system/bin:/system/xbin:/data/adb/ksu/bin")
            append(" HOME=/data/local/tmp")
            // The driver defaults to the official KernelSU package; pass the manager the user
            // actually has so the late-load step binds to it instead of installing a second one.
            if (ksudPath != null) append(" PYB110_MANAGER_PKG=").append(ksudPackageOf(ksudPath))
        }

        onLine("$ cd $REMOTE_DIR && sh ${engine.script}")
        val output = StringBuilder()
        val exit = AdbShell.stream(
            manager,
            "cd $REMOTE_DIR && $env sh ${engine.script} 2>&1",
        ) { line ->
            output.append(line).append('\n')
            onLine(line)
        }
        return Result(exitCode = exit, output = output.toString())
    }

    /** `.../me.weishu.kernelsu/lib/libksud.so` -> `me.weishu.kernelsu`. */
    private fun ksudPackageOf(ksudPath: String): String =
        runCatching {
            File(ksudPath).parentFile?.parentFile?.name.orEmpty()
        }.getOrDefault("")
}
