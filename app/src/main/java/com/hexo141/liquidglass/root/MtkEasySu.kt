package com.hexo141.liquidglass.root

import android.content.Context
import com.hexo141.liquidglass.adb.AbsAdbConnectionManager
import com.hexo141.liquidglass.adb.AdbShell

/**
 * Bootless root on MediaTek devices: the mtk-su payload, then Magisk 20.4 into `/sbin`.
 *
 * ## Why this engine is not a kernel exploit engine
 *
 * Every other engine here goes kernel bug → root in memory → `ksud late-load`. This one never touches
 * the kernel image: `mtk-su` abuses the MediaTek command-queue driver (`/dev/mtk_cmdq`) from an
 * ordinary app uid, lands `uid=0` with SELinux already permissive, and then `magiskinit` boots a
 * Magisk payload that lives only in `/sbin`. Nothing is written to a partition, so the bootloader
 * stays locked and nothing survives a reboot. That is the whole point of the approach and also its
 * whole limitation.
 *
 * ## Preconditions, and why they are checked before anything runs
 *
 * `mtk-su` was fixed around March 2020. On a device patched after that the binary runs and fails,
 * which looks identical to "this device is not supported", so the engine probes first:
 *
 * - the SoC has to report MediaTek (`ro.hardware` / `ro.board.platform` starts with `mt`),
 * - `/dev/mtk_cmdq` (or the `mtk_smi`/`cmdq` siblings) has to be openable by the shell user,
 * - the build's patch level has to predate the fix, or the caller is warned loudly.
 *
 * ## Manager pairing
 *
 * The payload in `/sbin` is Magisk 20.4. A modern manager will refuse it and push an "update" that
 * breaks the bootless setup, so [MagiskManager.Flavor.LEGACY] is the only correct pairing and the
 * caller is told so rather than left to discover it.
 */
object MtkEasySu {
    data class Probe(
        val isMediaTek: Boolean,
        val soc: String,
        val patchLevel: String,
        val cmdqPaths: List<String>,
        val reason: String,
        /**
         * Whether the 64-bit half should be used.
         *
         * `mtk-su32` and `mtk-su64` are different binaries and the wrong one dies with
         * `exec format error`, so the choice is made from the device's own ABI list rather than
         * guessed: `ro.product.cpu.abilist` lists the 64-bit ABIs first on a 64-bit userspace.
         */
        val use64: Boolean = false,
    ) {
        val supported: Boolean
            get() = isMediaTek && cmdqPaths.isNotEmpty()

        /**
         * `true` when the build is new enough that `mtk-su` is almost certainly fixed.
         *
         * Not a hard stop: the caller may still want to try, and the payload decides for real.
         */
        val likelyPatched: Boolean
            get() = patchLevel >= "2020-03-01"
    }

    /** Files the payload needs, all staged by [deploy]. */
    private val STAGE_ASSETS = listOf(
        "mtk/mtk-su32",
        "mtk/mtk-su64",
        "mtk/magiskinit32",
        "mtk/magiskinit64",
        "mtk/magisk-boot.sh",
    )

    private const val STAGE_DIR = "/data/local/tmp/openroot/mtk"

    /** The file the stock `magisk-boot.sh` creates; its presence is the success signal. */
    private const val SUCCESS_MARKER = "/sbin/su"

    /** Marker this engine leaves in `/dev`, next to the `dfm*` markers bootstrap writes. */
    const val MARKER_OK = "/dev/dfmm1"
    const val MARKER_FAIL = "/dev/dfmme1"

    /**
     * Checks whether this device is a plausible target.
     *
     * Every command goes through the shell user, so the probe works before any root exists.
     */
    fun probe(manager: AbsAdbConnectionManager, log: (String) -> Unit = {}): Probe {
        val socCommand = "getprop ro.hardware; getprop ro.board.platform; " +
            "getprop ro.product.board; getprop ro.vendor.product.model"
        log("$ $socCommand")
        val socRaw = runCatching { AdbShell.exec(manager, socCommand) }.getOrDefault("")
        if (socRaw.isNotBlank()) log(socRaw.trimEnd())
        val soc = socRaw.lineSequence().map { it.trim() }.firstOrNull { it.isNotEmpty() }.orEmpty()

        val isMtk = socRaw.lineSequence().any { line ->
            val v = line.trim().lowercase()
            // MTK reports as mt65xx/mt67xx/mt68xx, or the umbrella `mtk` on newer vendor blobs.
            v.startsWith("mt") && v.length <= 12 || v.contains("mediatek") || v.contains("mtk")
        }

        val patchCommand = "getprop ro.build.version.security_patch"
        log("$ $patchCommand")
        val patch = runCatching { AdbShell.exec(manager, patchCommand) }.getOrDefault("").trim()
        if (patch.isNotEmpty()) log(patch)

        /* `abilist` is authoritative: on a 32-bit userspace `mtk-su64` cannot even exec, and the
         * device can still be arm64-capable in hardware. */
        val abiCommand = "getprop ro.product.cpu.abilist"
        log("$ $abiCommand")
        val abilist = runCatching { AdbShell.exec(manager, abiCommand) }.getOrDefault("").trim()
        if (abilist.isNotEmpty()) log(abilist)
        val use64 = abilist.contains("arm64-v8a") || abilist.contains("arm64")

        val cmdq = probesCmdq(manager, log)

        val reason = when {
            !isMtk -> "not a MediaTek device (soc probe said '$soc')"
            cmdq.isEmpty() -> "no MediaTek command-queue node is openable by the shell user"
            patch >= "2020-03-01" -> "patch level $patch postdates the mtk-su fix; expect a failure"
            else -> "MediaTek device with an openable command-queue node"
        }
        return Probe(isMtk, soc, patch, cmdq, reason, use64)
    }

    /**
     * Finds a command-queue node the shell user can actually open read-write.
     *
     * Being present is not enough: on many builds the node exists and is `0600 root root`, which makes
     * `mtk-su` fail immediately. Opening it is the only honest test, so `dd` is used to do exactly
     * that and nothing else.
     */
    private fun probesCmdq(manager: AbsAdbConnectionManager, log: (String) -> Unit): List<String> {
        val candidates = listOf(
            "/dev/mtk_cmdq",
            "/dev/mtk-cmdq",
            "/dev/cmdq",
            "/proc/mtk_cmdq",
            "/dev/mtk_smi",
        )
        val command = candidates.joinToString("; ") { p ->
            "([ -e $p ] && dd if=$p of=/dev/null bs=1 count=0 2>/dev/null && echo $p)"
        } + "; true"
        log("$ $command")
        val out = runCatching { AdbShell.exec(manager, command) }.getOrDefault("")
        if (out.isNotBlank()) log(out.trimEnd())
        val found = out.lineSequence().map { it.trim() }.filter { it in candidates }.toList()
        // A node that exists but cannot be opened is still worth reporting, so the log explains itself.
        if (found.isEmpty()) {
            val ls = runCatching {
                AdbShell.exec(manager, "ls -l ${candidates.joinToString(" ")} 2>&1")
            }.getOrDefault("")
            if (ls.isNotBlank()) log(ls.trimEnd())
        }
        return found
    }

    /**
     * Runs the payload and reports whether `/sbin/su` appeared.
     *
     * `magisk-boot.sh` decides between the 32- and 64-bit halves from its argument, and mtk-su has to
     * run as the shell user (not as root), which is exactly what `AdbShell` gives us. The script needs
     * the binaries beside it, so everything is staged flat into one directory.
     */
    fun run(
        context: Context,
        manager: AbsAdbConnectionManager,
        use64: Boolean,
        log: (String) -> Unit = {},
        timeoutMs: Long = 180_000L,
    ): Boolean {
        deploy(context, manager, log) ?: return false

        val arch = if (use64) "64" else "32"
        val command = "cd $STAGE_DIR && sh ./magisk-boot.sh $arch 2>&1; echo \"__rc=\$?\"; " +
            "ls -l $SUCCESS_MARKER 2>&1; id"
        log("$ sh magisk-boot.sh $arch")
        val out = runCatching {
            AdbShell.exec(manager, command, timeoutMs)
        }.getOrDefault("")
        out.lineSequence().filter { it.isNotBlank() }.forEach { log(it.trimEnd()) }

        val ok = out.contains("__rc=0") && out.contains(SUCCESS_MARKER)
        touch(manager, if (ok) MARKER_OK else MARKER_FAIL, log)
        log(
            if (ok) "<i> Magisk 20.4 is live in /sbin; pair it with the legacy manager"
            else "<e> the payload did not create $SUCCESS_MARKER"
        )
        return ok
    }

    /**
     * Copies the five payload files out of the APK next to the script.
     *
     * They live in `assets/mtk/` and are pushed through `AdbShell`, which means they are streamed over
     * the same channel every other stage uses. Each file is marked executable because `mtk-su` and
     * `magiskinit` are both invoked directly by the script.
     */
    private fun deploy(
        context: Context,
        manager: AbsAdbConnectionManager,
        log: (String) -> Unit,
    ): String? {
        val absent = Assets.missing(context, STAGE_ASSETS)
        if (absent.isNotEmpty()) {
            log("<e> the MediaTek payload is not bundled: ${absent.joinToString()}")
            return null
        }
        val prep = runCatching {
            AdbShell.exec(manager, "mkdir -p $STAGE_DIR && chmod 700 $STAGE_DIR")
        }
        if (prep.isFailure) {
            log("<e> cannot create $STAGE_DIR")
            return null
        }
        log("<i> staging the MediaTek payload in $STAGE_DIR")
        for (asset in STAGE_ASSETS) {
            val name = asset.substringAfterLast('/')
            val ok = pushAsset(context, manager, asset, "$STAGE_DIR/$name", log)
            if (!ok) {
                log("<e> $asset could not be staged")
                return null
            }
        }
        runCatching { AdbShell.exec(manager, "chmod 755 $STAGE_DIR/mtk-su* $STAGE_DIR/magiskinit*; chmod 644 $STAGE_DIR/magisk-boot.sh") }
        return STAGE_DIR
    }

    /**
     * Writes one asset onto the device.
     *
     * The bytes go through [AdbShell.push], which is the same transfer every other engine uses: it
     * chunks the write, retries a dropped pipe and resumes from the last confirmed offset. Rolling a
     * private `base64` route here would have produced a file that looks right and is not, because a
     * shell heredoc cannot carry arbitrary binary safely.
     */
    private fun pushAsset(
        context: Context,
        manager: AbsAdbConnectionManager,
        asset: String,
        remote: String,
        log: (String) -> Unit,
    ): Boolean {
        val bytes = Assets.read(context, asset)
        if (bytes == null || bytes.isEmpty()) {
            // assets/ is where the payload is checked in; missing means the build dropped it.
            log("<e> asset '$asset' is missing from the APK")
            return false
        }
        log("$ push $remote (${bytes.size} bytes)")
        val ok = runCatching { AdbShell.push(manager, remote, bytes) }.getOrDefault(false)
        if (!ok) {
            log("<e> pushing $remote failed")
            return false
        }
        // Trust but verify: a truncated push is exactly the failure this check exists to catch.
        val size = runCatching {
            AdbShell.exec(manager, "wc -c < '$remote'")
        }.getOrDefault("").trim().toIntOrNull() ?: -1
        if (size != bytes.size) {
            log("<e> $remote is $size bytes, expected ${bytes.size}")
            return false
        }
        return true
    }

    private fun touch(
        manager: AbsAdbConnectionManager,
        path: String,
        log: (String) -> Unit,
    ) {
        runCatching { AdbShell.exec(manager, "touch $path") }
    }
}

/**
 * Reads a bundled payload file.
 *
 * The payload ships under `assets/`, so a `Context` is needed; the caller always has one at the
 * point where an engine is started, so nothing is cached here.
 */
internal object Assets {
    fun read(context: Context, name: String): ByteArray? =
        runCatching { context.assets.open(name).use { it.readBytes() } }.getOrNull()

    /** `true` when every name resolves, used to fail early with a readable message. */
    fun missing(context: Context, names: List<String>): List<String> =
        names.filter { runCatching { context.assets.open(it).close() }.isFailure }
}