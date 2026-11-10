package com.hexo141.liquidglass.root

import android.content.Context
import com.hexo141.liquidglass.adb.AbsAdbConnectionManager
import com.hexo141.liquidglass.adb.AdbShell
import java.io.File

/**
 * GhostLock54: CVE-2026-43499, hand-ported to the OPPO Reno7 5G.
 *
 * ## Why this is a second row for a CVE that already has one
 *
 * [RootExploit] runs the upstream engine and picks offsets from a bundled profile; this one is a
 * single build whose offsets are compiled into the C for exactly one kernel,
 * `5.4.254-qgki-gaa96eae94d32`. They share a CVE and nothing else — different source, different
 * payload, different follow-up — so they get different rows rather than one row pretending to
 * cover both. The same reasoning already applies to the Shark ports and to JokerLock.
 *
 * ## What it does differently
 *
 * The exploit replaces the target's `cred` with `init_cred` and clears `task_struct.seccomp`, then
 * loads a KernelSU module that the upstream author compiled against this kernel
 * (`kernelsu.ko`, vermagic `5.4.254-qgki-gaa96eae94d32`). Root is whatever KernelSU hands out
 * afterwards — `u:r:ksu:s0` from the manager — not a shell the exploit parks you in. That
 * in-place `#` shell existed up to v5.0 upstream and was removed, so this engine does not claim it.
 *
 * ## The three things that have to be true first
 *
 * 1. The kernel release must be the one the offsets were written for. `ghostlock54.c` does not
 *    check this itself — it starts writing as soon as it runs — so the gate has to be here, before
 *    a single byte is pushed.
 * 2. The module's vermagic must match the same release, or `init_module` refuses it and the run
 *    ends with root that vanishes on reboot and no manager.
 * 3. The module file has to reach `/data/local/tmp` root, not a subdirectory: `g_module_path`
 *    defaults to exactly `/data/local/tmp/kernelsu.ko`.
 *
 * Upstream: <https://github.com/54gay/ghostlock54-OPPO-Reno7-5G>
 */
object GhostLock54Runner {
    /** The payload, packaged under a library name so it survives APK packaging. */
    const val PAYLOAD = "libghostlock54.so"

    /** The KernelSU module, an asset because a `.ko` would be stripped by jniLibs handling. */
    const val MODULE_ASSET = "ghostlock54/kernelsu.ko"

    /** Where both files are staged. Flat, because the module path is baked into the C. */
    private const val DIR = "/data/local/tmp"
    const val PAYLOAD_PATH = "$DIR/ghostlock54"
    const val MODULE_PATH = "$DIR/kernelsu.ko"

    /** The only kernel this build targets. `uname -r` must equal it, not merely start with 5.4. */
    const val KERNEL = "5.4.254-qgki-gaa96eae94d32"

    /** The model the port was written for; shown in the row so a mismatch is obvious. */
    const val DEVICE = "OPPO Reno7 5G (PFJM10), Android 12"

    /**
     * KernelSU Manager's package.
     *
     * The module hands root to the manager rather than to this process, so the manager is what the
     * user actually opens afterwards. Kept here as well as in [LSPromise] because the two engines
     * share the same requirement but neither should have to depend on the other's object.
     */
    const val KSUN_PACKAGE = "me.weishu.kernelsu"

    enum class Availability {
        /** Running the exact kernel the offsets were written for. */
        READY,

        /** Connected, but a different kernel release. */
        KERNEL_MISMATCH,

        /** Payload or module missing from the build. */
        NOT_PACKAGED,

        /** Nothing to read, no connection. */
        UNKNOWN,
    }

    data class Probe(
        val availability: Availability,
        val kernel: String,
        val detail: String,
    ) {
        val canRun: Boolean get() = availability == Availability.READY
    }

    /**
     * Compares the running release against [KERNEL].
     *
     * Equality rather than a prefix test on purpose: `5.4.254-qgki-gaa96eae94d32` and
     * `5.4.254-qgki-gaa96eae94df` are the same kernel version and a different kernel, and every
     * offset in the payload would be wrong on the second one.
     */
    fun probe(
        context: Context,
        manager: AbsAdbConnectionManager,
        log: (String) -> Unit = {},
    ): Probe {
        val out = runCatching { AdbShell.exec(manager, "uname -r") }.getOrDefault("")
        val kernel = out.trim().lineSequence().firstOrNull().orEmpty()
        log("<i> uname -r: $kernel")

        val availability = when {
            kernel.isEmpty() -> Availability.UNKNOWN
            !isPayloadPresent(context) -> Availability.NOT_PACKAGED
            kernel != KERNEL -> Availability.KERNEL_MISMATCH
            else -> Availability.READY
        }
        val detail = when (availability) {
            Availability.READY -> "GhostLock54 for $KERNEL, module packaged"
            Availability.KERNEL_MISMATCH -> "built for $KERNEL; this kernel is $kernel"
            Availability.NOT_PACKAGED -> "the payload or kernelsu.ko is missing from this build"
            Availability.UNKNOWN -> "the kernel release could not be read"
        }
        log("<i> $detail")
        return Probe(availability, kernel, detail)
    }

    /** Both files are in this build: the native payload and the bundled module. */
    fun isPayloadPresent(context: Context): Boolean {
        val payload = File(context.applicationInfo.nativeLibraryDir, PAYLOAD).isFile
        val module = runCatching {
            context.assets.open(MODULE_ASSET).use { it.readBytes() }.isNotEmpty()
        }.getOrDefault(false)
        return payload && module
    }

    /**
     * Pushes the payload and the module, then runs the exploit.
     *
     * The run is synchronous and the exploit keeps its parent alive on purpose: the kernel-side
     * primitive leaves a futex reference behind, and letting the process exit would turn that into
     * a panic. The timeout is therefore generous and the caller is expected to treat a timeout as
     * "still running", not as a failure to report.
     */
    fun run(
        context: Context,
        manager: AbsAdbConnectionManager,
        log: (String) -> Unit = {},
        timeoutMs: Long = 240_000L,
    ): Result {
        val probe = probe(context, manager, log)
        if (!probe.canRun) {
            log("<e> ${probe.detail}")
            return Result(false, probe, probe.detail)
        }

        if (!pushPayload(context, manager, log)) {
            return Result(false, probe, "the payload could not be staged")
        }
        if (!pushModule(context, manager, log)) {
            return Result(false, probe, "kernelsu.ko could not be staged")
        }

        // Flat directory and the module path the C already expects; no -m needed.
        val command = "chmod 700 $PAYLOAD_PATH; $PAYLOAD_PATH 2>&1"
        log("$ $command")
        val out = runCatching { AdbShell.exec(manager, command, timeoutMs) }.getOrDefault("")
        if (out.isNotBlank()) log(out.trimEnd())

        val loaded = out.contains("[KSU] insmod ret=0") ||
            out.contains("kernelsu already loaded") ||
            out.contains("Now open KernelSU Manager")
        val rooted = loaded || out.contains("[CHILD]")
        val detail = when {
            loaded -> "kernelsu.ko loaded; open the KernelSU manager and grant root"
            rooted -> "the exploit ran but the module was not confirmed loaded"
            else -> "the exploit did not report a loaded module"
        }
        log(if (loaded) "<i> $detail" else "<e> $detail")
        return Result(loaded, probe, detail)
    }

    /**
     * Stages the payload as an executable.
     *
     * It lives in `nativeLibraryDir` because that is where Android unpacks `lib*.so` from jniLibs,
     * and the shell user cannot read that directory on most builds, so it is read here as the app
     * and pushed over ADB rather than exec'd in place.
     */
    private fun pushPayload(
        context: Context,
        manager: AbsAdbConnectionManager,
        log: (String) -> Unit,
    ): Boolean {
        val file = File(context.applicationInfo.nativeLibraryDir, PAYLOAD)
        val bytes = runCatching { file.readBytes() }.getOrNull()
        if (bytes == null || bytes.isEmpty()) {
            log("<e> $PAYLOAD is not in nativeLibraryDir; this build did not compile it")
            return false
        }
        log("$ push $PAYLOAD_PATH (${bytes.size} bytes)")
        if (!runCatching { AdbShell.push(manager, PAYLOAD_PATH, bytes) }.getOrDefault(false)) {
            log("<e> pushing $PAYLOAD_PATH failed")
            return false
        }
        return verifiedSize(manager, PAYLOAD_PATH, bytes.size, log)
    }

    private fun pushModule(
        context: Context,
        manager: AbsAdbConnectionManager,
        log: (String) -> Unit,
    ): Boolean {
        val bytes = runCatching {
            context.assets.open(MODULE_ASSET).use { it.readBytes() }
        }.getOrNull()
        if (bytes == null || bytes.isEmpty()) {
            log("<e> the bundled $MODULE_ASSET could not be read")
            return false
        }
        log("$ push $MODULE_PATH (${bytes.size} bytes)")
        if (!runCatching { AdbShell.push(manager, MODULE_PATH, bytes) }.getOrDefault(false)) {
            log("<e> pushing $MODULE_PATH failed")
            return false
        }
        return verifiedSize(manager, MODULE_PATH, bytes.size, log)
    }

    /** A truncated push reports its real failure much later, so the size is read back every time. */
    private fun verifiedSize(
        manager: AbsAdbConnectionManager,
        path: String,
        expected: Int,
        log: (String) -> Unit,
    ): Boolean {
        val actual = runCatching {
            AdbShell.exec(manager, "wc -c < '$path'")
        }.getOrDefault("").trim().toIntOrNull() ?: -1
        if (actual != expected) {
            log("<e> $path is $actual bytes, expected $expected")
            return false
        }
        return true
    }

    /**
     * What a run produced.
     *
     * @param moduleLoaded `kernelsu.ko` reported a successful load, which is what makes root
     *   survive the app being closed and reopenable from the manager
     */
    data class Result(
        val moduleLoaded: Boolean,
        val probe: Probe,
        val detail: String,
    )
}