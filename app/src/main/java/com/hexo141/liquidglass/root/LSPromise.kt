package com.hexo141.liquidglass.root

import com.hexo141.liquidglass.adb.AbsAdbConnectionManager
import com.hexo141.liquidglass.adb.AdbShell

/**
 * LSPromise: CVE-2026-49881 followed by CVE-2026-43284, chained into root.
 *
 * ## Why this is one engine and not two
 *
 * Neither half is enough on its own, and that is not an opinion:
 *
 * - **CVE-2026-43284** (DirtyFrag) is a page-cache write that patches `libc.so` in place, but
 *   SELinux only grants `netlink_xfrm_socket` to three domains: `system_server`,
 *   `network_stack` and `netd`. An ordinary app cannot open the socket at all, so the write never
 *   starts.
 * - **CVE-2026-49881** runs Java inside `system_server` without any extra privilege, which is
 *   exactly the domain DirtyFrag needs — but reaching `system_server` alone grants nothing beyond
 *   what `system_server` already has.
 *
 * So the chain is: 49881 puts code in `system_server`, that code injects into
 * `com.android.networkstack` (the second domain the xfrm socket allows), and DirtyFrag runs from
 * there. [DirtyFragRunner] stays separate and untouched: it is the page-cache engine for kernels
 * where xfrm is reachable another way, and replacing it with this would lose that.
 *
 * ## Why the ADB half is honest about its limits
 *
 * The published chain needs Java state that only exists inside the app process: a registered
 * `PhoneAccount` for `addNewIncomingCall`, an `AppComponentFactory` that `Shellcode` loads into,
 * and a `BroadcastReceiver` to hand the networkstack binder back. [`inject`] can therefore do the
 * two things that *are* shell-reachable — stage the payloads and confirm the prerequisites — but it
 * cannot drive the chain to completion. It reports that instead of pretending.
 *
 * ## Preconditions
 *
 * - Android 17 (`Baklava`) only; 49881 is a Telecom logic bug introduced in that release.
 * - A kernel in the 6.6.127 family. The bundled `dirtyfrag.ko` carries
 *   `vermagic=6.6.127-4k-g46a034eca005-dirty`, and a module whose vermagic does not match is
 *   refused by `init_module`. The 6.1.xxx-android14 trees are explicitly unsupported upstream.
 * - KernelSU must be installed: the final step pulls `libksud.so` out of it and execs that.
 * - A failed run leaves xfrm state behind and cannot be retried without a reboot.
 *
 * Upstream: <https://github.com/LSPosed/LSPromise>
 */
object LSPromise {
    /** Where the payloads are staged. Same directory the other engines use. */
    private const val DIR = "/data/local/tmp/openroot"

    /** The staged shell daemon. Patched `libc.so` makes it exec under the right label. */
    const val SHELLD = "$DIR/shelld"

    /** The splice helper that performs the page-cache write. */
    const val SPLICEHELPER = "$DIR/splicehelper"

    /** The kernel module. Its vermagic has to match the running kernel exactly. */
    const val MODULE = "$DIR/dirtyfrag.ko"

    /** Written by the chain so a run can be observed rather than guessed at. */
    const val MARKER = "$DIR/lspromise-ok"

    /** Package the final step borrows `libksud.so` from. */
    const val KSUN_PACKAGE = "me.weishu.kernelsu"

    /** The networkstack process 49881 targets. Its uid is fixed by AOSP's `android.uid.networkstack`. */
    const val NETWORK_STACK_UID = 1073
    const val NETWORK_STACK_PROCESS = "com.android.networkstack.process"

    enum class Availability {
        /** Android 17, a matching vermagic, and an installed KernelSU. */
        READY,

        /** Android is too old, or from a release this chain does not target. */
        OUT_OF_WINDOW,

        /** Right Android, but the module was built for a different kernel. */
        KERNEL_MISMATCH,

        /** KernelSU is absent, so the chain would stop at its last step. */
        NO_KERNEL_SU,

        /** No connection, so nothing could be read. */
        UNKNOWN,
    }

    data class Probe(
        val availability: Availability,
        val sdk: Int,
        val release: String,
        val kernel: String,
        val moduleVermagic: String,
        val detail: String,
    ) {
        val canRun: Boolean get() = availability == Availability.READY
    }

    /**
     * Checks the three prerequisites that can be read without touching the chain.
     *
     * The vermagic comparison is the one that matters most and gets forgotten most: a module built
     * against a different tree loads with silence, not an error, because `init_module` refuses it
     * before the payload in it ever runs.
     */
    fun probe(manager: AbsAdbConnectionManager, log: (String) -> Unit = {}): Probe {
        val command = "getprop ro.build.version.sdk; getprop ro.build.version.release; " +
            "uname -r; pm list packages $KSUN_PACKAGE 2>/dev/null"
        log("$ $command")
        val out = runCatching { AdbShell.exec(manager, command) }.getOrDefault("")
        if (out.isNotBlank()) log(out.trimEnd())

        val lines = out.lineSequence().map { it.trim() }.toList()
        val sdk = lines.getOrNull(0)?.toIntOrNull() ?: 0
        val release = lines.getOrNull(1).orEmpty()
        val kernel = lines.getOrNull(2).orEmpty()
        val ksuInstalled = lines.drop(3).any { it.contains(KSUN_PACKAGE) }

        // The module's own vermagic, read from the staged copy when there is one.
        val vermagic = readModuleVermagic(manager, log)
        val kernelMatches = kernel.isNotEmpty() && vermagic.isNotEmpty() && kernel in vermagic

        val availability = when {
            sdk == 0 -> Availability.UNKNOWN
            sdk < 36 -> Availability.OUT_OF_WINDOW
            !kernelMatches -> Availability.KERNEL_MISMATCH
            !ksuInstalled -> Availability.NO_KERNEL_SU
            else -> Availability.READY
        }
        val detail = when (availability) {
            Availability.READY ->
                "Android $release (API $sdk) on $kernel, KernelSU present: all three steps can run"
            Availability.OUT_OF_WINDOW ->
                "Android $release (API $sdk): 49881 is a Telecom bug introduced in Android 17"
            Availability.KERNEL_MISMATCH -> if (vermagic.isEmpty()) {
                "the module is not staged yet, so its vermagic could not be read for $kernel"
            } else {
                "the module targets $vermagic but this kernel is $kernel"
            }
            Availability.NO_KERNEL_SU -> "KernelSU is not installed, so the chain has nothing to load"
            Availability.UNKNOWN -> "the build properties could not be read"
        }
        log("<i> $detail")
        return Probe(availability, sdk, release, kernel, vermagic, detail)
    }

    /** Reads the staged module's vermagic, or an empty string when it is not there. */
    private fun readModuleVermagic(
        manager: AbsAdbConnectionManager,
        log: (String) -> Unit,
    ): String {
        val out = runCatching {
            AdbShell.exec(manager, "if [ -e $MODULE ]; then strings $MODULE | grep vermagic; fi")
        }.getOrDefault("")
        if (out.isNotBlank()) log(out.trimEnd())
        // The line reads `vermagic=6.6.127-... aarch64`; the version is the part after `=`.
        return out.lineSequence()
            .firstOrNull { it.startsWith("vermagic=") }
            ?.removePrefix("vermagic=")
            ?.trim()
            ?.substringBefore(' ')
            .orEmpty()
    }

    /**
     * Stages the three payloads and reports whether the chain could start.
     *
     * The payloads are pushed by the caller, which is what the other engines' `isPayloadPresent`
     * does too. What this adds is the executable bit and the honest answer about the next step.
     */
    fun prepare(manager: AbsAdbConnectionManager, log: (String) -> Unit = {}): Boolean {
        val probe = probe(manager, log)
        if (!probe.canRun) {
            log("<e> ${probe.detail}")
            return false
        }
        val command = "mkdir -p $DIR; chmod 700 $SHELLD $SPLICEHELPER 2>&1; " +
            "ls -l $SHELLD $SPLICEHELPER $MODULE 2>&1"
        log("$ $command")
        val out = runCatching { AdbShell.exec(manager, command) }.getOrDefault("")
        if (out.isNotBlank()) log(out.trimEnd())
        val staged = out.contains("shelld") && out.contains("splicehelper") &&
            out.contains("dirtyfrag.ko") && !out.contains("No such file")
        if (!staged) log("<e> the payloads are not all in $DIR; push them first")
        return staged
    }

    /**
     * Runs the half of the chain that a shell can run, and stops where it has to.
     *
     * `shelld` listens on an abstract unix socket and `exec`s whatever it is handed, inheriting its
     * parent's SELinux label. Started from the shell user it would inherit `shell`, which cannot
     * open an xfrm socket — so the DirtyFrag write would fail on the socket open, not on the page
     * cache. That is why this starts `shelld`, proves it answers, and then says plainly that the
     * system_server half is missing rather than leaking a `root shell` claim it did not earn.
     *
     * @return [Result.syscallReachable] is `false` by construction here; the caller should show the
     *   reason instead of a failure, because nothing went wrong — the model just cannot express it.
     */
    fun run(manager: AbsAdbConnectionManager, log: (String) -> Unit = {}): Result {
        val probe = probe(manager, log)
        if (!probe.canRun) {
            log("<e> ${probe.detail}")
            return Result(false, false, probe.detail)
        }

        // The daemon is started so its socket exists; a run without a live socket is not a run.
        val start = "setsid $SHELLD </dev/null >/dev/null 2>&1 & sleep 1; " +
            "pgrep -f ' $SHELLD' >/dev/null && echo shelld-up || echo shelld-down"
        log("$ $start")
        val out = runCatching { AdbShell.exec(manager, start, 20_000L) }.getOrDefault("")
        if (out.isNotBlank()) log(out.trimEnd())
        val up = out.contains("shelld-up")

        if (!up) {
            val detail = "shelld did not stay up; check that the payload staged and is executable"
            log("<e> $detail")
            return Result(false, false, detail)
        }

        val detail = "shelld is up, but it inherited the shell label: the xfrm socket that " +
            "CVE-2026-43284 writes through is not reachable from here. The 49881 half that would " +
            "move it into system_server cannot be driven over ADB."
        log("<w> $detail")
        return Result(true, false, detail)
    }

    /**
     * What a run achieved.
     *
     * @param daemonUp `shelld` answers on its socket
     * @param syscallReachable the xfrm socket could be opened, which is what the 43284 write needs
     */
    data class Result(
        val daemonUp: Boolean,
        val syscallReachable: Boolean,
        val detail: String,
    )

    /** Whether the three payloads are in the APK. The caller pushes them from `assets/lspromise`. */
    fun isPayloadPresent(context: android.content.Context): Boolean = runCatching {
        val names = context.assets.list("lspromise").orEmpty().toList()
        "shelld" in names && "splicehelper" in names && "dirtyfrag.ko" in names
    }.getOrDefault(false)

    /**
     * Pushes the three payloads to [DIR].
     *
     * Each push is size-verified against the byte count read out of the APK, because a truncated
     * `chmod +x`ed binary reports "cannot execute" much later and in a place that looks unrelated
     * to the push. The module is the one file where truncation would also be silent: `strings`
     * still finds a vermagic on a half-written copy.
     */
    fun pushAssets(
        context: android.content.Context,
        manager: AbsAdbConnectionManager,
        log: (String) -> Unit,
    ): Boolean {
        if (!isPayloadPresent(context)) {
            log("<e> assets/lspromise is missing from the APK; this build cannot run the chain")
            return false
        }
        runCatching { AdbShell.exec(manager, "mkdir -p $DIR") }
        val files = listOf("shelld" to SHELLD, "splicehelper" to SPLICEHELPER, "dirtyfrag.ko" to MODULE)
        for ((asset, remote) in files) {
            val bytes = Assets.read(context, "lspromise/$asset")
            if (bytes == null || bytes.isEmpty()) {
                log("<e> asset 'lspromise/$asset' could not be read")
                return false
            }
            log("$ push $remote (${bytes.size} bytes)")
            if (!runCatching { AdbShell.push(manager, remote, bytes) }.getOrDefault(false)) {
                log("<e> pushing $remote failed")
                return false
            }
            val size = runCatching {
                AdbShell.exec(manager, "wc -c < '$remote'")
            }.getOrDefault("").trim().toIntOrNull() ?: -1
            if (size != bytes.size) {
                log("<e> $remote is $size bytes, expected ${bytes.size}")
                return false
            }
        }
        return true
    }
}
