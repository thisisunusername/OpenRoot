package com.hexo141.liquidglass.root

import com.hexo141.liquidglass.adb.AbsAdbConnectionManager
import com.hexo141.liquidglass.adb.AdbShell

/**
 * Reads what the staged `bootstrap` actually managed to start after a payload handed root over.
 *
 * `bootstrap` leaves one marker per stage in `/dev`, which is a tmpfs: a marker can only come from
 * the current boot, so it is a reliable "this run got that far" signal. The marker that decides the
 * outcome is the last one:
 *
 * - `dfm6`  KernelSU module loaded, the manager can be opened.
 * - `dfm7`  the late-load failed but a root command channel was started instead (bootstrap falls
 *           back on purpose, see native-or/bootstrap.c).
 * - `dfm1`  bootstrap ran, nothing is running yet: only a real `id` through the channel can tell.
 * - `dfme0/dfme1/dfme2`  the stage that failed, kept for the log.
 *
 * `dfm1` is touched before anything else runs, so it must never be treated as success on its own.
 *
 * The handoff is asynchronous (the page cache payload exits long before the kernel module execs
 * `bootstrap`), so the wait happens **on the device**: one shell command blocks until a decisive
 * marker shows up and then lists them once. Polling from here would drop the same `ls` block into
 * the log card every second.
 */
object RootHandoff {
    /**
     * What a run actually produced.
     *
     * The order is the preference order the caller relies on: KernelSU is the only outcome that
     * survives a reboot, Magisk is the next best thing, a bare command channel is the floor, and the
     * MediaTek payload is reported separately because it is a different code path with a different
     * manager requirement rather than a worse KernelSU.
     */
    enum class State { NONE, KERNEL_SU, MAGISK, COMMAND, MAGISK_LEGACY }

    /**
     * Which engine produced the root, kept apart from [State] so the manager pairing can be decided
     * from one value.
     */
    enum class Payload { NONE, KERNEL_SU, MAGISK, COMMAND, MEDIATEK }

    data class Result(
        val state: State,
        val markers: Set<String>,
        val detail: String,
        val payload: Payload = Payload.NONE,
    ) {
        val rooted: Boolean get() = state != State.NONE

        /**
         * `true` when the run produced a manager the caller should install, as opposed to a bare
         * root channel which has nothing to install a manager for.
         */
        val wantsManager: Boolean
            get() = state == State.KERNEL_SU ||
                state == State.MAGISK ||
                state == State.MAGISK_LEGACY
    }

    private const val LIST_COMMAND =
        "ls /dev/dfm1 /dev/dfm6 /dev/dfm7 /dev/dfmm1 /dev/dfmme1 /dev/dfmg1 " +
            "/dev/dfme0 /dev/dfme1 /dev/dfme2 2>/dev/null"

    /**
     * Waits up to [seconds] for a decisive marker, then prints whatever exists.
     *
     * `dfm1` is deliberately not a stopping condition: it appears the moment bootstrap starts,
     * which is before ksud has had a chance to load. `dfmg1` is the Magisk fallback, which bootstrap
     * only touches after the KernelSU late-load has already failed.
     */
    private fun waitCommand(seconds: Int): String =
        "c=0; until [ -e /dev/dfm6 ] || [ -e /dev/dfmg1 ] || [ -e /dev/dfm7 ] || " +
            "[ -e /dev/dfmm1 ] || [ -e /dev/dfmme1 ] || [ -e /dev/dfme0 ] || " +
            "[ -e /dev/dfme1 ] || [ -e /dev/dfme2 ] || [ \$c -ge $seconds ]; do " +
            "c=\$((c+1)); sleep 1; done; $LIST_COMMAND"

    /**
     * @param log receives one command line and the device output, so the log card shows why the run
     *        is reported the way it is
     * @param waitMs upper bound for the on-device wait
     */
    fun probe(
        manager: AbsAdbConnectionManager,
        log: (String) -> Unit = {},
        waitMs: Long = 15_000,
    ): Result {
        val seconds = (waitMs / 1000).toInt().coerceIn(1, 60)
        log("$ [waiting up to ${seconds}s for /dev/dfm*]")
        val listing = runCatching {
            // The shell stays silent for the whole wait, so the watchdog has to outlive it.
            AdbShell.exec(manager, waitCommand(seconds), timeoutMs = waitMs + 5_000)
        }.getOrDefault("")
        listing.trimEnd().lineSequence().filter { it.isNotBlank() }.forEach(log)

        val markers = listing.lineSequence()
            .map { it.trim().substringAfterLast('/') }
            .filter { it.isNotEmpty() }
            .toSet()

        if ("dfm6" in markers) {
            return Result(
                State.KERNEL_SU, markers,
                "KernelSU module loaded", Payload.KERNEL_SU,
            )
        }
        /* `dfmg1` is checked before the `dfme*` branch on purpose: a successful Magisk fallback also
         * leaves `dfme2` behind (it records that the KernelSU late-load failed), so the generic
         * failure branch would otherwise report this run as a failure. */
        if ("dfmg1" in markers) {
            return Result(
                State.MAGISK, markers,
                "KernelSU late-load failed, Magisk payload loaded instead", Payload.MAGISK,
            )
        }
        if ("dfmm1" in markers) {
            return Result(
                State.MAGISK_LEGACY, markers,
                "MediaTek payload loaded Magisk 20.4 into /sbin", Payload.MEDIATEK,
            )
        }
        if ("dfmme1" in markers) {
            return Result(
                State.NONE, markers,
                "the MediaTek payload ran but did not create /sbin/su", Payload.MEDIATEK,
            )
        }
        if ("dfm7" in markers || "dfm1" in markers) {
            if (channelAnswers(manager)) {
                val detail = if ("dfm7" in markers) {
                    "neither KernelSU nor Magisk loaded, root command channel is up"
                } else {
                    "root command channel is up"
                }
                return Result(State.COMMAND, markers, detail, Payload.COMMAND)
            }
        }
        if (markers.any { it.startsWith("dfme") }) {
            return Result(State.NONE, markers, failureReason(markers), Payload.NONE)
        }
        val detail = if (markers.isEmpty()) {
            "bootstrap did not run"
        } else {
            "bootstrap ran but no root channel answered"
        }
        return Result(State.NONE, markers, detail, Payload.NONE)
    }

    /** The daemon only counts as up if it answers a command with uid 0. */
    private fun channelAnswers(manager: AbsAdbConnectionManager): Boolean =
        runCatching { RootShell.run(manager, "id", timeoutMs = 2_500) }
            .getOrDefault("")
            .contains("uid=0")

    private fun failureReason(markers: Set<String>): String = when {
        "dfme2" in markers -> "KernelSU late-load failed and no command channel answered"
        "dfme1" in markers -> "disabling modules failed and no command channel answered"
        "dfme0" in markers -> "bootstrap could not read its preferences"
        else -> "bootstrap reported a failure"
    }
}
