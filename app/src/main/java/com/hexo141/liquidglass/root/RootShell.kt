package com.hexo141.liquidglass.root

import java.io.File

import com.hexo141.liquidglass.adb.AbsAdbConnectionManager
import com.hexo141.liquidglass.adb.AdbShell

/**
 * Command channel to the root daemon started by `bootstrap` in root-command mode.
 *
 * The daemon polls `cmd` in the staging directory and writes the output to `out`, so a command is
 * just a file write plus a poll - no persistent socket and no manager required. The output file is
 * tailed while the command runs, so the log fills in as the command produces data instead of
 * appearing all at once at the end.
 */
object RootShell {
    private const val DIR = "/data/local/tmp/openroot"
    private const val CMD = "$DIR/cmd"
    private const val OUT = "$DIR/out"
    private const val DONE = "$DIR/done"

    /**
     * Runs [command] as root, forwarding its output to [onLine] as it arrives.
     *
     * @param timeoutMs how long to wait for the command to finish
     * @return the full output
     */
    @Throws(Exception::class)
    fun run(
        manager: AbsAdbConnectionManager,
        command: String,
        timeoutMs: Long = 60_000,
        cacheDirectory: File? = null,
        onLine: (String) -> Unit = {},
    ): String {
        AdbShell.exec(manager, "rm -f $CMD $OUT $DONE")
        AdbShell.stage(manager, CMD, command.toByteArray(), cacheDirectory, "stage-cmd.sh")

        val full = StringBuilder()
        val pending = StringBuilder()
        val deadline = System.currentTimeMillis() + timeoutMs
        var finished = false

        while (System.currentTimeMillis() < deadline) {
            // Re-read the whole file and forward only what is new; the files are tiny.
            val current = AdbShell.exec(manager, "cat $OUT 2>/dev/null")
            if (current.length > full.length) {
                val delta = current.substring(full.length)
                full.append(delta)
                pending.append(delta)
                while (true) {
                    val newline = pending.indexOf("\n")
                    if (newline < 0) break
                    onLine(pending.substring(0, newline).trimEnd('\r'))
                    pending.delete(0, newline + 1)
                }
            }

            val probe = AdbShell.exec(manager, "[ -f $DONE ] && echo yes || echo no")
            if (probe.contains("yes")) {
                finished = true
                break
            }
            Thread.sleep(250)
        }

        // Anything written after the last poll (or without a trailing newline).
        val tail = AdbShell.exec(manager, "cat $OUT 2>/dev/null")
        if (tail.length > full.length) {
            pending.append(tail.substring(full.length))
            full.setLength(0)
            full.append(tail)
        }
        if (pending.isNotEmpty()) onLine(pending.toString().trimEnd('\r', '\n'))

        AdbShell.exec(manager, "rm -f $OUT $DONE $CMD")
        return if (finished) full.toString() else full.toString() + "\n[timeout after ${timeoutMs / 1000}s]"
    }
}
