package com.hexo141.liquidglass.adb

import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException

/** Runs shell commands through the ADB connection. */
object AdbShell {
    /**
     * Chunk size used when streaming a file into `cat`.
     *
     * Over ADB each write is answered with a READY before the next one goes out, so 32 KiB is free.
     * Over Shizuku the stream is an ordinary pipe with no acknowledgement: the writer races `cat`
     * for the pipe buffer, and a chunk the child cannot drain yet comes back as
     * `write failed: EPIPE (Broken pipe)`. 8 KiB kept the writer behind the reader on stock
     * Shizuku; 4 KiB leaves room for servers that size their pipe smaller still.
     */
    private const val PUSH_CHUNK = 4 * 1024

    /** How many times [push] reopens the pipe after the child drops it mid-transfer. */
    private const val PUSH_ATTEMPTS = 8

    /**
     * Base delay before a [push] retry, multiplied by the attempt number.
     *
     * A retry that starts immediately races the same cold start again and fails identically, which
     * is what `EPIPE` on attempt one through five looked like on a server whose `sh` takes a while
     * to exec `cat`.
     */
    private const val PUSH_RETRY_DELAY_MS = 250L

    /** A shell command that stops producing output for this long is treated as stuck. */
    private const val IDLE_TIMEOUT_MS = 15_000L

    /**
     * @param command command line, executed by the daemon's shell (`shell:<command>`)
     * @param timeoutMs how long the command may stay silent before the stream is closed
     * @return everything the command wrote to stdout, decoded as UTF-8
     */
    @Throws(Exception::class)
    fun exec(
        manager: AbsAdbConnectionManager,
        command: String,
        timeoutMs: Long = IDLE_TIMEOUT_MS,
    ): String {
        val stream = manager.openStream("shell:$command")
        val watchdog = StreamWatchdog(stream, timeoutMs)
        try {
            val out = ByteArrayOutputStream()
            val buffer = ByteArray(4096)
            while (true) {
                // AdbStream reports the peer's close as an IOException instead of EOF.
                val read = try {
                    stream.read(buffer, 0, buffer.size)
                } catch (e: IOException) {
                    if (stream.isClosed()) break else throw e
                }
                watchdog.touch()
                if (read <= 0) break
                out.write(buffer, 0, read)
            }
            return out.toString("UTF-8")
        } finally {
            watchdog.stop()
            runCatching { stream.close() }
        }
    }

    /**
     * Streams a command's output line by line, so long running payloads can be shown live.
     *
     * @return the command's exit status, or -1 when it could not be determined
     */
    @Throws(Exception::class)
    fun stream(
        manager: AbsAdbConnectionManager,
        command: String,
        onLine: (String) -> Unit,
        idleTimeoutMs: Long = 120_000L,
    ): Int {
        // `pty` matters: with a pipe the payload's stdio is block buffered, so its log only arrives
        // in 4 KB chunks. A pty makes it line buffered, i.e. real time like a terminal. The v1
        // service carries no exit status, so the wrapper echoes it as a marker instead.
        val stream = openStream(manager, "$command; echo \"$EXIT_MARKER\$?\"", pty = true)
        val watchdog = StreamWatchdog(stream, idleTimeoutMs)
        val pending = StringBuilder()
        var exitCode = -1
        try {
            val buffer = ByteArray(4096)
            while (true) {
                val read = try {
                    stream.read(buffer, 0, buffer.size)
                } catch (e: IOException) {
                    if (stream.isClosed()) break else throw e
                }
                watchdog.touch()
                if (read <= 0) break
                pending.append(String(buffer, 0, read, Charsets.UTF_8))
                while (true) {
                    val newline = pending.indexOf("\n")
                    if (newline < 0) break
                    val line = pending.substring(0, newline).trimEnd('\r')
                    pending.delete(0, newline + 1)
                    if (line.startsWith(EXIT_MARKER)) {
                        exitCode = line.removePrefix(EXIT_MARKER).trim().toIntOrNull() ?: -1
                    } else {
                        onLine(line)
                    }
                }
            }
            if (pending.isNotEmpty()) onLine(pending.toString().trimEnd('\r'))
        } finally {
            watchdog.stop()
            runCatching { stream.close() }
        }
        return exitCode
    }
    /**
     * Writes [bytes] to [remotePath] through the daemon's shell.
     *
     * Finishing the write is not the same as finishing the file: `cat` only moves its buffer to
     * disk once it sees the end of its input, so the channel's stdin is closed first and the child
     * is given time to exit. Killing the channel straight after the last byte used to leave every
     * pushed file at 0 bytes on the Shizuku transport.
     *
     * @return true when the bytes made it across in one pass
     */
    @Throws(Exception::class)
    fun push(manager: AbsAdbConnectionManager, remotePath: String, bytes: ByteArray): Boolean {
        var offset = 0
        var attempts = 0
        while (offset < bytes.size) {
            // The first pass truncates, a retry appends: the prefix on disk is already correct.
            val operator = if (offset == 0) ">" else ">>"
            val stream = manager.openStream("shell:cat $operator '$remotePath'")
            val startOfAttempt = offset
            // A dropped channel is recoverable, but only if the retry waits. Shizuku starts `sh`
            // in a fresh process per channel, and on a slower server the pipe is closed before the
            // child has exec'd `cat` - the write then fails with EPIPE on the very first chunk no
            // matter how small it is. Backing off before reopening gives that child time to run.
            if (attempts > 0) {
                try {
                    Thread.sleep(PUSH_RETRY_DELAY_MS * attempts)
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                }
            }
            try {
                while (offset < bytes.size) {
                    val length = minOf(PUSH_CHUNK, bytes.size - offset)
                    stream.write(bytes, offset, length)
                    offset += length
                    // Yield between chunks: the writer shares a pipe with `cat`, and writing the next
                    // chunk before `cat` drains the last one is what EPIPE means here.
                    Thread.yield()
                }
                stream.flush()
                stream.closeInput()
            } catch (e: IOException) {
                // The pipe broke mid-chunk: the bytes from the failed write may be half there, so
                // resume from the last confirmed offset and let `>>` append the rest.
                offset = startOfAttempt
                if (++attempts >= PUSH_ATTEMPTS) throw e
            } finally {
                runCatching { stream.close() }
            }
        }
        return true
    }

    /**
     * Stages [bytes] at [remotePath] using a file the shell can already read as the source.
     *
     * Feeding a shell command through its stdin is unreliable on the Shizuku transport: every
     * `cat > file` came out 0 bytes no matter how carefully the write half was closed. A file the
     * app writes into its own external cache directory sits on shared storage the `shell` user can
     * read, so the copy happens entirely inside the device with `cat`, and nothing crosses the
     * process boundary except the command line.
     *
     * Falls back to [push] when the cache directory is not usable.
     *
     * @param cacheDirectory a directory on shared storage the shell user can read
     * @return a one-line description of what was used, for the log
     */
    @Throws(Exception::class)
    fun stage(
        manager: AbsAdbConnectionManager,
        remotePath: String,
        bytes: ByteArray,
        cacheDirectory: File?,
        fileName: String,
        onLine: (String) -> Unit = {},
    ): String {
        if (cacheDirectory != null) {
            val relay = runCatching {
                cacheDirectory.mkdirs()
                val file = File(cacheDirectory, fileName)
                file.writeBytes(bytes)
                file
            }.getOrNull()

            if (relay != null && relay.length() == bytes.size.toLong()) {
                onLine("$ cat ${relay.absolutePath} > $remotePath")
                // `cat` is an external command: when it cannot be found or its source is
                // unreadable, the redirection has already created (and truncated) the target, so
                // the file exists but is empty and every later step fails for the wrong reason.
                // Checking the size here turns that into one clear line instead.
                val report = AdbShell.exec(
                    manager,
                    "rm -f '$remotePath'; cat '${relay.absolutePath}' > '$remotePath' 2>&1; " +
                        "echo \"rc=\$?\"; ls -l '$remotePath' 2>&1",
                    timeoutMs = 120_000,
                ).trim()
                // Leave nothing behind on shared storage once the copy is done.
                runCatching { relay.delete() }
                if (report.isNotEmpty() && !report.startsWith("rc=0")) {
                    onLine("<e> relay copy reported: ${report.replace('\n', ' ')}")
                }
                return "relay"
            }
        }

        onLine("$ cat > $remotePath    # ${bytes.size} bytes")
        push(manager, remotePath, bytes)
        return "stdin"
    }

    /**
     * Closes the stream when it stops producing data, so a daemon that never answers cannot leave a
     * caller waiting forever.
     */
    private class StreamWatchdog(private val stream: ShellStream, private val timeoutMs: Long) {
        @Volatile
        private var lastActivity = System.currentTimeMillis()

        private val thread = Thread({
            while (!Thread.currentThread().isInterrupted) {
                if (System.currentTimeMillis() - lastActivity > timeoutMs) {
                    runCatching { stream.close() }
                    return@Thread
                }
                try {
                    Thread.sleep(250)
                } catch (_: InterruptedException) {
                    return@Thread
                }
            }
        }, "adb-shell-watchdog").apply {
            isDaemon = true
            start()
        }

        fun touch() {
            lastActivity = System.currentTimeMillis()
        }

        fun stop() {
            thread.interrupt()
        }
    }

    /**
     * Sets [mode] on [remotePath] and confirms the kernel actually accepted it.
     *
     * Every engine runs its payload with `./name`, so a `chmod` that silently did nothing leaves a
     * file with the right bytes and the wrong permissions, and the failure only surfaces much later
     * as a vague "cannot run" or as `sh: ./payload: Permission denied`. Asking `stat` for the result
     * costs one extra round trip and turns that into a precise message.
     *
     * @param mode octal string, e.g. `"755"`
     * @return the permissions as reported afterwards, or `null` when they could not be read
     */
    @Throws(Exception::class)
    fun chmod(
        manager: AbsAdbConnectionManager,
        remotePath: String,
        mode: String,
    ): String? {
        val report = exec(
            manager,
            "chmod $mode '$remotePath' 2>&1; echo \"rc=\$?\"; " +
                "stat -c '%a' '$remotePath' 2>/dev/null || ls -l '$remotePath' 2>&1",
            timeoutMs = 30_000,
        ).trim()
        // The first line that is not the `rc=` marker is either the octal mode from `stat`, or the
        // `ls -l` listing (or an error) when `stat` is unavailable on this build.
        return report.lineSequence()
            .map { it.trim() }
            .firstOrNull { it.isNotEmpty() && !it.startsWith("rc=") }
    }

    /** Opens a shell service, falling back to a plain pipe when the daemon rejects the pty flag. */
    private fun openStream(
        manager: AbsAdbConnectionManager,
        command: String,
        pty: Boolean,
    ): ShellStream {
        if (pty) {
            // Shizuku has no terminal, so `shell,pty:` is passed through only when the destination
            // is really an ADB service; a local transport ignores the suffix itself.
            runCatching { return manager.openStream("shell,pty:$command") }
        }
        return manager.openStream("shell:$command")
    }

    private const val EXIT_MARKER = "__OPENROOT_EXIT:"
}
