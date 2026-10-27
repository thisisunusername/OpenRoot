package com.hexo141.liquidglass.adb

import java.io.ByteArrayOutputStream
import java.io.IOException

/** Runs shell commands through the ADB connection. */
object AdbShell {
    /**
     * Chunk size used when streaming a file into `cat`.
     *
     * Over ADB each write is answered with a READY before the next one goes out, so 32 KiB is free.
     * Over Shizuku the stream is an ordinary pipe with no acknowledgement: the writer races `cat`
     * for the pipe buffer, and a chunk the child cannot drain yet comes back as
     * `write failed: EPIPE (Broken pipe)`. 8 KiB keeps the writer behind the reader.
     */
    private const val PUSH_CHUNK = 8 * 1024

    /** How many times [push] reopens the pipe after the child drops it mid-transfer. */
    private const val PUSH_ATTEMPTS = 5

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
     */
    @Throws(Exception::class)
    fun push(manager: AbsAdbConnectionManager, remotePath: String, bytes: ByteArray) {
        var offset = 0
        var attempts = 0
        while (offset < bytes.size) {
            // The first pass truncates, a retry appends: the prefix on disk is already correct.
            val operator = if (offset == 0) ">" else ">>"
            val stream = manager.openStream("shell:cat $operator '$remotePath'")
            val startOfAttempt = offset
            try {
                while (offset < bytes.size) {
                    val length = minOf(PUSH_CHUNK, bytes.size - offset)
                    stream.write(bytes, offset, length)
                    offset += length
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
