// SPDX-License-Identifier: GPL-3.0-or-later OR Apache-2.0

package com.hexo141.liquidglass.adb

import android.util.Log
import rikka.shizuku.ShizukuRemoteProcess
import java.io.IOException
import java.io.InputStream
import java.util.concurrent.LinkedBlockingDeque
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * A shell channel backed by a process started through Shizuku.
 *
 * The semantics are made to match an ADB `shell:` service, because that is what every payload
 * runner already expects:
 *
 * - **stdout and stderr are merged** into one byte stream. An ADB shell service does this
 *   implicitly (both end up on the same pty/pipe); [ShizukuRemoteProcess] exposes them as two
 *   separate pipes, so two pump threads feed a single queue here. Dropping stderr would lose
 *   exactly the lines that matter when a payload fails.
 * - **The peer's close is reported as [IOException]** while [isClosed] is true, which is how
 *   [AdbStream] behaves and what [AdbShell] already handles.
 * - **No pty.** Shizuku's `newProcess` has no terminal support, so a payload's stdio stays block
 *   buffered and its log arrives in larger chunks. Callers only lose smoothness, not content.
 *
 * Writes go straight to the process's stdin, which is what [AdbShell.push] uses (`cat > path`).
 */
class ShizukuStream(
    private val process: ShizukuRemoteProcess,
    private val command: String,
) : ShellStream {

    private val queue = LinkedBlockingDeque<ByteArray>()

    /** Guards [outputDone] and the wait/notify handshake; [queue] itself is thread safe. */
    private val lock = Object()

    /**
     * Set once the process has exited **and** both pumps have drained.
     *
     * Waiting for the pipes to reach EOF is not enough on its own: Shizuku hands back two separate
     * pipes, and in practice one of them keeps `read()` blocked long after the child is gone, which
     * left every `exec()` waiting for the idle watchdog and returning an empty string. The reaper
     * below therefore watches the process itself, not the pipes.
     */
    @Volatile
    private var outputDone = false

    @Volatile
    private var closed = false

    private val livePumps = AtomicInteger(2)

    private inner class Pump(name: String, val source: InputStream) : Thread(name) {
        init {
            isDaemon = true
        }

        override fun run() {
            val buffer = ByteArray(4096)
            try {
                while (true) {
                    val read = source.read(buffer, 0, buffer.size)
                    if (read <= 0) break
                    queue.addLast(buffer.copyOf(read))
                }
            } catch (e: IOException) {
                // The process went away; anything already queued is still delivered.
                Log.v(TAG, "pump $name ended: ${e.message}")
            } finally {
                runCatching { source.close() }
                livePumps.decrementAndGet()
                maybeFinish()
                synchronized(lock) { lock.notifyAll() }
            }
        }
    }

    /**
     * Waits for the child to exit, then stops trusting the pipes.
     *
     * Once the process is gone the pumps are drained as far as they will go: whatever is still
     * queued is handed out, and the very next [read] reports EOF. Any pump that is still blocked in
     * `read()` is released by closing its pipe, which is safe here because the writer is dead.
     */
    private inner class Reaper : Thread("shizuku-reaper") {
        init {
            isDaemon = true
        }

        override fun run() {
            try {
                // Bounded: a wedged child must not keep this thread (and the stream) alive forever.
                process.waitForTimeout(REAPER_TIMEOUT_MS, TimeUnit.MILLISECONDS)
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
            } catch (e: Throwable) {
                Log.v(TAG, "waitFor failed for $command: ${e.message}")
            }
            processGone = true
            // Give the pumps a short grace period to drain what the child wrote, then cut them off.
            val deadline = System.currentTimeMillis() + DRAIN_GRACE_MS
            while (livePumps.get() > 0 && System.currentTimeMillis() < deadline) {
                Thread.sleep(10)
                if (queue.isEmpty() && livePumps.get() == 0) break
            }
            if (livePumps.get() > 0) {
                pumps.forEach { runCatching { it.source.close() } }
            }
            maybeFinish()
            synchronized(lock) { lock.notifyAll() }
        }
    }

    @Volatile
    private var processGone = false

    /** Marks the stream finished once the child is gone and the pumps have stopped feeding it. */
    private fun maybeFinish() {
        if (!processGone || closed) return
        if (livePumps.get() == 0 || queue.isEmpty()) {
            outputDone = true
        }
    }

    private val pumps = listOf(
        Pump("shizuku-stdout", process.inputStream),
        Pump("shizuku-stderr", process.errorStream),
    )

    init {
        pumps.forEach { it.start() }
        Reaper().start()
    }

    @Throws(IOException::class)
    override fun read(bytes: ByteArray, offset: Int, length: Int): Int {
        while (true) {
            // Drain what is already buffered first, so a closed stream still hands out its tail.
            val head = queue.pollFirst()
            if (head != null) {
                val count = minOf(length, head.size)
                System.arraycopy(head, 0, bytes, offset, count)
                if (count < head.size) {
                    queue.addFirst(head.copyOfRange(count, head.size))
                }
                return count
            }

            if (closed) throw IOException("Stream closed.")
            if (outputDone) return -1

            synchronized(lock) {
                if (queue.isEmpty() && !closed && !outputDone) {
                    try {
                        lock.wait(250)
                    } catch (e: InterruptedException) {
                        Thread.currentThread().interrupt()
                        throw IOException("Interrupted while reading", e)
                    }
                }
            }
        }
    }

    @Throws(IOException::class)
    override fun write(bytes: ByteArray, offset: Int, length: Int) {
        if (closed) throw IOException("Stream closed")
        try {
            process.outputStream.write(bytes, offset, length)
        } catch (e: RuntimeException) {
            // ShizukuRemoteProcess wraps RemoteException in RuntimeException.
            throw IOException("Failed to write to $command", e)
        }
    }

    @Throws(IOException::class)
    override fun flush() {
        if (closed) throw IOException("Stream closed")
        try {
            process.outputStream.flush()
        } catch (e: RuntimeException) {
            throw IOException("Failed to flush $command", e)
        }
    }

    override fun isClosed(): Boolean = closed

    override fun close() {
        if (closed) return
        closed = true
        // Shizuku keeps a started process alive until the caller dies, and AdbShell closes the
        // stream the moment a push has written its bytes, so the process has to be taken down here.
        runCatching { process.destroy() }
            .onFailure { Log.w(TAG, "destroy failed for $command", it) }
        // Unblock a pump stuck in read(); the pipes belong to the dead process at this point.
        pumps.forEach { runCatching { it.source.close() } }
        synchronized(lock) { lock.notifyAll() }
    }

    /**
     * Sends EOF on the child's stdin and waits for it to exit, without killing it.
     *
     * A `cat > file` only flushes when it sees the end of its input. Destroying the process instead
     * left every pushed file behind as 0 bytes: the writes had gone into the pipe, but the child
     * never got the chance to move them to disk.
     */
    override fun closeInput() {
        runCatching { process.outputStream.close() }
            .onFailure { Log.w(TAG, "closing stdin failed for $command", it) }
            .onSuccess {
                runCatching { process.waitForTimeout(STDIN_DRAIN_MS, TimeUnit.MILLISECONDS) }
                    .onFailure { Log.v(TAG, "waiting for $command did not settle", it) }
            }
    }

    private companion object {
        const val TAG = "ShizukuStream"

        /** How long the pumps may keep draining after the child exited before they are cut off. */
        const val DRAIN_GRACE_MS = 300L

        /** Upper bound on the reaper's wait; `AdbShell`'s own watchdog is the real deadline. */
        const val REAPER_TIMEOUT_MS = 600_000L

        /** How long a writer waits for its command to finish after the stdin EOF. */
        const val STDIN_DRAIN_MS = 30_000L
    }
}