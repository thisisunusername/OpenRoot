// SPDX-License-Identifier: GPL-3.0-or-later OR Apache-2.0

package com.hexo141.liquidglass.adb

import android.util.Log
import rikka.shizuku.ShizukuRemoteProcess
import java.io.IOException
import java.io.InputStream
import java.util.concurrent.LinkedBlockingDeque
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

    /** Both pipes draining means the process wrote everything it is going to write. */
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
                if (livePumps.decrementAndGet() == 0) {
                    outputDone = true
                }
                synchronized(lock) { lock.notifyAll() }
            }
        }
    }

    private val pumps = listOf(
        Pump("shizuku-stdout", process.inputStream),
        Pump("shizuku-stderr", process.errorStream),
    )

    init {
        pumps.forEach { it.start() }
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

    private companion object {
        const val TAG = "ShizukuStream"
    }
}