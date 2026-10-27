// SPDX-License-Identifier: GPL-3.0-or-later OR Apache-2.0

package com.hexo141.liquidglass.adb

import java.io.Closeable

/**
 * The four operations [AdbShell] actually needs from a live shell channel.
 *
 * Two implementations exist:
 * - [AdbStreamAdapter]  a channel multiplexed over the ADB TLS connection to `adbd`.
 * - [ShizukuStream]     a local process started by the Shizuku server as shell (uid 2000).
 *
 * Both deliver **stdout and stderr interleaved in one byte stream**, which is what an ADB
 * `shell:` service does natively; [ShizukuStream] merges the two pipes itself so the payload
 * pipeline cannot tell which transport it is running on.
 *
 * Keeping this tiny interface separate from [AdbStream] lets the whole payload pipeline run on
 * either transport without knowing which one it is on.
 */
interface ShellStream : Closeable {

    /**
     * @return number of bytes read, or `-1` when the peer has closed the channel.
     * @throws java.io.IOException when the channel is gone; callers treat that as EOF after
     *                             checking [isClosed], exactly like [AdbStream] does.
     */
    fun read(bytes: ByteArray, offset: Int, length: Int): Int

    fun write(bytes: ByteArray, offset: Int, length: Int)

    fun flush()

    /**
     * A method rather than a property so it maps straight onto [AdbStream.isClosed] and stays
     * usable as `stream.isClosed` from Kotlin call sites.
     */
    fun isClosed(): Boolean
}
