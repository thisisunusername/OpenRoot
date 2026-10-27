// SPDX-License-Identifier: GPL-3.0-or-later OR Apache-2.0

package com.hexo141.liquidglass.adb

import java.io.IOException

/**
 * Adapts the project's existing [AdbStream] to [ShellStream].
 *
 * Nothing is translated: `shell:` already merges the daemon's stdout and stderr into one pipe,
 * and [AdbStream] already reports the peer's close as an [IOException] plus [isClosed]. The
 * wrapper exists only so [AdbShell] can be written against the transport-neutral interface.
 */
class AdbStreamAdapter(private val stream: AdbStream) : ShellStream {

    override fun read(bytes: ByteArray, offset: Int, length: Int): Int =
        stream.read(bytes, offset, length)

    override fun write(bytes: ByteArray, offset: Int, length: Int) =
        stream.write(bytes, offset, length)

    override fun flush() = stream.flush()

    override fun isClosed(): Boolean = stream.isClosed

    @Throws(IOException::class)
    override fun close() = stream.close()
}