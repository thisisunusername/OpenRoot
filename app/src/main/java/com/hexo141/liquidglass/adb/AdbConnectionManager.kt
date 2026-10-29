package com.hexo141.liquidglass.adb

import android.content.Context
import android.os.Build
import android.util.Log
import java.io.IOException
import java.security.PrivateKey
import java.security.cert.Certificate

/**
 * Connection manager with two transports:
 *
 * 1. **Shizuku** (preferred) - the Shizuku server lends this app a process running as `shell`
 *    (uid 2000) or `root` (uid 0). No wireless debugging, no mDNS, no pairing code, and it works
 *    from Android 6.0 up, which covers both older releases and ROMs with the wireless-debugging
 *    entry stripped out.
 * 2. **ADB over TLS** (fallback) - the original path: pair once with a code, then reuse the key.
 *
 * The switch lives here so every payload runner keeps taking the same [AbsAdbConnectionManager]
 * and never learns which transport is actually in use.
 */
class AdbConnectionManager private constructor(private val context: Context) : AbsAdbConnectionManager() {

    private val keyManager = AdbKeyManager(context)

    /** The last transport that actually produced a working channel. */
    @Volatile
    private var transport: Transport = Transport.NONE

    enum class Transport { NONE, SHIZUKU, ADB }

    init {
        setApi(Build.VERSION.SDK_INT)
        // Make a rejected key surface as AdbAuthenticationFailedException instead of silently
        // retrying, so the caller knows the pairing has to be redone.
        setThrowOnUnauthorised(true)
        ShizukuShell.attach(context)
    }

    override fun getPrivateKey(): PrivateKey = keyManager.privateKey

    override fun getCertificate(): Certificate = keyManager.certificate

    override fun getDeviceName(): String = AdbPairingService.DEVICE_NAME

    fun activeTransport(): Transport = transport

    /**
     * Turns the Shizuku transport on or off.
     *
     * Enabling it makes every `shell:` request go to a Shizuku-started process; the ADB connection,
     * if any, is left untouched so switching back costs nothing.
     */
    fun useShizuku(enabled: Boolean) {
        if (enabled) {
            // Shizuku gets the destination verbatim: it has no service layer, so `ShizukuShell`
            // strips the `shell:` / `shell,pty:` prefix itself and runs the rest through `sh`.
            // Stripping only `shell,pty:` here used to leave `shell:ls` on the command line, and
            // `sh` reported every such command as `inaccessible or not found`.
            setLocalShell { destination -> ShizukuShell.openStream(destination) }
            transport = Transport.SHIZUKU
        } else {
            setLocalShell(null)
            transport = Transport.NONE
        }
    }

    /**
     * Connects using whichever transport is available, Shizuku first.
     *
     * @return `true` when a shell channel can be opened afterwards.
     * @throws AdbAuthenticationFailedException when the daemon rejected our key, so the caller can
     *                                          drop the "paired" flag instead of showing a generic error.
     */
    @Throws(IOException::class, InterruptedException::class, AdbPairingRequiredException::class)
    fun connect(context: Context, timeoutMillis: Long): Boolean {
        if (ShizukuShell.isReady()) {
            useShizuku(true)
            Log.i(TAG, "connected via Shizuku (${ShizukuShell.describePrivilege()})")
            return true
        }
        val ok = connectTls(context, timeoutMillis)
        if (ok) transport = Transport.ADB
        return ok
    }

    companion object {
        private const val TAG = "AdbConnectionManager"

        @Volatile
        private var instance: AdbConnectionManager? = null

        /** Returns the shared manager, creating it on first use. */
        fun get(context: Context): AdbConnectionManager =
            instance ?: synchronized(this) {
                instance ?: AdbConnectionManager(context.applicationContext).also { instance = it }
            }

        /** Whether the shared manager currently holds a live connection (never creates one). */
        fun isConnected(): Boolean = instance?.isConnected() == true

        /** `true` when the existing manager is already served by Shizuku. */
        fun isUsingShizuku(): Boolean = instance?.transport == Transport.SHIZUKU
    }
}