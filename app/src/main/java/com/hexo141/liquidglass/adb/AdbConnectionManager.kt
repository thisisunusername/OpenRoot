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

    /**
     * Swaps the ADB identity for a private key that was generated somewhere else.
     *
     * A device running `adb tcpip` never shows the "allow debugging" prompt, so adbd rejects every
     * key it does not already have in `/data/misc/adb/adb_keys` - and that directory is closed to
     * the shell user. Reusing the key of a client that connected before is the only way in without
     * root. The pairing flag is cleared afterwards because the new identity has not been accepted
     * yet, which keeps the main screen offering a connection instead of assuming one works.
     *
     * @return `true` when the key was parsed and stored, so a reconnect is worth attempting.
     */
    fun importKey(pem: String): Boolean {
        if (!keyManager.importPrivateKey(pem)) return false
        PairingState(context).isPaired = false
        transport = Transport.NONE
        return true
    }

    /** Whether the identity in use came from [importKey] rather than being generated here. */
    fun hasImportedKey(): Boolean = keyManager.isImported()

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
            // "Allowed" is not "usable": a server can hold the permission and still answer a start
            // request with nothing, and the app would then report a working transport while every
            // command quietly produced no output. One echo decides which case this is.
            if (ShizukuShell.probe()) {
                useShizuku(true)
                Log.i(TAG, "connected via Shizuku (${ShizukuShell.describePrivilege()})")
                return true
            }
            Log.w(
                TAG,
                "Shizuku is granted but could not start a process; falling back to ADB over TLS",
            )
            // Hand `shell:` back to the daemon: leaving the Shizuku hook installed would keep
            // routing every command into the server that just failed its probe.
            useShizuku(false)
        }
        val saved = PairingState(context).manualEndpoint
        val ok = if (saved != null) {
            // A saved manual address beats discovery: it was typed because discovery found nothing,
            // and searching again would wait out the whole timeout before failing the same way.
            runCatching { connectManual(context, saved) }.getOrElse {
                Log.w(TAG, "manual endpoint $saved failed, trying discovery", it)
                connectTls(context, timeoutMillis)
            }
        } else {
            connectTls(context, timeoutMillis)
        }
        if (ok) transport = Transport.ADB
        return ok
    }

    /**
     * Connects straight to an ADB endpoint the user typed in.
     *
     * Discovery through mDNS is the only route this code had, and it does not exist on a device
     * whose settings carry no wireless-debugging entry, nor on one where `adb tcpip` was used
     * instead. A host and a port need no discovery at all: `127.0.0.1:5555` is the daemon on the
     * same device, and any other address is that device reachable over the network.
     *
     * Shizuku is deliberately not consulted. Asking for a manual address is a statement that the
     * user wants this transport, so probing and falling back would ignore the request.
     *
     * @param endpoint either `host:port`, or a bare port meaning `127.0.0.1:<port>`
     */
    @Throws(IOException::class, InterruptedException::class, AdbPairingRequiredException::class)
    fun connectManual(context: Context, endpoint: String): Boolean {
        val (host, port) = parseEndpoint(endpoint)
            ?: throw IOException("'$endpoint' is not host:port")
        setLocalShell(null)
        transport = Transport.NONE
        val ok = connect(host, port)
        if (ok) {
            transport = Transport.ADB
            // Remember the address so a later reconnect and the status line agree with it.
            PairingState(context).manualEndpoint = "$host:$port"
        }
        return ok
    }

    /** Splits `host:port`, or a bare port, which the local daemon uses. */
    private fun parseEndpoint(endpoint: String): Pair<String, Int>? {
        val trimmed = endpoint.trim().removePrefix("adb://").removeSuffix("/")
        if (trimmed.isEmpty()) return null
        val colon = trimmed.lastIndexOf(':')
        val host: String
        val portText: String
        if (colon < 0) {
            host = "127.0.0.1"
            portText = trimmed
        } else {
            host = trimmed.substring(0, colon).ifEmpty { "127.0.0.1" }
            portText = trimmed.substring(colon + 1)
        }
        val port = portText.toIntOrNull() ?: return null
        if (port !in 1..65535) return null
        return host to port
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