package com.hexo141.liquidglass

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.content.res.Configuration
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.DisplayMetrics
import android.util.Log
import android.widget.Toast
import androidx.activity.OnBackPressedCallback
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.platform.ComposeView
import androidx.core.content.ContextCompat
import com.hexo141.liquidglass.adb.AdbAuthenticationFailedException
import com.hexo141.liquidglass.adb.AdbConnectionManager
import com.hexo141.liquidglass.adb.AdbKeyManager
import com.hexo141.liquidglass.adb.AdbPairingService
import com.hexo141.liquidglass.adb.PairingState
import com.hexo141.liquidglass.adb.ShizukuShell
import rikka.shizuku.Shizuku
import com.hexo141.liquidglass.consent.ConsentStore
import com.hexo141.liquidglass.device.DeviceInfo
import com.hexo141.liquidglass.root.DirtyFragRunner
import com.hexo141.liquidglass.root.ExploitMemory
import com.hexo141.liquidglass.root.BinderBombRunner
import com.hexo141.liquidglass.root.GhostLockRunner
import com.hexo141.liquidglass.root.GpuRunner
import com.hexo141.liquidglass.root.KsuManager
import com.hexo141.liquidglass.root.PctRunner
import com.hexo141.liquidglass.root.RootExploit
import com.hexo141.liquidglass.root.RootHandoff
import com.hexo141.liquidglass.root.RootShell
import com.hexo141.liquidglass.ui.ConsentScreen
import com.hexo141.liquidglass.ui.ConsentTransition
import com.hexo141.liquidglass.ui.ExploitLogScreen
import com.hexo141.liquidglass.ui.AboutScreen
import com.hexo141.liquidglass.ui.AppScaffold
import com.hexo141.liquidglass.ui.PairingScreen
import com.hexo141.liquidglass.ui.ExploitChoice
import com.hexo141.liquidglass.ui.SupportState
import com.hexo141.liquidglass.ui.VivoWiredScreen
import com.hexo141.liquidglass.vivo.VivoWiredController
import com.hexo141.liquidglass.vivo.progressFraction
import kotlin.math.roundToInt
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel

class MainActivity : AppCompatActivity() {

    private companion object {
        const val TAG = "MainActivity"

        /** Engine ids used by the picker; one per vulnerability, never per device or payload. */
        const val ENGINE_CVE_43499 = "cve-2026-43499"
        const val ENGINE_CVE_64560 = "cve-2026-64560"
        const val ENGINE_CVE_21479 = "cve-2025-21479"
        const val ENGINE_CVE_43284 = "cve-2026-43284"
        /** CVE-2020-0041: binder out-of-bounds write, the 5.4 / 5.4-qgki engine. */
        const val ENGINE_CVE_0041 = "cve-2020-0041"

        /** How long to wait for `_adb-tls-connect._tcp` before giving up on a direct connect. */
        const val CONNECT_TIMEOUT_MS = 6_000L

        /** Request code for the Shizuku permission dialog; only its own answer matters. */
        const val SHIZUKU_PERMISSION_REQUEST = 0x5A17

        /** Give adbd a moment to publish the connect service after the pairing handshake. */
        const val CONNECT_AFTER_PAIR_DELAY_MS = 700L

        /**
         * Reference width of the layout in dp. Bigger number = smaller UI (more dp per screen):
         * 411 is a Pixel/OnePlus phone, 460 draws everything about 11% smaller.
         */
        const val DESIGN_WIDTH_DP = 460f

        /** Density clamps, so neither a tiny nor a huge panel produces an unusable layout. */
        const val MIN_UI_SCALE = 1.0f
        const val MAX_UI_SCALE = 3.5f
    }

    /** First start: the GPL-3.0 text and the temporary-root disclaimer must both be accepted. */
    private val consentAccepted = mutableStateOf(false)

    /** Whether the pairing service runs; Compose state so the button label follows it. */
    private val pairingRunning = mutableStateOf(false)

    /** Already paired: adbd holds our public key, so no pairing code is needed. */
    private val paired = mutableStateOf(false)

    /** A direct connect is in flight. */
    private val connecting = mutableStateOf(false)

    /** adbd is connected. */
    private val connected = mutableStateOf(false)

    /** Direct connect failed: show the pairing button again so a code can be used. */
    private val needsPairing = mutableStateOf(false)

    /** Mirrors [ShizukuShell.status] so the screen can swap the pairing button for a grant button. */
    private val shizukuStatus = mutableStateOf(ShizukuShell.Status.NOT_INSTALLED)

    /** The endpoint typed in the manual field, or `null` before one worked. */
    private val manualEndpoint = mutableStateOf<String?>(null)

    /** Device info: local props first, replaced by the values read over ADB once connected. */
    private val deviceInfo = mutableStateOf<DeviceInfo?>(null)

    /** Support state, used directly by the status card. */
    private val supportState = mutableStateOf(SupportState.NotConnected)

    /** CVE id of the engine in use; null when nothing can run here. */
    private val engineLabel = mutableStateOf<String?>(null)

    /** A temporary-root payload is running. */
    private val exploiting = mutableStateOf(false)

    /** Live payload output. */
    private val exploitLog = mutableStateOf<List<String>>(emptyList())

    /** Result line after the payload ends. */
    private val exploitStatus = mutableStateOf<String?>(null)

    /** Progress bar, driven by the payload's real stages, 0..1. */
    private val exploitProgress = mutableStateOf(0f)

    /** Whether the vulnerability picker is shown. */
    private val pickerVisible = mutableStateOf(false)

    /** Active bottom-bar tab: 0 home, 1 vivo/iQOO OTG, 2 exploit log, 3 about. */
    private val selectedTab = mutableStateOf(0)

    /** Vulnerabilities offered for the connected device. */
    private val exploitChoices = mutableStateOf<List<ExploitChoice>>(emptyList())

    /** Resolved root manager (with its ksud path); null when none is installed. */
    private val ksudTarget = mutableStateOf<KsuManager.Target?>(null)

    /** Root command channel available (bootstrap came up). */
    private val commandMode = mutableStateOf(false)

    /** Auto-connect at most once per foreground entry, so a failure does not loop. */
    private var autoConnectTried = false

    /** The Shizuku probe runs once per activity, so the transport is not re-tested constantly. */
    private var shizukuProbed = false

    private val refreshHandler = Handler(Looper.getMainLooper())

    /** Activity-scoped so a running vivo flow survives tab switches; released in onDestroy. */
    private val vivoScope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private var vivoController: VivoWiredController? = null

    /** While pairing runs in the background, align the state once a second. */
    private val refreshTick = object : Runnable {
        override fun run() {
            refreshState()
            if (pairingRunning.value) refreshHandler.postDelayed(this, 1000)
        }
    }

    /** After a successful pair, connect once without asking for another code. */
    private val pairingConnect = Runnable {
        if (paired.value && !connected.value && !connecting.value) {
            connect(silent = false)
        }
    }

    /**
     * Asks the Shizuku server to prove it can start a process, once per foreground entry.
     *
     * Runs the probe on a worker thread: it opens a real channel, and a server that is unhealthy
     * answers slowly or not at all. When it fails the status becomes [ShizukuShell.Status.UNUSABLE]
     * and the pairing button appears, which is the only way out of a grant that is already given.
     */
    private val shizukuProbe = Runnable {
        if (shizukuProbed) return@Runnable
        shizukuProbed = true
        Thread({
            val usable = ShizukuShell.probe()
            refreshHandler.post {
                // Re-read the status: probe() cached the answer, so this now reports UNUSABLE.
                shizukuStatus.value = ShizukuShell.status()
                if (!usable) {
                    // Give the user the transport that works instead of leaving them on a dead end.
                    autoConnectTried = false
                    maybeAutoConnect()
                }
            }
        }, "shizuku-probe").start()
    }

    private val requestNotificationPermission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
            if (granted) startPairing() else toast(R.string.adb_pairing_permission_needed)
        }

    /** Pairing succeeded: refresh the screen and connect without a code. */
    private val pairingStateListener =
        SharedPreferences.OnSharedPreferenceChangeListener { _, key ->
            if (key == PairingState.KEY_PAIRED || key == PairingState.KEY_PAIRED_AT) {
                runOnUiThread {
                    refreshState(pairingSucceeded = key == PairingState.KEY_PAIRED_AT)
                }
            }
        }

    /**
     * Makes the layout measure the same on every device, ignoring "Display size" and "Font size".
     *
     * The density is derived from the shortest screen side so the layout always spans
     * [DESIGN_WIDTH_DP] dp: devices ship wildly different factory densities, and using the raw
     * physical one made the cards look bloated on some of them and correct on others. Raising the
     * design width is the single knob for the overall scale — a bigger number means more dp fit on
     * the screen, i.e. smaller text, cards and paddings. It is clamped so a tiny or a huge panel
     * does not end up unusable, and `fontScale` is pinned to 1.0 for the same reason.
     *
     * The activity has no `configChanges`, so a system change recreates it and lands here again.
     */
    override fun attachBaseContext(newBase: Context) {
        val config = Configuration(newBase.resources.configuration)
        config.fontScale = 1f

        val metrics = newBase.resources.displayMetrics
        val shortestSide = minOf(metrics.widthPixels, metrics.heightPixels)
        if (shortestSide > 0) {
            val scale = (shortestSide / DESIGN_WIDTH_DP).coerceIn(MIN_UI_SCALE, MAX_UI_SCALE)
            config.densityDpi = (scale * DisplayMetrics.DENSITY_DEFAULT).roundToInt()
        }

        super.attachBaseContext(newBase.createConfigurationContext(config))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_main)
        // The wallpaper runs edge to edge; each screen pads its own content against
        // WindowInsets.safeDrawing, so nothing sits under the status or navigation bar.

        consentAccepted.value = ConsentStore.isAccepted(this)

        // Shizuku listeners: the binder can arrive late (Shizuku started after this app) and the
        // user can grant access at any moment, so the connection state is re-evaluated on each event.
        ShizukuShell.addPermissionListener(shizukuPermissionListener)
        ShizukuShell.addBinderAliveListener(shizukuBinderAliveListener)
        ShizukuShell.addBinderDeadListener(shizukuBinderDeadListener)

        // Back closes the log page or the picker first, and only then leaves the app.
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                when {
                    selectedTab.value != 0 -> selectedTab.value = 0
                    pickerVisible.value -> pickerVisible.value = false
                    else -> {
                        isEnabled = false
                        onBackPressedDispatcher.onBackPressed()
                    }
                }
            }
        })

        findViewById<ComposeView>(R.id.main).setContent {
            // Fade into the main screen once both documents are accepted; before that it is not
            // composed at all and no ADB work happens.
            ConsentTransition(
                accepted = consentAccepted.value,
                consent = { ConsentScreen(onAccept = ::acceptConsent) },
                main = {
                    AppScaffold(
                        selectedTab = selectedTab.value,
                        onTabSelected = { selectedTab.value = it },
                        home = { backdrop ->
                            PairingScreen(
                                running = pairingRunning.value,
                                paired = paired.value,
                                connecting = connecting.value,
                                connected = connected.value,
                                needsPairing = needsPairing.value,
                                shizukuStatus = shizukuStatus.value,
                                supportState = supportState.value,
                                engineLabel = engineLabel.value,
                                deviceInfo = deviceInfo.value,
                                exploiting = exploiting.value,
                                exploitLog = exploitLog.value,
                                exploitStatus = exploitStatus.value,
                                exploitChoices = exploitChoices.value,
                                pickerVisible = pickerVisible.value,
                                backdrop = backdrop,
                                manualEndpoint = manualEndpoint.value,
                                onManualConnect = ::connectManual,
                                onToggle = ::onPrimaryAction,
                                onExploit = ::openEnginePicker,
                                onPickEngine = ::startExploit,
                                onDismissPicker = { pickerVisible.value = false },
                                onOpenLog = { selectedTab.value = 2 },
                            )
                        },
                        log = { backdrop ->
                            ExploitLogScreen(
                                lines = exploitLog.value,
                                status = exploitStatus.value,
                                progress = exploitProgress.value,
                                commandMode = commandMode.value,
                                running = exploiting.value ||
                                    (vivoController?.state?.running == true),
                                onCommand = ::runRootCommand,
                                backdrop = backdrop,
                            )
                        },
                        about = { backdrop ->
                            AboutScreen(backdrop = backdrop)
                        },
                        vivo = { backdrop ->
                            VivoWiredScreen(
                                backdrop = backdrop,
                                controllerProvider = ::ensureVivoController,
                            )
                        },
                    )
                },
            )
        }

        if (consentAccepted.value) startMain()
    }

    /** Both documents accepted: store the version and time, then start what the screen needs. */
    private fun acceptConsent() {
        ConsentStore.accept(this)
        consentAccepted.value = true
        startMain()
        beginLiveUpdates()
    }

    private fun startMain() {
        // Fill local device info first so the cards are never empty; ADB values replace it.
        deviceInfo.value = DeviceInfo.fromLocal(this)
        refreshState()
        intent?.let { handleDebugPair(it) }
    }

    /** State sync while the main screen lives: one tick a second, instant pairing updates, one auto-connect. */
    private fun beginLiveUpdates() {
        // Reset before refreshState(): a pairing success detected there schedules the delayed
        // direct connect and marks the auto-connect as handled, so it is not attempted twice.
        autoConnectTried = false
        refreshState()
        getSharedPreferences(PairingState.PREF_NAME, MODE_PRIVATE)
            .registerOnSharedPreferenceChangeListener(pairingStateListener)
        maybeAutoConnect()
        refreshHandler.removeCallbacks(refreshTick)
        refreshHandler.postDelayed(refreshTick, 1000)
    }

    override fun onResume() {
        super.onResume()
        // No main screen and no auto-connect before the documents are accepted.
        if (!consentAccepted.value) return
        beginLiveUpdates()
    }

    override fun onPause() {
        refreshHandler.removeCallbacks(refreshTick)
        getSharedPreferences(PairingState.PREF_NAME, MODE_PRIVATE)
            .unregisterOnSharedPreferenceChangeListener(pairingStateListener)
        super.onPause()
    }

    override fun onDestroy() {
        ShizukuShell.removePermissionListener(shizukuPermissionListener)
        ShizukuShell.removeBinderAliveListener(shizukuBinderAliveListener)
        ShizukuShell.removeBinderDeadListener(shizukuBinderDeadListener)
        vivoController?.dispose()
        vivoController = null
        vivoScope.cancel()
        refreshHandler.removeCallbacksAndMessages(null)
        super.onDestroy()
    }

    // ------------------------------------------------------------- Shizuku plumbing

    /** The user answered the Shizuku dialog: connect if granted, otherwise say why not. */
    private val shizukuPermissionListener =
        Shizuku.OnRequestPermissionResultListener { _, grantResult ->
            runOnUiThread {
                if (grantResult == PackageManager.PERMISSION_GRANTED) {
                    Log.i(TAG, "Shizuku permission granted (${ShizukuShell.describePrivilege()})")
                    connect()
                } else {
                    Log.w(TAG, "Shizuku permission denied")
                    toast(R.string.shizuku_permission_denied)
                    refreshState()
                }
            }
        }

    /** Shizuku was (re)started: a granted app can connect immediately, an ungranted one is asked. */
    private val shizukuBinderAliveListener = Shizuku.OnBinderReceivedListener {
        runOnUiThread {
            Log.i(TAG, "Shizuku binder received")
            autoConnectTried = false
            maybeAutoConnect()
        }
    }

    /** Shizuku died: whatever ran through it is gone, so the UI must stop claiming it is connected. */
    private val shizukuBinderDeadListener = Shizuku.OnBinderDeadListener {
        runOnUiThread {
            Log.i(TAG, "Shizuku binder died")
            // Only the local transport is affected; an ADB connection survives.
            if (AdbConnectionManager.isUsingShizuku()) {
                AdbConnectionManager.get(this).useShizuku(false)
            }
            autoConnectTried = false
            refreshState()
        }
    }

    private fun ensureVivoController(): VivoWiredController {
        vivoController?.let { return it }
        val controller = VivoWiredController(
            context = this,
            scope = vivoScope,
            onLog = { line -> logLine("[vivo] $line") },
            onStateChanged = { state ->
                exploitStatus.value = state.status
                exploitProgress.value = state.progressFraction()
                if (state.running) commandMode.value = false
            },
        )
        vivoController = controller
        return controller
    }

    private fun refreshState(
        updatePairing: Boolean = true,
        pairingSucceeded: Boolean = false,
    ) {
        if (updatePairing) pairingRunning.value = AdbPairingService.isRunning()
        // Cheap enough to poll: one binder ping plus one permission check.
        shizukuStatus.value = ShizukuShell.status()
        // A granted server still has to prove it can start a process, and the grant button is the
        // dead end that appears when it cannot. Probe off the main thread so the screen is not
        // blocked, then refresh the status once the answer is known.
        if (shizukuStatus.value == ShizukuShell.Status.READY) {
            refreshHandler.post(shizukuProbe)
        }
        val wasPaired = paired.value
        val isPaired = PairingState(this).isPaired
        paired.value = isPaired
        if (manualEndpoint.value == null) {
            manualEndpoint.value = PairingState(this).manualEndpoint
        }
        val isConnected = AdbConnectionManager.isConnected()
        connected.value = isConnected
        if (!isConnected) {
            supportState.value = SupportState.NotConnected
            engineLabel.value = null
            // Drop the picker when the connection is gone; the button is hidden as well.
            pickerVisible.value = false
        }
        // A re-pair keeps the boolean true, so the timestamp event is the reliable success edge.
        if (isPaired && (pairingSucceeded || !wasPaired)) {
            // The service stops itself after a successful pair; the button must read "Start" if a
            // later direct connect fails and brings it back.
            pairingRunning.value = false
            needsPairing.value = false
            refreshHandler.removeCallbacks(pairingConnect)
            refreshHandler.postDelayed(pairingConnect, CONNECT_AFTER_PAIR_DELAY_MS)
            autoConnectTried = true
        }
        loadDeviceInfo()
    }

    // ------------------------------------------------------------------ actions

    /**
     * Connects to an endpoint the user typed, skipping discovery.
     *
     * Runs off the main thread because the handshake blocks, and reports the failure inline: the
     * usual reason is a port that is not listening, and a toast that names the address says that
     * in one line.
     */
    private fun connectManual(endpoint: String) {
        // Echo the tap: this device drops third-party logs, so without a visible marker a silent
        // `return` below is indistinguishable from a tap that never arrived.
        Toast.makeText(this, "connecting to $endpoint…", Toast.LENGTH_SHORT).show()
        if (connecting.value || connected.value) return
        connecting.value = true
        Thread({
            val outcome = runCatching {
                AdbConnectionManager.get(this).connectManual(this, endpoint)
            }
            runOnUiThread {
                connecting.value = false
                if (outcome.getOrNull() == true) {
                    connected.value = true
                    manualEndpoint.value = endpoint
                    // A manual connection needs no pairing code either, so the flag is set the same
                    // way a Shizuku connection sets it.
                    paired.value = true
                    PairingState(this).markPaired()
                    supportState.value = SupportState.Checking
                    Log.i(TAG, "connected manually to $endpoint")
                    loadDeviceInfo()
                } else {
                    // The reason has to reach the user: this device filters third-party logs, so a
                    // message that only exists in logcat is invisible. The exception type and its
                    // message distinguish a closed port from a rejected key.
                    val reason = outcome.exceptionOrNull()
                    val detail = when (val e = reason) {
                        null -> "returned false"
                        else -> "${e.javaClass.simpleName}: ${e.message ?: "no message"}"
                    }
                    Log.w(TAG, "manual connect to $endpoint failed: $detail", reason)
                    Toast.makeText(
                        this,
                        "$endpoint -> $detail",
                        Toast.LENGTH_LONG,
                    ).show()
                }
            }
        }, "adb-manual-connect").start()
    }

    /**
     * Connect directly when the device is already paired instead of asking for a code again; only a
     * failure brings the pairing button back.
     *
     * A device paired before the isPaired flag existed still has our ADB key stored, so that case
     * tries one silent direct connect and fills the flag in when it works.
     */
    private fun maybeAutoConnect() {
        if (autoConnectTried) return
        if (pairingRunning.value || connected.value || connecting.value) return
        // Shizuku is ready and already granted: connect without any ADB key or pairing at all.
        // `status()` reports UNUSABLE once the probe failed, so a server that cannot start a
        // process falls through to the pairing route instead of being retried forever.
        if (ShizukuShell.status() == ShizukuShell.Status.READY) {
            autoConnectTried = true
            connect()
            return
        }
        // Shizuku is installed and running but not granted yet; ask once, the answer is handled
        // by the permission listener which then calls maybeAutoConnect again.
        if (ShizukuShell.status() == ShizukuShell.Status.PERMISSION_REQUIRED) {
            autoConnectTried = true
            ShizukuShell.requestPermission(SHIZUKU_PERMISSION_REQUEST)
            return
        }
        val isPaired = paired.value
        if (!isPaired && !AdbKeyManager.hasStoredKey(this)) return
        autoConnectTried = true
        connect(silent = !isPaired)
    }

    private fun connect(silent: Boolean = false) {
        if (connecting.value) return
        connecting.value = true
        needsPairing.value = false
        Thread({
            val outcome = runCatching {
                // Shizuku first: it needs no pairing and works on devices without wireless debugging.
                // Falls back to the original ADB TLS path when Shizuku is unavailable.
                AdbConnectionManager.get(this).connect(this, CONNECT_TIMEOUT_MS)
            }
            runOnUiThread {
                connecting.value = false
                if (outcome.getOrNull() == true) {
                    connected.value = true
                    supportState.value = SupportState.Checking
                    // A Shizuku connection has no notion of "paired", so the flag is set anyway:
                    // every later code path treats it as "do not ask the user for a code".
                    paired.value = true
                    PairingState(this).isPaired = true
                    Log.i(TAG, "connected via ${AdbConnectionManager.get(this).activeTransport()}")
                    loadDeviceInfo()
                } else {
                    val error = outcome.exceptionOrNull()
                    Log.w(TAG, "connect failed (silent=$silent)", error)
                    // Only blame the grant when the grant is actually the problem. A live binder is
                    // not enough: a server that answers but cannot start a process keeps the binder
                    // alive, and telling the user to grant again sends them in circles because the
                    // grant is already there. That case belongs on the pairing route below.
                    val shizukuStatus = ShizukuShell.status()
                    if (shizukuStatus == ShizukuShell.Status.PERMISSION_REQUIRED ||
                        shizukuStatus == ShizukuShell.Status.PERMISSION_DENIED
                    ) {
                        toast(R.string.shizuku_permission_required)
                        return@runOnUiThread
                    }
                    if (shizukuStatus == ShizukuShell.Status.UNUSABLE) {
                        toast(R.string.shizuku_unusable)
                        needsPairing.value = true
                        return@runOnUiThread
                    }
                    if (silent) return@runOnUiThread
                    // adbd rejected our key: the pairing is really gone
                    if (error is AdbAuthenticationFailedException) {
                        PairingState(this).isPaired = false
                        paired.value = false
                    }
                    needsPairing.value = true
                    toast(R.string.adb_connect_failed_fallback)
                }
            }
        }, "adb-direct-connect").start()
    }

    /**
     * What can actually run on this device right now. Single source of truth for card + picker.
     *
     * The picker lists vulnerabilities (CVE ids), not devices or payload variants: the payload for
     * a given CVE is resolved from the device here, so one row covers every build of that bug.
     */
    private data class Availability(
        val profile: Boolean,
        val pageCache: String?,
        val gpuMatched: Boolean,
        val gpuPayload: GpuRunner.Payload?,
        val pctMatched: Boolean,
        val pctPayload: PctRunner.Payload?,
        val ghostLock: String?,
        val binderBomb: String?,
    )

    private fun availability(info: DeviceInfo?): Availability {
        // No `connected.value` read here: this runs off the main thread too, where snapshot reads
        // can be stale. A non-null DeviceInfo already means the device answered.
        if (info == null) return Availability(false, null, false, null, false, null, null, null)
        val profile = RootExploit.isPayloadPresent(this) && RootExploit.hasProfile(this, info.kernel)
        val pageCache = if (DirtyFragRunner.isPayloadPresent(this)) {
            DirtyFragRunner.describe(info.androidRelease, info.kernel)
        } else {
            null
        }
        // A Qualcomm GPU is necessary but not sufficient: whether the firmware is patched is only
        // known after a run, so the card reports Untested until ExploitMemory has an answer.
        val gpuMatched = GpuRunner.isSupported(info)
        val gpuPayload = GpuRunner.payloadFor(info)
            ?.takeIf { GpuRunner.isPayloadPresent(this, it) }
        // Same rule for CVE-2026-64560: the device family only says the port is worth trying, the
        // payload's own `--preflight` decides whether this build is the ported one.
        val pctMatched = PctRunner.isSupported(info)
        val pctPayload = PctRunner.payloadFor(info)
            ?.takeIf { PctRunner.isPayloadPresent(this, it) }
        // GhostLock is the one engine whose support is decided up front: the bundled profile either
        // carries offsets for this exact `uname -r` or it does not, and nothing needs to run first.
        val ghostLock = GhostLockRunner.describe(this, info.kernel)
        // CVE-2020-0041 is profile-driven too: it covers 5.4 and 5.4-qgki builds from one binary,
        // and the profile either carries the eleven offsets this `uname -r` needs or it does not.
        val binderBomb = if (BinderBombRunner.isPayloadPresent(this)) {
            BinderBombRunner.describe(this, info.kernel)
        } else {
            null
        }
        return Availability(
            profile,
            pageCache,
            gpuMatched,
            gpuPayload,
            pctMatched,
            pctPayload,
            ghostLock,
            binderBomb,
        )
    }

    private fun resolveEngine(info: DeviceInfo): Pair<String?, SupportState> {
        val available = availability(info)
        if (available.profile) {
            return getString(R.string.engine_kernel_profile) to SupportState.Supported
        }
        // GhostLock comes before the payload engines: its support is a data question the bundled
        // profile set answers immediately, while the others can only promise "worth trying".
        val ghostLock = available.ghostLock
        if (ghostLock != null) {
            return ghostLock to SupportState.Supported
        }
        // Same reasoning for CVE-2020-0041: an exact profile for this `uname -r` is a fact, not a
        // guess, so it outranks the "worth trying" engines below.
        val binderBomb = available.binderBomb
        if (binderBomb != null) {
            return binderBomb to SupportState.Supported
        }
        // A matched device build is more specific than "this SoC has a GPU", so it comes first.
        if (available.pctPayload != null) {
            val state = when (ExploitMemory.result(this, info.kernel, ExploitMemory.ENGINE_PCT)) {
                true -> SupportState.Supported
                false -> SupportState.Unsupported
                null -> SupportState.Candidate
            }
            return PctRunner.describe(info) to state
        }
        if (available.gpuPayload != null) {
            val state = when (ExploitMemory.result(this, info.kernel, ExploitMemory.ENGINE_GPU)) {
                true -> SupportState.Supported
                false -> SupportState.Unsupported
                null -> SupportState.Candidate
            }
            return GpuRunner.describe(info) to state
        }
        val label = available.pageCache ?: return null to SupportState.Unsupported
        // Without a profile this is only "worth trying": a run is the only way to know.
        val state = when (ExploitMemory.result(this, info.kernel)) {
            true -> SupportState.Supported
            false -> SupportState.Unsupported
            null -> SupportState.Candidate
        }
        return label to state
    }

    /** Pulls the device details over ADB, replacing the locally read placeholder. */
    private fun loadDeviceInfo() {
        if (!connected.value) return
        Thread({
            val info = runCatching { DeviceInfo.fromAdb(AdbConnectionManager.get(this)) }
                .onFailure { Log.w(TAG, "cannot read device info over adb", it) }
                .getOrNull()
            if (info != null) {
                Log.i(TAG, "device info from adb: $info")
                // Decide on the main thread: snapshot reads on another thread can be stale.
                runOnUiThread {
                    val (engine, state) = resolveEngine(info)
                    Log.i(TAG, "availability: profile=${availability(info).profile} " +
                        "pageCache=${availability(info).pageCache}")
                    deviceInfo.value = info
                    engineLabel.value = engine
                    supportState.value = state
                }
                val ksud = KsuManager.resolve(this, AdbConnectionManager.get(this)) { line ->
                    Log.i(TAG, line)
                }
                runOnUiThread { ksudTarget.value = ksud }
            }
        }, "adb-device-info").start()
    }

    private fun onPrimaryAction() {
        when {
            pairingRunning.value -> stopPairing()
            connecting.value -> Unit // already busy
            // Shizuku running but not granted yet: the button only exists to open that dialog.
            !connected.value &&
                ShizukuShell.status() == ShizukuShell.Status.PERMISSION_REQUIRED ->
                ShizukuShell.requestPermission(SHIZUKU_PERMISSION_REQUEST)
            else -> requestStart()
        }
    }

    /**
     * Runs temporary root: the payload is pushed to /data/local/tmp over ADB and executed as the
     * `shell` user, with its output mirrored live in the log card.
     */
    /** Exploit tapped: let the user pick a vulnerability first. */
    private fun openEnginePicker() {
        if (exploiting.value) return
        // The button is hidden until adbd is connected; this is the second line of defence.
        if (!connected.value) {
            toast(R.string.exploit_needs_adb)
            return
        }
        // All four CVEs are always listed; each row explains whether it can run.
        exploitChoices.value = buildChoices(deviceInfo.value)
        pickerVisible.value = true
    }

    private fun buildChoices(info: DeviceInfo?): List<ExploitChoice> {
        val kernel = info?.kernel.orEmpty()
        val available = availability(info)
        val manager = ksudTarget.value
        val noConnection = info == null
        val handoff = if (manager == null) {
            "root command channel"
        } else {
            "starts ${manager.packageName}"
        }

        return listOf(
            ExploitChoice(
                id = ENGINE_CVE_43499,
                title = "CVE-2026-43499",
                detail = when {
                    noConnection -> "Connect to adb first"
                    available.ghostLock != null -> "${available.ghostLock}, profile ready"
                    available.profile -> "Kernel profile for $kernel"
                    !RootExploit.isPayloadPresent(this) -> "Payload not packaged for this ABI"
                    else -> "No profile for $kernel"
                },
                enabled = available.ghostLock != null || available.profile,
            ),
            ExploitChoice(
                id = ENGINE_CVE_0041,
                title = "CVE-2020-0041",
                detail = when {
                    noConnection -> "Connect to adb first"
                    available.binderBomb != null ->
                        "${available.binderBomb}, profile ready, $handoff"
                    !BinderBombRunner.isPayloadPresent(this) ->
                        "Payload not packaged for this ABI"
                    else -> "No 5.4 / 5.4-qgki profile for $kernel"
                },
                enabled = available.binderBomb != null,
            ),
            ExploitChoice(
                id = ENGINE_CVE_64560,
                title = "CVE-2026-64560",
                detail = when {
                    noConnection -> "Connect to adb first"
                    !available.pctMatched -> "No ported build for this device"
                    available.pctPayload == null -> "Payload not packaged for this ABI"
                    else -> "Race, up to 32 attempts, SELinux stays off, $handoff"
                },
                enabled = available.pctPayload != null,
            ),
            ExploitChoice(
                id = ENGINE_CVE_21479,
                title = "CVE-2025-21479",
                detail = when {
                    noConnection -> "Connect to adb first"
                    !available.gpuMatched -> "GPU not supported"
                    available.gpuPayload == null -> "Payload not packaged for this ABI"
                    else -> "SELinux stays off, $handoff"
                },
                enabled = available.gpuPayload != null,
            ),
            ExploitChoice(
                id = ENGINE_CVE_43284,
                title = "CVE-2026-43284",
                detail = when {
                    noConnection -> "Connect to adb first"
                    available.pageCache == null -> "Kernel not covered by the module images"
                    else -> "${available.pageCache}, $handoff"
                },
                enabled = available.pageCache != null,
            ),
        )
    }

    private fun startExploit(engineId: String) {
        pickerVisible.value = false
        if (exploiting.value) return
        // The payload is pushed over ADB, so do nothing without a connection.
        if (!connected.value) {
            toast(R.string.exploit_needs_adb)
            return
        }
        val info = deviceInfo.value ?: return
        // The payload is resolved from the device, not from the row: one row per CVE.
        val gpuPayload = if (engineId == ENGINE_CVE_21479) {
            GpuRunner.payloadFor(info)?.takeIf { GpuRunner.isPayloadPresent(this, it) }
        } else {
            null
        }
        val pctPayload = if (engineId == ENGINE_CVE_64560) {
            PctRunner.payloadFor(info)?.takeIf { PctRunner.isPayloadPresent(this, it) }
        } else {
            null
        }
        // CVE-2026-43284 hands off to a manager when one is installed, otherwise it keeps a root
        // command channel; the page cache engine itself does not care which. Which one applies is
        // decided after a fresh resolve inside the worker, not from the cached value.
        when (engineId) {
            ENGINE_CVE_43499 -> if (!RootExploit.hasProfile(this, info.kernel)) return
            ENGINE_CVE_0041 ->
                if (!BinderBombRunner.isSupported(this, info.kernel)) return
            ENGINE_CVE_64560 -> if (pctPayload == null) return
            ENGINE_CVE_21479 -> if (gpuPayload == null) return
            else -> if (!DirtyFragRunner.isSupported(info.androidRelease, info.kernel)) return
        }

        exploiting.value = true
        exploitLog.value = emptyList()
        exploitStatus.value = null
        exploitProgress.value = 0f
        commandMode.value = false
        // The log is its own tab: show it while the payload runs.
        selectedTab.value = 2
        Thread({
            // Resolving ksud scans /data/app over ADB: done once on this worker and shared by all
            // four engines, which also puts the scan itself in the log.
            val outcome = runCatching {
                val ksud = KsuManager.resolve(this, AdbConnectionManager.get(this), ::logLine)
                    ?.takeIf { it.packageName.isNotEmpty() }
                when {
                    engineId == ENGINE_CVE_43499 -> runProfileEngine(info, ksud)
                    engineId == ENGINE_CVE_0041 -> runBinderEngine(info, ksud)
                    pctPayload != null -> runPctEngine(info, pctPayload, ksud)
                    gpuPayload != null -> runGpuEngine(info, gpuPayload, ksud)
                    else -> runPageCacheEngine(
                        info = info,
                        ksud = ksud,
                        mode = if (ksud != null) {
                            DirtyFragRunner.Mode.KERNEL_SU
                        } else {
                            DirtyFragRunner.Mode.ROOT_COMMAND
                        },
                    )
                }
            }
            runOnUiThread {
                exploiting.value = false
                exploitProgress.value = 1f
                exploitStatus.value = outcome.getOrElse { error ->
                    Log.w(TAG, "exploit failed", error)
                    error.message ?: error.javaClass.simpleName
                }
            }
        }, "root-exploit").start()
    }

    private fun reportProgress(value: Float) {
        runOnUiThread { exploitProgress.value = value }
    }

    private fun logLine(line: String) {
        runOnUiThread { exploitLog.value = (exploitLog.value + line).takeLast(300) }
    }

    /** CVE-2026-43499: the payload picks its profile by `uname -r` and late-loads ksud itself. */
    private fun runProfileEngine(info: DeviceInfo, ksud: KsuManager.Target?): String {
        val result = RootExploit.run(
            context = this,
            manager = AdbConnectionManager.get(this),
            release = info.kernel,
            ksudPath = ksud?.ksudPath,
            ksudPackage = ksud?.packageName,
            onLine = ::logLine,
            onProgress = ::reportProgress,
        )
        ExploitMemory.record(this, info.kernel, result.kernelSuLoaded)
        return when {
            result.kernelSuLoaded -> {
                // The payload loads the module itself; the app only has to bring the manager up.
                val opened = KsuManager.launchWithRetry(
                    context = this,
                    manager = AdbConnectionManager.get(this),
                    packageName = ksud?.packageName.orEmpty(),
                    log = ::logLine,
                )
                getString(if (opened) R.string.exploit_ksu_opened else R.string.exploit_ksu_manual)
            }
            result.exitCode == 0 -> getString(R.string.exploit_finished)
            else -> getString(R.string.exploit_exit_code, result.exitCode)
        }
    }

    /**
     * CVE-2020-0041: same shape as the GPU engine, but the payload is profile-driven so the runner
     * stages an offset file next to the binary. One binary covers plain 5.4 and 5.4-qgki; which
     * kernel it is targeting is decided entirely by that profile.
     */
    private fun runBinderEngine(info: DeviceInfo, ksud: KsuManager.Target?): String {
        val result = BinderBombRunner.run(
            context = this,
            manager = AdbConnectionManager.get(this),
            kernelRelease = info.kernel,
            suManager = ksud,
            onLine = ::logLine,
            onProgress = ::reportProgress,
        )
        ExploitMemory.record(this, info.kernel, result.handoff.rooted, ExploitMemory.ENGINE_BINDER)
        return reportHandoff(ksud, result.handoff, result.exitCode)
    }

    /**
     * CVE-2025-21479: the payload runs as `shell` over the ADB channel and re-execs the staged
     * `bootstrap` as a child once root is held; bootstrap then late-loads ksud or starts the root
     * command channel according to its preferences.
     */
    private fun runGpuEngine(
        info: DeviceInfo,
        payload: GpuRunner.Payload,
        ksud: KsuManager.Target?,
    ): String {
        val result = GpuRunner.run(
            context = this,
            manager = AdbConnectionManager.get(this),
            payload = payload,
            suManager = ksud,
            onLine = ::logLine,
            onProgress = ::reportProgress,
        )
        ExploitMemory.record(this, info.kernel, result.handoff.rooted, ExploitMemory.ENGINE_GPU)
        return reportHandoff(ksud, result.handoff, result.exitCode)
    }

    /**
     * CVE-2026-64560: the payload runs `--preflight` first to confirm the fingerprint and kernel
     * really are the ported build, then the race. Once root is held it hands the root child to the
     * staged bootstrap, same as the other engines.
     */
    private fun runPctEngine(
        info: DeviceInfo,
        payload: PctRunner.Payload,
        ksud: KsuManager.Target?,
    ): String {
        val result = PctRunner.run(
            context = this,
            manager = AdbConnectionManager.get(this),
            payload = payload,
            suManager = ksud,
            onLine = ::logLine,
            onProgress = ::reportProgress,
        )
        // A refusal before the race says nothing about the vulnerability, so it is not remembered.
        if (!result.attempted) {
            return if (result.buildMismatch) {
                getString(R.string.exploit_profile_gate_failed)
            } else {
                getString(R.string.exploit_exit_code, result.exitCode)
            }
        }
        ExploitMemory.record(this, info.kernel, result.handoff.rooted, ExploitMemory.ENGINE_PCT)
        return reportHandoff(ksud, result.handoff, result.exitCode)
    }

    /** CVE-2026-43284: the module is loaded by the kernel; bootstrap and ksud are staged over ADB. */
    private fun runPageCacheEngine(
        info: DeviceInfo,
        ksud: KsuManager.Target?,
        mode: DirtyFragRunner.Mode,
    ): String {
        val result = DirtyFragRunner.run(
            context = this,
            manager = AdbConnectionManager.get(this),
            androidRelease = info.androidRelease,
            kernelRelease = info.kernel,
            suManager = ksud,
            mode = mode,
            onLine = ::logLine,
            onProgress = ::reportProgress,
        )
        ExploitMemory.record(this, info.kernel, result.handoff.rooted)
        return reportHandoff(ksud, result.handoff, result.exitCode)
    }

    /**
     * Turns what `bootstrap` started into the status line and, when KernelSU is up, opens the
     * manager. A root that exists but has no manager (or whose late-load failed) is reported as
     * the command channel instead of being thrown away as "not vulnerable".
     */
    private fun reportHandoff(
        ksud: KsuManager.Target?,
        handoff: RootHandoff.Result,
        exitCode: Int,
    ): String {
        logLine("<i> ${handoff.detail}")
        return when (handoff.state) {
            RootHandoff.State.KERNEL_SU -> {
                val opened = KsuManager.launchWithRetry(
                    context = this,
                    manager = AdbConnectionManager.get(this),
                    packageName = ksud?.packageName.orEmpty(),
                    log = ::logLine,
                )
                getString(if (opened) R.string.exploit_ksu_opened else R.string.exploit_ksu_manual)
            }
            RootHandoff.State.COMMAND -> {
                runOnUiThread { commandMode.value = true }
                getString(R.string.exploit_root_ready)
            }
            RootHandoff.State.NONE ->
                if (exitCode == 0) {
                    getString(R.string.exploit_finished)
                } else {
                    getString(R.string.exploit_exit_code, exitCode)
                }
        }
    }

    /** Runs one command through the root channel and mirrors its output while it runs. */
    private fun runRootCommand(command: String) {
        logLine("$ $command")
        Thread({
            runCatching {
                RootShell.run(AdbConnectionManager.get(this), command) { line -> logLine(line) }
            }.onFailure { error -> logLine("<e> ${error.message}") }
        }, "root-shell").start()
    }

    /** Debug-only hook so an ADB-driven smoke test can run a pairing attempt with a known code. */
    private fun handleDebugPair(intent: Intent) {
        val code = intent.getStringExtra(AdbPairingService.EXTRA_DEBUG_CODE) ?: return
        val port = intent.getIntExtra(AdbPairingService.EXTRA_DEBUG_PORT, -1)
        val host = intent.getStringExtra(AdbPairingService.EXTRA_DEBUG_HOST)
        AdbPairingService.debugPair(this, code, port, host)
    }

    private fun requestStart() {
        if (hasNotificationPermission()) {
            startPairing()
        } else {
            requestNotificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    private fun startPairing() {
        AdbPairingService.start(this)
        pairingRunning.value = true
        refreshHandler.removeCallbacks(refreshTick)
        refreshHandler.postDelayed(refreshTick, 1000)
    }

    private fun stopPairing() {
        AdbPairingService.stop(this)
        refreshHandler.removeCallbacks(refreshTick)
        // Set the UI state directly. Re-reading isRunning() here races the asynchronous
        // stopService(): the old value would flip the button back to "Stop".
        pairingRunning.value = false
        refreshState(updatePairing = false)
    }

    private fun hasNotificationPermission(): Boolean =
        Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED

    private fun toast(resId: Int) = Toast.makeText(this, resId, Toast.LENGTH_SHORT).show()
}
