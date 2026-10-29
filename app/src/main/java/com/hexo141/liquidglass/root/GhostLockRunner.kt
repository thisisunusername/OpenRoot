// SPDX-License-Identifier: GPL-3.0-or-later OR Apache-2.0
package com.hexo141.liquidglass.root

import android.content.Context
import android.util.Log

/**
 * Fifth engine: CVE-2026-43499, the futex PI waiter use-after-free ("GhostLock").
 *
 * Unlike the other three engines this one carries no per-device payload binary. The exploit is one
 * program driven entirely by a **kernel profile**: a table of struct offsets and a kernel address
 * pair recovered from that exact build. Support is therefore "is there a profile whose `release`
 * matches `uname -r` byte for byte" - a device either has one or it does not, and no run is needed
 * to find out.
 *
 * The profile set under `assets/ghostlock/` is copied from YuKongA/ghostlock-app, which is the
 * reference implementation of this bug. Keeping the data separate from the code means a new kernel
 * is a new file, not a new release of this app.
 */
object GhostLockRunner {

    private const val TAG = "GhostLock"

    /** Where the profiles live in the APK. */
    private const val ASSET_DIR = "ghostlock"

    /** The index file that maps a `release` to its profile, `index.conf`. */
    private const val INDEX = "$ASSET_DIR/index.conf"

    /** A profile that is known to exist in the APK. */
    data class Profile(
        /** Exact `uname -r`, e.g. `6.1.138-android14-11-g151cf2b6bfbe-ab13719792`. */
        val release: String,
        /** File name inside `assets/ghostlock/`. */
        val file: String,
        /** The `release` is a `*-template` reference, never matched automatically. */
        val template: Boolean,
    )

    /** Parsed once per process: the index is a few hundred entries and changes only with an APK. */
    @Volatile
    private var index: List<Profile>? = null

    @Volatile
    private var byRelease: Map<String, Profile>? = null

    /**
     * The profile for [kernelRelease], or null when this build has none.
     *
     * Matching is exact on purpose. GhostLock reads raw offsets out of the running kernel, so a
     * near miss is not "probably fine" - it is a wrong address, which panics the device.
     */
    fun profileFor(context: Context, kernelRelease: String): Profile? {
        val release = kernelRelease.trim()
        if (release.isEmpty()) return null
        val table = byReleaseOf(context) ?: return null
        return table[release]?.takeIf { !it.template }
    }

    /** Human readable engine name for the status card, e.g. `CVE-2026-43499 (6.1.138-...)`. */
    fun describe(context: Context, kernelRelease: String): String? {
        val profile = profileFor(context, kernelRelease) ?: return null
        return "CVE-2026-43499 (${profile.release})"
    }

    /**
     * True when this build has a usable profile for [kernelRelease].
     *
     * No payload check: the exploit program is one binary shared by every profile, so what decides
     * availability is purely whether the offsets for this kernel are present.
     */
    fun isSupported(context: Context, kernelRelease: String): Boolean =
        profileFor(context, kernelRelease) != null

    /** How many kernel builds the bundled profile set covers, for the About screen. */
    fun supportedKernelCount(context: Context): Int =
        byReleaseOf(context)?.count { !it.value.template } ?: 0

    /** The raw HOCON text of [profile], with every `include` resolved, or null when unreadable. */
    fun readProfile(context: Context, profile: Profile): String? = runCatching {
        val text = readAsset(context, "$ASSET_DIR/${profile.file}") ?: return null
        expandIncludes(context, text, depth = 0)
    }.onFailure { Log.w(TAG, "cannot read ${profile.file}", it) }.getOrNull()

    /**
     * Resolves `include "x.conf"` lines the way the reference implementation's asset loader does.
     *
     * The shared files (`credential-6x.conf`, `kernelsnitch-6x.conf`, `execution-*.conf`) carry the
     * fields every profile of a family has in common, so a profile is only complete once they are
     * inlined. Inlining here means the native side never has to know about includes.
     */
    private fun expandIncludes(context: Context, text: String, depth: Int): String {
        if (depth > MAX_INCLUDE_DEPTH) return text
        val builder = StringBuilder(text.length * 2)
        for (line in text.lineSequence()) {
            val trimmed = line.trim()
            val name = includeTarget(trimmed)
            if (name == null) {
                builder.append(line).append('\n')
                continue
            }
            val included = readAsset(context, "$ASSET_DIR/$name")
            if (included == null) {
                Log.w(TAG, "missing include $name")
                builder.append('\n')
            } else {
                builder.append(expandIncludes(context, included, depth + 1)).append('\n')
            }
        }
        return builder.toString()
    }

    /** `include "credential-6x.conf"` -> `credential-6x.conf`. */
    private fun includeTarget(line: String): String? {
        if (!line.startsWith("include")) return null
        val open = line.indexOf('"')
        val close = line.lastIndexOf('"')
        if (open < 0 || close <= open) return null
        return line.substring(open + 1, close).ifEmpty { null }
    }

    private fun readAsset(context: Context, path: String): String? = runCatching {
        context.assets.open(path).bufferedReader().use { it.readText() }
    }.getOrNull()

    private fun byReleaseOf(context: Context): Map<String, Profile>? {
        byRelease?.let { return it }
        val parsed = indexOf(context) ?: return null
        val table = parsed.associateBy { it.release }
        byRelease = table
        return table
    }

    /** Parses `index.conf` once. Entries are `{ release = "...", file = "..." }`, possibly on one line. */
    private fun indexOf(context: Context): List<Profile>? {
        index?.let { return it }
        val text = readAsset(context, INDEX)
        if (text == null) {
            Log.w(TAG, "no $INDEX in assets")
            return null
        }
        // The index is HOCON and puts both keys on a single line, so scan for the pair rather than
        // walking lines: `{ release = "x", file = "y" }`.
        val parsed = buildList {
            var position = 0
            while (true) {
                val releaseAt = text.indexOf("release", position)
                if (releaseAt < 0) break
                val name = quotedAfter(text, releaseAt)
                val fileAt = text.indexOf("file", releaseAt)
                if (name == null || fileAt < 0) {
                    position = releaseAt + 1
                    continue
                }
                val file = quotedAfter(text, fileAt)
                if (file == null) {
                    position = fileAt + 1
                    continue
                }
                add(Profile(name, file, name.contains("-template")))
                position = fileAt + file.length
            }
        }
        index = parsed
        Log.i(TAG, "loaded ${parsed.size} kernel profiles")
        return parsed
    }

    /** The first `"..."` at or after [from], used for both keys of an index entry. */
    private fun quotedAfter(text: String, from: Int): String? {
        val open = text.indexOf('"', from)
        if (open < 0) return null
        val close = text.indexOf('"', open + 1)
        if (close <= open) return null
        return text.substring(open + 1, close).ifEmpty { null }
    }

    private const val MAX_INCLUDE_DEPTH = 4
}
