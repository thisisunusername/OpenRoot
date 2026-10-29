// SPDX-License-Identifier: GPL-3.0-or-later OR Apache-2.0
package com.hexo141.liquidglass.root

/**
 * A deliberately small HOCON reader for GhostLock kernel profiles.
 *
 * The bundled profiles use a tiny subset of HOCON: `#` comments, `key = value` scalars, and
 * `key { ... }` blocks nested a few levels deep. Quoted strings appear only for `release` and
 * `fallback { to = "..." }`. That is little enough that a full HOCON library would be a large
 * dependency for no gain, and it keeps the parse dependency-free in unit tests.
 *
 * `null` is treated as "absent" rather than as a value: GhostLock's transport encodes presence by
 * key occurrence, so a profile that writes `pi_lock = null` must send nothing at all.
 *
 * Indentation is not trusted. One upstream profile has a field written flush against the left
 * margin inside a block, so the scanner only tracks brace depth and ignores column position.
 */
internal class Hocon private constructor(
    private val scalars: Map<String, String>,
    private val blocks: Set<String>,
) {

    /** A numeric value at [path], or null when absent, `null`, or not a number. */
    fun number(vararg path: String): Long? = number(path.asList())

    /** A numeric value at [path], or null when absent, `null`, or not a number. */
    fun number(path: List<String>): Long? {
        val raw = scalars[path.joinToString(".")] ?: return null
        val text = raw.trim()
        if (text.equals("null", ignoreCase = true)) return null
        // Values are plain decimal in every bundled profile. `caps_value = -1` is the one negative,
        // and the transport stores it as two's complement, which toLong() already produces.
        return text.toLongOrNull()
    }

    /** A string value at [path], with surrounding quotes removed. */
    fun string(path: List<String>, key: String): String? {
        val raw = scalars[(path + key).joinToString(".")] ?: return null
        return raw.trim().trim('"').ifEmpty { null }
    }

    /** True when [path] names a block, even an empty one. */
    fun has(vararg path: String): Boolean {
        val name = path.joinToString(".")
        return blocks.contains(name) || scalars.keys.any { it.startsWith("$name.") }
    }

    companion object {

        /** Parses [text] into a flat map of dotted paths plus the set of block paths. */
        fun parse(text: String): Hocon {
            val scalars = LinkedHashMap<String, String>()
            val blocks = LinkedHashSet<String>()
            // The stack of open block names; empty at the top level.
            val stack = ArrayDeque<String>()

            fun pathOf(child: String): String =
                if (stack.isEmpty()) child else stack.joinToString(".") + "." + child

            for (raw in text.lineSequence()) {
                // Comments run to end of line. `#` never appears inside a value in these profiles.
                val hash = raw.indexOf('#')
                val line = (if (hash >= 0) raw.substring(0, hash) else raw).trim()
                if (line.isEmpty()) continue

                // A lone `}` closes the innermost block. Some profiles put `}` and the next key on
                // one line, so handle both here and keep scanning the remainder of the line.
                var rest = line
                while (true) {
                    if (rest.startsWith("}")) {
                        if (stack.isNotEmpty()) stack.removeLast()
                        rest = rest.substring(1).trimStart().removePrefix(",").trimStart()
                        if (rest.isEmpty()) break
                        continue
                    }
                    // A block opens with `key {`.
                    val open = rest.indexOf('{')
                    val equals = rest.indexOf('=')
                    if (open >= 0 && (equals < 0 || open < equals)) {
                        val name = rest.substring(0, open).trim().trim('"')
                        if (name.isNotEmpty()) {
                            blocks += pathOf(name)
                            stack.addLast(name)
                        }
                        // Recurse into whatever follows the brace on this same line; a `}` there
                        // closes immediately, which `rest.startsWith("}")` above handles next round.
                        rest = rest.substring(open + 1).trimStart()
                        if (rest.isEmpty()) break
                        continue
                    }
                    // Otherwise it is `key = value`.
                    if (equals >= 0) {
                        val key = rest.substring(0, equals).trim().removePrefix("\"").removeSuffix("\"")
                        val value = rest.substring(equals + 1).trim()
                            .removeSuffix(",").trim()
                        if (key.isNotEmpty()) scalars[pathOf(key)] = value
                    }
                    break
                }
            }
            return Hocon(scalars, blocks)
        }
    }
}