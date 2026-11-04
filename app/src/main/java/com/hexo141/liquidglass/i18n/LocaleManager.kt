package com.hexo141.liquidglass.i18n

import android.content.Context
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.os.LocaleListCompat

/**
 * The three answers the language picker can give.
 *
 * [SYSTEM] is the absence of a choice, not a third locale: it hands the decision back to Android,
 * which then applies the device's own language list. That is stored as the empty list rather than
 * as a saved tag, because `setApplicationLocales(empty())` is exactly how AppCompat spells "no
 * override" - writing `en` there instead would pin an English-speaking user's app to English even
 * after they switch the phone to Chinese.
 */
enum class AppLanguage(val tag: String) {
    /** Follow whatever the device is set to. */
    SYSTEM(""),

    /** Pin English. */
    ENGLISH("en"),

    /** Pin Simplified Chinese; `zh-Hans` so a Traditional Chinese device still gets this text. */
    CHINESE("zh-Hans");

    companion object {
        fun ofTag(tag: String): AppLanguage =
            entries.firstOrNull { it.tag.equals(tag, ignoreCase = true) } ?: SYSTEM
    }
}

/**
 * Applies and remembers the language override.
 *
 * Two mechanisms are in play and only one of them is ours:
 *
 * - AppCompat keeps the override in its own storage and reapplies it on every process start, and
 *   from Android 13 the same value is what the system's per-app language screen edits. Because both
 *   write the same store, the in-app picker and that screen can never disagree.
 * - [STORE] is a mirror used only to draw the picker before the per-app locales are read back; it
 *   is written from [apply] so it cannot drift.
 *
 * Every call re-creates the running activities, which is the point: the strings are resolved at
 * composition time, so the screen has to be rebuilt for a new locale to take effect.
 */
object LocaleManager {

    private const val STORE = "language"
    private const val KEY_LANGUAGE = "language"

    /** The stored answer, or [AppLanguage.SYSTEM] when the user has never picked one. */
    fun current(context: Context): AppLanguage {
        val stored = preferences(context).getString(KEY_LANGUAGE, "").orEmpty()
        if (stored.isNotEmpty()) return AppLanguage.ofTag(stored)
        // Fall back to AppCompat's own store: the system settings screen writes there directly,
        // and on first run after that the mirror above has not been written yet.
        val applied = AppCompatDelegate.getApplicationLocales()
        if (applied.isEmpty) return AppLanguage.SYSTEM
        return AppLanguage.ofTag(applied.toLanguageTags().substringBefore(','))
    }

    /** Applies [language] and rebuilds every open activity. */
    fun apply(context: Context, language: AppLanguage) {
        preferences(context).edit().putString(KEY_LANGUAGE, language.tag).apply()
        val locales = if (language.tag.isEmpty()) {
            LocaleListCompat.getEmptyLocaleList()
        } else {
            LocaleListCompat.forLanguageTags(language.tag)
        }
        AppCompatDelegate.setApplicationLocales(locales)
    }

    /**
     * Called from `Application.onCreate` before any activity exists.
     *
     * AppCompat restores the override by itself, so this only exists to make the ordering explicit:
     * the override has to be in place before the first view inflates, otherwise the launch screen
     * flashes the device language and then swaps.
     */
    fun restore(context: Context) {
        val stored = preferences(context).getString(KEY_LANGUAGE, "").orEmpty()
        if (stored.isEmpty()) return
        AppCompatDelegate.setApplicationLocales(LocaleListCompat.forLanguageTags(stored))
    }

    private fun preferences(context: Context) =
        context.applicationContext.getSharedPreferences(STORE, Context.MODE_PRIVATE)
}