package com.hexo141.liquidglass.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicText
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shadow
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.hexo141.liquidglass.R
import com.hexo141.liquidglass.i18n.AppLanguage
import com.hexo141.liquidglass.i18n.LocaleManager

/**
 * Three-segment language switch, drawn inside the About card.
 *
 * A row of pills rather than a dropdown: there are exactly three answers, and showing all of them
 * at once makes the current choice self-evident instead of hiding it behind a label that has to be
 * opened to be read.
 *
 * The selection is read at composition time and never cached in Compose state. `apply` restarts the
 * activity, so the next composition already reads the new value - keeping a local copy would only
 * risk showing the old highlight for a frame.
 */
@Composable
fun LocaleRow(modifier: Modifier = Modifier) {
    Row(
        modifier = modifier,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        val context = LocalContext.current
        val current = LocaleManager.current(context)
        Segment(
            text = stringResource(R.string.language_auto),
            selected = current == AppLanguage.SYSTEM,
            onClick = { LocaleManager.apply(context, AppLanguage.SYSTEM) },
        )
        Segment(
            text = stringResource(R.string.language_english),
            selected = current == AppLanguage.ENGLISH,
            onClick = { LocaleManager.apply(context, AppLanguage.ENGLISH) },
        )
        Segment(
            text = stringResource(R.string.language_chinese),
            selected = current == AppLanguage.CHINESE,
            onClick = { LocaleManager.apply(context, AppLanguage.CHINESE) },
        )
    }
}

/** One pill: filled blue when it is the current language, translucent white when it is not. */
@Composable
private fun Segment(text: String, selected: Boolean, onClick: () -> Unit) {
    val shadow = Shadow(
        color = Color.Black.copy(alpha = 0.45f),
        offset = androidx.compose.ui.geometry.Offset(0f, 1f),
        blurRadius = 6f,
    )
    androidx.compose.foundation.layout.Box(
        modifier = Modifier
            .clip(RoundedCornerShape(percent = 50))
            .background(
                if (selected) Color(0xFF0A84FF) else Color.White.copy(alpha = 0.10f)
            )
            .clickable(onClick = onClick)
            .padding(horizontal = 14.dp, vertical = 7.dp),
    ) {
        BasicText(
            text = text,
            style = TextStyle(
                color = Color.White.copy(alpha = if (selected) 1f else 0.75f),
                fontSize = 12.sp,
                fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal,
                shadow = shadow,
            ),
        )
    }
}
