package com.hexo141.liquidglass.ui

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicText
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shadow
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.hexo141.liquidglass.R
import com.hexo141.liquidglass.i18n.AppLanguage
import com.hexo141.liquidglass.i18n.LocaleManager

/**
 * First thing a fresh install shows: pick a language, then read the legal documents.
 *
 * It comes before [ConsentScreen] on purpose. The disclaimer is prose, and asking someone to accept
 * a document in a language they do not read is not consent. Picking a language calls
 * [LocaleManager.apply], which recreates the activity, so the very next thing on screen - the
 * licence - is already in the chosen language.
 *
 * The choice is not pre-selected from the device locale: pre-highlighting an answer invites tapping
 * Continue without reading, and the whole point of this screen is that the reader takes a moment.
 */
@Composable
fun WelcomeScreen(
    onDone: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current

    /** null = nothing picked yet, which keeps Continue disabled. */
    var picked by remember { mutableStateOf<AppLanguage?>(null) }

    Box(modifier.fillMaxSize()) {
        Image(
            painter = painterResource(R.drawable.bg),
            contentDescription = null,
            contentScale = ContentScale.Crop,
            modifier = Modifier.fillMaxSize()
        )
        Box(Modifier.fillMaxSize().background(Color.Black.copy(alpha = 0.74f)))

        Column(
            modifier = Modifier
                .fillMaxSize()
                .windowInsetsPadding(WindowInsets.safeDrawing)
                .padding(start = 20.dp, end = 20.dp, top = 12.dp, bottom = 20.dp)
        ) {
            Spacer(Modifier.weight(1f))

            BasicText(
                text = stringResource(R.string.app_name),
                style = TextStyle(
                    color = Color.White,
                    fontSize = 26.sp,
                    fontWeight = FontWeight.SemiBold,
                    shadow = Shadow(Color.Black.copy(alpha = 0.45f), Offset(0f, 2f), 8f)
                )
            )
            Spacer(Modifier.height(10.dp))
            BasicText(
                text = stringResource(R.string.welcome_title),
                style = TextStyle(
                    color = Color.White.copy(alpha = 0.92f),
                    fontSize = 18.sp,
                    fontWeight = FontWeight.Medium
                )
            )
            Spacer(Modifier.height(6.dp))
            BasicText(
                text = stringResource(R.string.welcome_subtitle),
                style = TextStyle(
                    color = Color.White.copy(alpha = 0.55f),
                    fontSize = 12.sp,
                    lineHeight = 17.sp
                )
            )
            Spacer(Modifier.height(22.dp))

            ChoiceRow(
                label = stringResource(R.string.welcome_english),
                hint = "English",
                selected = picked == AppLanguage.ENGLISH,
                onClick = { picked = AppLanguage.ENGLISH }
            )
            Spacer(Modifier.height(10.dp))
            ChoiceRow(
                label = stringResource(R.string.welcome_chinese),
                hint = "简体中文",
                selected = picked == AppLanguage.CHINESE,
                onClick = { picked = AppLanguage.CHINESE }
            )
            Spacer(Modifier.height(10.dp))
            ChoiceRow(
                label = stringResource(R.string.welcome_system),
                hint = stringResource(R.string.welcome_system_hint),
                selected = picked == AppLanguage.SYSTEM,
                onClick = { picked = AppLanguage.SYSTEM }
            )

            Spacer(Modifier.weight(1f))

            val ready = picked != null
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(50.dp)
                    .clip(RoundedCornerShape(percent = 50))
                    .background(if (ready) WelcomeAccent else Color.White.copy(alpha = 0.14f))
                    .clickable(enabled = ready) {
                        // Applying the locale recreates the activity, so onDone() is only the
                        // fallback for the "follow system" case where nothing actually changes.
                        val choice = picked ?: return@clickable
                        LocaleManager.apply(context, choice)
                        onDone()
                    },
                contentAlignment = Alignment.Center
            ) {
                BasicText(
                    text = stringResource(R.string.welcome_continue),
                    style = TextStyle(
                        color = Color.White.copy(alpha = if (ready) 1f else 0.45f),
                        fontSize = 15.sp,
                        fontWeight = FontWeight.Medium
                    )
                )
            }
        }
    }
}

private val WelcomeAccent = Color(0xFF0A84FF)

/** One large tappable card; the label is in the target language, the hint explains the choice. */
@Composable
private fun ChoiceRow(
    label: String,
    hint: String,
    selected: Boolean,
    onClick: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(16.dp))
            .background(if (selected) WelcomeAccent.copy(alpha = 0.22f) else Color.White.copy(alpha = 0.07f))
            .border(
                1.dp,
                if (selected) WelcomeAccent else Color.White.copy(alpha = 0.14f),
                RoundedCornerShape(16.dp)
            )
            .clickable { onClick() }
            .padding(horizontal = 16.dp, vertical = 15.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(Modifier.weight(1f)) {
            BasicText(
                text = label,
                style = TextStyle(
                    color = Color.White.copy(alpha = 0.95f),
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Medium
                )
            )
            Spacer(Modifier.height(3.dp))
            BasicText(
                text = hint,
                style = TextStyle(
                    color = Color.White.copy(alpha = 0.5f),
                    fontSize = 11.sp,
                    lineHeight = 15.sp
                )
            )
        }
        // Ring that fills when this row is the current answer.
        Box(
            modifier = Modifier
                .size(20.dp)
                .clip(RoundedCornerShape(percent = 50))
                .background(if (selected) WelcomeAccent else Color.Transparent)
                .border(
                    1.5.dp,
                    if (selected) WelcomeAccent else Color.White.copy(alpha = 0.35f),
                    RoundedCornerShape(percent = 50)
                ),
            contentAlignment = Alignment.Center
        ) {
            if (selected) {
                BasicText(
                    text = "✓",
                    style = TextStyle(
                        color = Color.White,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold
                    )
                )
            }
        }
    }
}
