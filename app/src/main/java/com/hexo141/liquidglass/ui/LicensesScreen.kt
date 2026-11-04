package com.hexo141.liquidglass.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.hexo141.liquidglass.R
import com.hexo141.liquidglass.i18n.AppLanguage
import com.hexo141.liquidglass.i18n.LocaleManager

/** The bundled licence documents, in the order they are listed on this screen. */
private enum class LicenceDoc(
    val title: String,
    val english: String,
    val chinese: String,
) {
    GPL(
        title = "GNU General Public License v3.0",
        english = "licenses/gpl-3.0.txt",
        chinese = "licenses/zh-CN/gpl-3.0.txt"
    ),
    APACHE(
        title = "Apache License 2.0",
        english = "licenses/apache-2.0.txt",
        chinese = "licenses/zh-CN/apache-2.0.txt"
    ),
    MPL(
        title = "Mozilla Public License 2.0",
        english = "licenses/mpl-2.0.txt",
        chinese = "licenses/zh-CN/mpl-2.0.txt"
    ),
}

/**
 * Read-only viewer for the licences that ship inside the APK.
 *
 * These are not part of the acceptance flow - [ConsentScreen] only gates the GPL and the
 * disclaimer, because making someone tick four boxes instead of two mostly teaches them to tick
 * boxes. Apache and MPL are still worth showing, since both require the notices to be reachable, so
 * they live here and are opened from About.
 *
 * Every document can be flipped to its Chinese reference translation; the header of each translated
 * file already states that the English text is the binding one.
 */
@Composable
fun LicensesScreen(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current

    var selected by remember { mutableStateOf(LicenceDoc.GPL) }
    var showChinese by remember {
        mutableStateOf(LocaleManager.current(context) == AppLanguage.CHINESE)
    }

    val text = remember(selected, showChinese) {
        val asset = if (showChinese) selected.chinese else selected.english
        runCatching {
            context.assets.open(asset).bufferedReader().use { it.readText() }
        }.getOrDefault("")
    }
    val lines = remember(text) { text.lines() }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(Color(0xFF07080A))
            .windowInsetsPadding(WindowInsets.safeDrawing)
            .padding(horizontal = 16.dp, vertical = 12.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                modifier = Modifier
                    .height(34.dp)
                    .clip(RoundedCornerShape(percent = 50))
                    .background(Color.White.copy(alpha = 0.10f))
                    .clickable { onBack() }
                    .padding(horizontal = 14.dp),
                contentAlignment = Alignment.Center
            ) {
                BasicText(
                    text = stringResource(R.string.licenses_back),
                    style = TextStyle(
                        color = Color.White.copy(alpha = 0.85f),
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Medium
                    )
                )
            }
            Spacer(Modifier.weight(1f))
            BasicText(
                text = stringResource(R.string.licenses_title),
                style = TextStyle(
                    color = Color.White,
                    fontSize = 17.sp,
                    fontWeight = FontWeight.SemiBold
                )
            )
        }
        Spacer(Modifier.height(14.dp))

        // Document selector.
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            LicenceDoc.entries.forEach { doc ->
                val active = doc == selected
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(40.dp)
                        .clip(RoundedCornerShape(12.dp))
                        .background(
                            if (active) Color(0xFF0A84FF).copy(alpha = 0.20f)
                            else Color.White.copy(alpha = 0.05f)
                        )
                        .border(
                            1.dp,
                            if (active) Color(0xFF0A84FF) else Color.White.copy(alpha = 0.10f),
                            RoundedCornerShape(12.dp)
                        )
                        .clickable { selected = doc }
                        .padding(horizontal = 14.dp),
                    contentAlignment = Alignment.CenterStart
                ) {
                    BasicText(
                        text = doc.title,
                        style = TextStyle(
                            color = Color.White.copy(alpha = if (active) 0.95f else 0.65f),
                            fontSize = 12.sp,
                            fontWeight = if (active) FontWeight.SemiBold else FontWeight.Normal
                        )
                    )
                }
            }
        }
        Spacer(Modifier.height(12.dp))

        // English / Chinese switch.
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            PillButton(
                label = stringResource(R.string.licenses_show_english),
                selected = !showChinese,
                onClick = { showChinese = false }
            )
            PillButton(
                label = stringResource(R.string.licenses_show_chinese),
                selected = showChinese,
                onClick = { showChinese = true }
            )
        }
        if (showChinese) {
            Spacer(Modifier.height(8.dp))
            BasicText(
                text = stringResource(R.string.licenses_reference),
                style = TextStyle(
                    color = Color.White.copy(alpha = 0.45f),
                    fontSize = 10.sp,
                    lineHeight = 14.sp
                )
            )
        }
        Spacer(Modifier.height(10.dp))

        Column(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f)
                .clip(RoundedCornerShape(16.dp))
                .background(Color.White.copy(alpha = 0.05f))
                .border(1.dp, Color.White.copy(alpha = 0.10f), RoundedCornerShape(16.dp))
                .padding(horizontal = 12.dp, vertical = 10.dp)
        ) {
            if (lines.isEmpty()) {
                BasicText(
                    text = stringResource(R.string.licenses_unavailable),
                    style = TextStyle(
                        color = Color.White.copy(alpha = 0.55f),
                        fontSize = 11.sp
                    )
                )
            } else {
                LazyColumn(modifier = Modifier.fillMaxWidth().fillMaxHeight()) {
                    items(lines) { line ->
                        BasicText(
                            text = line.ifEmpty { " " },
                            style = TextStyle(
                                color = Color.White.copy(alpha = 0.78f),
                                fontSize = 10.sp,
                                lineHeight = 14.sp,
                                fontFamily = FontFamily.Monospace
                            )
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun PillButton(
    label: String,
    selected: Boolean,
    onClick: () -> Unit,
) {
    Box(
        modifier = Modifier
            .height(28.dp)
            .clip(RoundedCornerShape(percent = 50))
            .background(if (selected) Color(0xFF0A84FF) else Color.White.copy(alpha = 0.10f))
            .clickable { onClick() }
            .padding(horizontal = 14.dp),
        contentAlignment = Alignment.Center
    ) {
        BasicText(
            text = label,
            style = TextStyle(
                color = Color.White.copy(alpha = if (selected) 1f else 0.65f),
                fontSize = 11.sp,
                fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal
            )
        )
    }
}