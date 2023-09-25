package com.x8bit.bitwarden.ui.vault.feature.vault

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.x8bit.bitwarden.R

/**
 * No items view for the [VaultScreen].
 */
@Composable
fun VaultNoItemsView(
    paddingValues: PaddingValues,
    addItemClickAction: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(paddingValues),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            modifier = Modifier.padding(16.dp),
            text = stringResource(id = R.string.no_items),
        )
        Button(
            modifier = Modifier.padding(16.dp),
            onClick = addItemClickAction,
        ) {
            Text(text = stringResource(id = R.string.add_an_item))
        }
    }
}