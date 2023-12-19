package com.x8bit.bitwarden.ui.vault.feature.additem.util

import com.bitwarden.core.CipherRepromptType
import com.bitwarden.core.CipherType
import com.bitwarden.core.CipherView
import com.bitwarden.core.FieldType
import com.bitwarden.core.FieldView
import com.x8bit.bitwarden.R
import com.x8bit.bitwarden.ui.platform.base.util.asText
import com.x8bit.bitwarden.ui.vault.feature.additem.VaultAddItemState
import com.x8bit.bitwarden.ui.vault.model.VaultLinkedFieldType.Companion.fromId
import java.util.UUID

/**
 * Transforms [CipherView] into [VaultAddItemState.ViewState].
 */
fun CipherView.toViewState(): VaultAddItemState.ViewState =
    when (type) {
        CipherType.LOGIN -> {
            val loginView = requireNotNull(this.login)
            VaultAddItemState.ViewState.Content.Login(
                originalCipher = this,
                name = this.name,
                username = loginView.username.orEmpty(),
                password = loginView.password.orEmpty(),
                uri = loginView.uris?.firstOrNull()?.uri.orEmpty(),
                favorite = this.favorite,
                masterPasswordReprompt = this.reprompt == CipherRepromptType.PASSWORD,
                notes = this.notes.orEmpty(),
                // TODO: Update these properties to pull folder from data layer (BIT-501)
                folderName = this.folderId?.asText() ?: R.string.folder_none.asText(),
                availableFolders = emptyList(),
                // TODO: Update this property to pull owner from data layer (BIT-501)
                ownership = "",
                // TODO: Update this property to pull available owners from data layer (BIT-501)
                availableOwners = emptyList(),
                customFieldData = this.fields.orEmpty().map { it.toCustomField() },
            )
        }

        CipherType.SECURE_NOTE -> {
            VaultAddItemState.ViewState.Content.SecureNotes(
                originalCipher = this,
                name = this.name,
                favorite = this.favorite,
                masterPasswordReprompt = this.reprompt == CipherRepromptType.PASSWORD,
                notes = this.notes.orEmpty(),
                // TODO: Update these properties to pull folder from data layer (BIT-501)
                folderName = this.folderId?.asText() ?: R.string.folder_none.asText(),
                availableFolders = emptyList(),
                // TODO: Update this property to pull owner from data layer (BIT-501)
                ownership = "",
                // TODO: Update this property to pull available owners from data layer (BIT-501)
                availableOwners = emptyList(),
                customFieldData = this.fields.orEmpty().map { it.toCustomField() },
            )
        }

        CipherType.CARD -> VaultAddItemState.ViewState.Error(
            message = "Not yet implemented.".asText(),
        )

        CipherType.IDENTITY -> VaultAddItemState.ViewState.Error(
            message = "Not yet implemented.".asText(),
        )
    }

private fun FieldView.toCustomField() =
    when (this.type) {
        FieldType.TEXT -> VaultAddItemState.Custom.TextField(
            itemId = UUID.randomUUID().toString(),
            name = this.name.orEmpty(),
            value = this.value.orEmpty(),
        )

        FieldType.HIDDEN -> VaultAddItemState.Custom.HiddenField(
            itemId = UUID.randomUUID().toString(),
            name = this.name.orEmpty(),
            value = this.value.orEmpty(),
        )

        FieldType.BOOLEAN -> VaultAddItemState.Custom.BooleanField(
            itemId = UUID.randomUUID().toString(),
            name = this.name.orEmpty(),
            value = this.value.toBoolean(),
        )

        FieldType.LINKED -> VaultAddItemState.Custom.LinkedField(
            itemId = UUID.randomUUID().toString(),
            name = this.name.orEmpty(),
            vaultLinkedFieldType = fromId(requireNotNull(this.linkedId)),
        )
    }