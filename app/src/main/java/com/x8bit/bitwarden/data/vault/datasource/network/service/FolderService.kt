package com.x8bit.bitwarden.data.vault.datasource.network.service

import com.x8bit.bitwarden.data.vault.datasource.network.model.FolderJsonRequest
import com.x8bit.bitwarden.data.vault.datasource.network.model.UpdateFolderResponseJson
import com.x8bit.bitwarden.data.vault.datasource.network.model.SyncResponseJson

/**
 * Provides an API for querying folder endpoints.
 */
interface FolderService {
    /**
     * Attempt to create a folder.
     */
    suspend fun createFolder(body: FolderJsonRequest): Result<SyncResponseJson.Folder>

    /**
     * Attempt to update a folder.
     */
    suspend fun updateFolder(
        folderId: String,
        body: FolderJsonRequest,
    ): Result<UpdateFolderResponseJson>

    /**
     * Attempt to hard delete a folder.
     */
    suspend fun deleteFolder(folderId: String): Result<Unit>
}
