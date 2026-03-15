package com.sentinelpass

import android.content.Context
import android.util.Log
import com.google.api.services.drive.Drive
import com.google.api.services.drive.model.File
import com.google.api.services.drive.model.FileList
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.util.UUID

/**
 * Google Drive sync service for SentinelPass
 *
 * This service handles encrypted sync blob storage in Google Drive's AppData folder.
 * All sync operations use the core sync logic from Rust via JNI,
 * while this Kotlin class handles the Drive API integration.
 */
class DriveService(
    private val context: Context,
    private val driveService: Drive
) {
    companion object {
        private const val TAG = "DriveService"
        private const val APP_DATA_FOLDER = "appDataFolder"
        private const val MIME_TYPE = "application/json"
    }

    // Sync state
    sealed class SyncState {
        object Idle : SyncState()
        data class Syncing(val progress: Float) : SyncState()
        object Complete : SyncState()
        data class Error(val error: Throwable) : SyncState()
    }

    private var _syncState: SyncState = SyncState.Idle
    val syncState: SyncState get() = _syncState

    private var currentDeviceId: String? = null
    private var appDataFolderId: String? = null

    /**
     * Initialize the Drive sync service
     *
     * @param deviceId Unique identifier for this device
     */
    suspend fun init(deviceId: String) = withContext(Dispatchers.IO) {
        try {
            currentDeviceId = deviceId

            // Find or create AppData folder
            appDataFolderId = findOrCreateAppDataFolder()

            Log.d(TAG, "Drive service initialized with device: $deviceId")
            Result.success(Unit)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize Drive service", e)
            _syncState = SyncState.Error(e)
            Result.failure(e)
        }
    }

    /**
     * Push sync entries to Drive
     *
     * @param jsonBlobs JSON array of SyncEntryBlob objects
     * @return Result indicating success or failure
     */
    suspend fun pushEntries(jsonBlobs: String): Result<Unit> = withContext(Dispatchers.IO) {
        try {
            _syncState = SyncState.Syncing(0f)

            val blobs = JSONArray(jsonBlobs)
            val total = blobs.length()

            // Process each blob
            for (i in 0 until total) {
                val blobJson = blobs.getJSONObject(i)
                val syncId = blobJson.getString("id")
                val fileName = "$syncId.json"

                // Create Drive file metadata
                val fileMetadata = File().apply {
                    name = fileName
                    parents = if (appDataFolderId != null) listOf(appDataFolderId) else listOf(APP_DATA_FOLDER)
                    mimeType = MIME_TYPE

                    // App properties for sync metadata
                    appProperties = mapOf(
                        "entryType" to (blobJson.optString("entryType", "Credential")),
                        "syncVersion" to blobJson.optLong("syncVersion", 0).toString(),
                        "isTombstone" to blobJson.optBoolean("isTombstone", false).toString(),
                        "originDeviceId" to blobJson.optString("originDeviceId", currentDeviceId ?: "")
                    )
                }

                // Create file content
                val fileContent = ByteArrayOutputStream().use { output ->
                    blobJson.toString().byteInputStream().copyTo(output)
                    output.toByteArray()
                }

                // Upload to Drive
                val contentStream = com.google.api.client.http.ByteArrayContent(
                    MIME_TYPE,
                    fileContent
                )

                // Check if file exists
                val existingFile = findFileByName(fileName)
                if (existingFile != null) {
                    // Update existing file
                    driveService.files()
                        .update(existingFile.id, fileMetadata, contentStream)
                        .setFields("id")
                        .execute()
                } else {
                    // Create new file
                    driveService.files()
                        .create(fileMetadata, contentStream)
                        .setFields("id")
                        .execute()
                }

                _syncState = SyncState.Syncing((i + 1).toFloat() / total.toFloat())
            }

            _syncState = SyncState.Complete
            Log.d(TAG, "Pushed $total entries to Drive")
            Result.success(Unit)

        } catch (e: Exception) {
            Log.e(TAG, "Failed to push entries", e)
            _syncState = SyncState.Error(e)
            Result.failure(e)
        }
    }

    /**
     * Pull sync entries from Drive
     *
     * @param pageToken Optional start page token for incremental sync
     * @return Result with JSON array of SyncEntryBlob objects and next page token
     */
    suspend fun pullEntries(pageToken: String? = null): Result<Pair<String, String?>> = withContext(Dispatchers.IO) {
        try {
            _syncState = SyncState.Syncing(0f)

            // Query for all sync files in AppData
            val filesList = mutableListOf<com.google.api.services.drive.model.File>()

            var nextPageToken: String? = pageToken
            do {
                val result: FileList = driveService.files().list()
                    .setSpaces(APP_DATA_FOLDER)
                    .setFields("files(id,name,appProperties,modifiedTime),nextPageToken")
                    .setPageToken(nextPageToken)
                    .setPageSize(100)
                    .execute()

                filesList.addAll(result.files ?: emptyList())
                nextPageToken = result.nextPageToken

            } while (nextPageToken != null)

            // Convert Drive files to sync blob JSON format
            val blobsArray = JSONArray()
            for (file in filesList) {
                try {
                    val blobJson = convertDriveFileToSyncBlob(file)
                    blobsArray.put(blobJson)
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to convert file: ${file.name}", e)
                }
            }

            val jsonResult = blobsArray.toString()
            _syncState = SyncState.Complete

            Log.d(TAG, "Pulled ${filesList.size} entries from Drive")
            Result.success(Pair(jsonResult, nextPageToken))

        } catch (e: Exception) {
            Log.e(TAG, "Failed to pull entries", e)
            _syncState = SyncState.Error(e)
            Result.failure(e)
        }
    }

    /**
     * Delete entries from Drive
     *
     * @param recordIds List of sync IDs to delete
     * @return Result indicating success or failure
     */
    suspend fun deleteEntries(recordIds: List<String>): Result<Unit> = withContext(Dispatchers.IO) {
        try {
            for (syncId in recordIds) {
                val fileName = "$syncId.json"
                val file = findFileByName(fileName)

                if (file != null) {
                    driveService.files().delete(file.id).execute()
                    Log.d(TAG, "Deleted file: $fileName")
                }
            }

            Result.success(Unit)

        } catch (e: Exception) {
            Log.e(TAG, "Failed to delete entries", e)
            Result.failure(e)
        }
    }

    /**
     * Register this device with Drive
     *
     * @return Result indicating success or failure
     */
    suspend fun registerDevice(): Result<Unit> = withContext(Dispatchers.IO) {
        try {
            val deviceId = currentDeviceId ?: return@withContext Result.failure(
                IllegalStateException("Drive service not initialized")
            )

            val fileName = "device_$deviceId.json"
            val deviceInfo = mapOf(
                "deviceId" to deviceId,
                "deviceName" to android.os.Build.MODEL,
                "deviceType" to "Android",
                "registeredAt" to System.currentTimeMillis()
            )

            val fileMetadata = File().apply {
                name = fileName
                parents = if (appDataFolderId != null) listOf(appDataFolderId) else listOf(APP_DATA_FOLDER)
                mimeType = MIME_TYPE
            }

            val contentStream = com.google.api.client.http.ByteArrayContent(
                MIME_TYPE,
                JSONObject(deviceInfo).toString().toByteArray()
            )

            // Try to create, ignore if exists
            try {
                driveService.files()
                    .create(fileMetadata, contentStream)
                    .setFields("id")
                    .execute()
            } catch (e: Exception) {
                // Ignore "already exists" errors
                if (e.message?.contains("already exists", ignoreCase = true) != true) {
                    throw e
                }
            }

            Log.d(TAG, "Device registered: $deviceId")
            Result.success(Unit)

        } catch (e: Exception) {
            Log.e(TAG, "Failed to register device", e)
            Result.failure(e)
        }
    }

    // MARK: - Private Helpers

    /**
     * Find or create the AppData folder
     */
    private suspend fun findOrCreateAppDataFolder(): String? = withContext(Dispatchers.IO) {
        try {
            // Try to find existing AppData folder
            val result = driveService.files().list()
                .setSpaces(APP_DATA_FOLDER)
                .setFields("files(id,name)")
                .execute()

            val appDataFolder = result.files?.firstOrNull {
                it.name == "SentinelPass"
            }

            if (appDataFolder != null) {
                return@withContext appDataFolder.id
            }

            // Create new folder
            val folderMetadata = File().apply {
                name = "SentinelPass"
                mimeType = "application/vnd.google-apps.folder"
                parents = listOf(APP_DATA_FOLDER)
            }

            val folder = driveService.files()
                .create(folderMetadata)
                .setFields("id")
                .execute()

            return@withContext folder.id

        } catch (e: Exception) {
            Log.e(TAG, "Failed to find/create AppData folder", e)
            null
        }
    }

    /**
     * Find a file by name in AppData
     */
    private suspend fun findFileByName(fileName: String): File? = withContext(Dispatchers.IO) {
        try {
            val result = driveService.files().list()
                .setSpaces(APP_DATA_FOLDER)
                .setQ("name = '$fileName'")
                .setFields("files(id,name,appProperties)")
                .execute()

            result.files?.firstOrNull()

        } catch (e: Exception) {
            Log.e(TAG, "Failed to find file: $fileName", e)
            null
        }
    }

    /**
     * Convert Drive file to sync blob JSON format
     */
    private fun convertDriveFileToSyncBlob(file: File): JSONObject {
        // Download file content
        val outputStream = ByteArrayOutputStream()
        driveService.files().get(file.id).executeMediaAndDownloadTo(outputStream)
        val content = String(outputStream.toByteArray())

        // Parse the content
        val baseJson = JSONObject(content)

        // Add Drive-specific metadata
        val syncBlob = JSONObject().apply {
            put("id", file.name.removeSuffix(".json"))
            put("name", file.name)
            put("encryptedPayload", baseJson.optString("encryptedPayload"))
            put("modifiedTime", file.modifiedTime?.value ?: 0L)
            put("md5Checksum", file.md5Checksum)

            // App properties
            val appProps = file.appProperties ?: mapOf<String, String>()
            put("entryType", appProps["entryType"] ?: "Credential")
            put("syncVersion", appProps["syncVersion"]?.toLongOrNull() ?: 0L)
            put("isTombstone", appProps["isTombstone"]?.toBoolean() ?: false)
            put("originDeviceId", appProps["originDeviceId"] ?: "")
        }

        return syncBlob
    }
}
