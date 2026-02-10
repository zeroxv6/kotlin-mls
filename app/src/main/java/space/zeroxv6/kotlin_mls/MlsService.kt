package space.zeroxv6.kotlin_mls

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import uniffi.android_openmls.MlsClient
import uniffi.android_openmls.MlsException

/**
 * Kotlin wrapper for OpenMLS library with clean coroutine-based API
 *
 * This service provides end-to-end encrypted group messaging using the MLS protocol (RFC 9420).
 *
 * Features:
 * - Create and manage encrypted groups
 * - Add/remove members
 * - Send/receive encrypted messages
 * - Automatic state persistence
 *
 * @param context Android context for file storage
 * @param storageName Unique storage identifier (allows multiple users on same device for testing)
 */
class MlsService(context: Context, storageName: String = "mls_storage") {

    private val client: MlsClient by lazy {
        val dbPath = context.filesDir.absolutePath + "/" + storageName
        // Client automatically loads existing state in constructor
        MlsClient(dbPath)
    }

    /**
     * Creates a new identity and generates a key package
     *
     * @param name Display name for this identity
     * @return Hex-encoded key package that others can use to add you to groups
     * @throws MlsServiceException on crypto or serialization errors
     */
    suspend fun generateIdentity(name: String): String = withContext(Dispatchers.IO) {
        try {
            client.createIdentity(name)
        } catch (e: MlsException) {
            throw MlsServiceException("Failed to generate identity", e)
        }
    }

    /**
     * Creates a new group
     *
     * @param groupId Suggested group identifier (actual ID may differ)
     * @return Actual group ID (hex-encoded)
     * @throws MlsServiceException on group creation failure
     */
    suspend fun createGroup(groupId: String): String = withContext(Dispatchers.IO) {
        try {
            client.createGroup(groupId)
        } catch (e: MlsException) {
            throw MlsServiceException("Failed to create group", e)
        }
    }

    /**
     * Adds a new member to the group
     *
     * @param groupId The group to add the member to
     * @param keyPackageHex The new member's key package (hex-encoded)
     * @return JSON string with "commit" and "welcome" fields (both hex-encoded)
     *         - Send "commit" to existing members
     *         - Send "welcome" to the new member
     * @throws MlsServiceException if group not found or member add fails
     */
    suspend fun addMember(groupId: String, keyPackageHex: String): String = withContext(Dispatchers.IO) {
        try {
            client.addMember(groupId, keyPackageHex)
        } catch (e: MlsException) {
            throw MlsServiceException("Failed to add member to group $groupId", e)
        }
    }

    /**
     * Processes a Welcome message to join a group
     *
     * @param welcomeHex The Welcome message from the group creator (hex-encoded)
     * @return The group ID you've joined
     * @throws MlsServiceException if Welcome is invalid or processing fails
     */
    suspend fun processWelcome(welcomeHex: String): String = withContext(Dispatchers.IO) {
        try {
            val groupId = client.processWelcome(welcomeHex)
            client.saveState()
            groupId
        } catch (e: MlsException) {
            throw MlsServiceException("Failed to process Welcome message", e)
        }
    }

    /**
     * Processes a commit from another member
     *
     * @param groupId The group the commit is for
     * @param commitHex The commit message (hex-encoded)
     * @throws MlsServiceException if group not found or commit is invalid
     */
    suspend fun processCommit(groupId: String, commitHex: String): Unit = withContext(Dispatchers.IO) {
        try {
            client.processCommit(groupId, commitHex)
            client.saveState()
        } catch (e: MlsException) {
            throw MlsServiceException("Failed to process commit for group $groupId", e)
        }
    }

    /**
     * Encrypts a message for the group
     *
     * @param groupId The group to send the message to
     * @param plaintext The message to encrypt
     * @return Hex-encoded ciphertext to send to all group members
     * @throws MlsServiceException if group not found or encryption fails
     */
    suspend fun encrypt(groupId: String, plaintext: String): String = withContext(Dispatchers.IO) {
        try {
            client.encryptMessage(groupId, plaintext)
        } catch (e: MlsException) {
            throw MlsServiceException("Failed to encrypt message for group $groupId", e)
        }
    }

    /**
     * Decrypts a message from the group
     *
     * @param groupId The group the message is from
     * @param ciphertextHex The encrypted message (hex-encoded)
     * @return The decrypted plaintext message
     * @throws MlsServiceException if group not found or decryption fails
     */
    suspend fun decrypt(groupId: String, ciphertextHex: String): String = withContext(Dispatchers.IO) {
        try {
            val result = client.decryptMessage(groupId, ciphertextHex)
            client.saveState()
            result
        } catch (e: MlsException) {
            throw MlsServiceException("Failed to decrypt message for group $groupId", e)
        }
    }

    /**
     * Explicitly saves all group states to disk
     *
     * Note: State is automatically saved after key operations (decrypt, processWelcome, etc.)
     * but you can call this for additional safety.
     *
     * @throws MlsServiceException on IO errors
     */
    suspend fun save(): Unit = withContext(Dispatchers.IO) {
        try {
            client.saveState()
        } catch (e: MlsException) {
            throw MlsServiceException("Failed to save state", e)
        }
    }

    /**
     * Explicitly loads group states from disk
     *
     * Note: State is automatically loaded in the constructor, so you typically
     * don't need to call this manually.
     *
     * @throws MlsServiceException on IO or deserialization errors
     */
    suspend fun load(): Unit = withContext(Dispatchers.IO) {
        try {
            client.loadState()
        } catch (e: MlsException) {
            throw MlsServiceException("Failed to load state", e)
        }
    }

    /**
     * Lists all active group IDs currently in memory
     *
     * @return List of group IDs
     */
    suspend fun listActiveGroups(): List<String> = withContext(Dispatchers.IO) {
        try {
            client.listActiveGroups()
        } catch (e: Exception) {
            emptyList()
        }
    }

    /**
     * Gets information about a specific group
     *
     * @param groupId The group to get info for
     * @return JSON string with group information (group_id, epoch, member_count)
     * @throws MlsServiceException if group not found
     */
    suspend fun getGroupInfo(groupId: String): String = withContext(Dispatchers.IO) {
        try {
            client.getGroupInfo(groupId)
        } catch (e: MlsException) {
            throw MlsServiceException("Failed to get group info for $groupId", e)
        }
    }

    /**
     * Lists group IDs that have been saved to disk
     *
     * Note: These groups cannot be fully restored from disk due to security reasons.
     * This is useful for tracking which groups existed in previous sessions.
     *
     * @return List of saved group IDs
     */
    suspend fun listSavedGroups(): List<String> = withContext(Dispatchers.IO) {
        try {
            client.listSavedGroups()
        } catch (e: MlsException) {
            emptyList()
        }
    }
}

class MlsServiceException : Exception {
    constructor(message: String, cause: Throwable? = null) : super(message, cause)
    
    constructor(message: String, mlsException: MlsException) : super(
        "$message: ${mlsException.toString()}",
        mlsException
    )
}