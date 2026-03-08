package space.zeroxv6.kotlin_mls

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Encrypts the MLS state files at rest using AES-256-GCM with a key stored
 * in Android Keystore (hardware-backed where available).
 *
 * ## Usage
 *
 * Call [encryptAfterSave] after each `MlsService.save()` and
 * [decryptBeforeLoad] before creating the `MlsService` instance.
 *
 * ```kotlin
 * // On app start:
 * val encryptor = MlsStorageEncryptor(context, "mls_storage")
 * encryptor.decryptBeforeLoad()
 * val mlsService = MlsService(context, "mls_storage")
 *
 * // After operations that modify state:
 * mlsService.save()
 * encryptor.encryptAfterSave()
 * ```
 *
 * ## Security model
 *
 * - Key is stored in Android Keystore (TEE / StrongBox where available)
 * - Files are encrypted with AES-256-GCM (authenticated encryption)
 * - IV is stored prepended to the ciphertext
 * - Original plaintext files are deleted after encryption
 * - On a non-rooted device, this provides defense-in-depth alongside
 *   Android's app-private file storage.
 */
class MlsStorageEncryptor(
    private val context: Context,
    private val storageName: String = "mls_storage"
) {
    companion object {
        private const val KEYSTORE_ALIAS_PREFIX = "mls_storage_key_"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val AES_GCM_CIPHER = "AES/GCM/NoPadding"
        private const val GCM_TAG_LENGTH = 128 // bits
        private const val GCM_IV_LENGTH = 12   // bytes

        // Files that need encryption
        private val SENSITIVE_FILES = listOf("state.json", "openmls_store.json")
    }

    private val keystoreAlias = "$KEYSTORE_ALIAS_PREFIX$storageName"
    private val storageDir: File
        get() = File(context.filesDir, storageName)

    /**
     * Encrypts all sensitive MLS state files in-place.
     *
     * Call this **after** `MlsService.save()`.
     * Replaces `<file>` with `<file>.enc` and deletes the plaintext.
     */
    fun encryptAfterSave() {
        val key = getOrCreateKey()

        for (filename in SENSITIVE_FILES) {
            val plainFile = File(storageDir, filename)
            if (!plainFile.exists()) continue

            val encFile = File(storageDir, "$filename.enc")

            val plaintext = plainFile.readBytes()
            val cipher = Cipher.getInstance(AES_GCM_CIPHER)
            cipher.init(Cipher.ENCRYPT_MODE, key)

            val iv = cipher.iv
            val ciphertext = cipher.doFinal(plaintext)

            // Write: [IV (12 bytes)] + [ciphertext + GCM tag]
            FileOutputStream(encFile).use { fos ->
                fos.write(iv)
                fos.write(ciphertext)
            }

            // Securely delete plaintext
            plainFile.delete()
        }
    }

    /**
     * Decrypts all encrypted MLS state files back to plaintext.
     *
     * Call this **before** creating `MlsService` (which auto-loads state).
     * Replaces `<file>.enc` with `<file>` (plaintext, used by Rust).
     * The `.enc` files are kept so re-encryption is idempotent.
     */
    fun decryptBeforeLoad() {
        val key = getKeyOrNull() ?: return // No key = no encrypted files

        for (filename in SENSITIVE_FILES) {
            val encFile = File(storageDir, "$filename.enc")
            if (!encFile.exists()) continue

            val plainFile = File(storageDir, filename)

            try {
                val encData = encFile.readBytes()
                if (encData.size < GCM_IV_LENGTH) continue

                val iv = encData.copyOfRange(0, GCM_IV_LENGTH)
                val ciphertext = encData.copyOfRange(GCM_IV_LENGTH, encData.size)

                val cipher = Cipher.getInstance(AES_GCM_CIPHER)
                val spec = GCMParameterSpec(GCM_TAG_LENGTH, iv)
                cipher.init(Cipher.DECRYPT_MODE, key, spec)

                val plaintext = cipher.doFinal(ciphertext)
                plainFile.writeBytes(plaintext)
            } catch (e: Exception) {
                // If decryption fails (e.g., key was invalidated), skip
                // rather than crash. The MLS layer will treat it as fresh.
                e.printStackTrace()
            }
        }
    }

    /**
     * Removes all encrypted state files and the encryption key.
     * Use when the user logs out or clears data.
     */
    fun clearAll() {
        for (filename in SENSITIVE_FILES) {
            File(storageDir, filename).delete()
            File(storageDir, "$filename.enc").delete()
        }

        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)
            keyStore.deleteEntry(keystoreAlias)
        } catch (_: Exception) {
            // Ignore if key doesn't exist
        }
    }

    /**
     * Returns true if encrypted state files exist on disk.
     */
    fun hasEncryptedState(): Boolean {
        return SENSITIVE_FILES.any {
            File(storageDir, "$it.enc").exists()
        }
    }

    // ── Private key management ────────────────────────────────────────

    private fun getOrCreateKey(): SecretKey {
        return getKeyOrNull() ?: createKey()
    }

    private fun getKeyOrNull(): SecretKey? {
        return try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)
            keyStore.getKey(keystoreAlias, null) as? SecretKey
        } catch (_: Exception) {
            null
        }
    }

    private fun createKey(): SecretKey {
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEYSTORE
        )

        val spec = KeyGenParameterSpec.Builder(
            keystoreAlias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            // Require user authentication if you want an extra layer:
            // .setUserAuthenticationRequired(true)
            // .setUserAuthenticationValidityDurationSeconds(300)
            .build()

        keyGenerator.init(spec)
        return keyGenerator.generateKey()
    }
}
