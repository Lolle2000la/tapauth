package dev.rourunisen.tapauth.data

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import dev.rourunisen.tapauth.crypto.Ed25519Keypair
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Manages the server's Ed25519 keypair for signing authentication grants. The keypair is generated
 * once and stored securely using Android Keystore.
 */
class KeypairRepository(private val context: Context) {

    private val prefs: SharedPreferences =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    private val keyStore: KeyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }

    private var cachedKeypair: Ed25519Keypair? = null

    /** Get the server keypair, generating it if it doesn't exist */
    fun getKeypair(): Ed25519Keypair {
        // Check cache first
        cachedKeypair?.let {
            return it
        }

        // Try to load from storage
        val stored = loadKeypair()
        if (stored != null) {
            cachedKeypair = stored
            return stored
        }

        // Generate new keypair
        Log.i(TAG, "Generating new server Ed25519 keypair")
        val keypair = Ed25519Keypair.generate()
        storeKeypair(keypair)
        cachedKeypair = keypair

        return keypair
    }

    /** Get the server's public key */
    fun getPublicKey(): ByteArray {
        return getKeypair().publicKey
    }

    /** Get the server's private key (for signing) */
    fun getPrivateKey(): ByteArray {
        return getKeypair().privateKey
    }

    /** Check if a keypair exists */
    fun hasKeypair(): Boolean {
        return prefs.contains(KEY_PRIVATE_KEY_ENCRYPTED) && prefs.contains(KEY_PUBLIC_KEY)
    }

    /** Delete the stored keypair (for testing or reset) */
    fun deleteKeypair() {
        Log.w(TAG, "Deleting server keypair")
        prefs
            .edit()
            .remove(KEY_PRIVATE_KEY_ENCRYPTED)
            .remove(KEY_PUBLIC_KEY)
            .remove(KEY_PRIVATE_KEY_IV)
            .apply()
        cachedKeypair = null

        // Remove encryption key from keystore
        if (keyStore.containsAlias(KEYSTORE_ALIAS)) {
            keyStore.deleteEntry(KEYSTORE_ALIAS)
        }
    }

    private fun storeKeypair(keypair: Ed25519Keypair) {
        // Store public key directly (not sensitive)
        val publicKeyB64 = Base64.encodeToString(keypair.publicKey, Base64.NO_WRAP)

        // Encrypt private key with Android Keystore
        val encryptionKey = getOrCreateEncryptionKey()
        val cipher = Cipher.getInstance(ENCRYPTION_TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, encryptionKey)

        val encryptedPrivateKey = cipher.doFinal(keypair.privateKey)
        val iv = cipher.iv

        val encryptedPrivateKeyB64 = Base64.encodeToString(encryptedPrivateKey, Base64.NO_WRAP)
        val ivB64 = Base64.encodeToString(iv, Base64.NO_WRAP)

        prefs
            .edit()
            .putString(KEY_PUBLIC_KEY, publicKeyB64)
            .putString(KEY_PRIVATE_KEY_ENCRYPTED, encryptedPrivateKeyB64)
            .putString(KEY_PRIVATE_KEY_IV, ivB64)
            .apply()

        Log.d(TAG, "Stored server keypair (public key: ${keypair.publicKey.size} bytes)")
    }

    private fun loadKeypair(): Ed25519Keypair? {
        val publicKeyB64 = prefs.getString(KEY_PUBLIC_KEY, null) ?: return null
        val encryptedPrivateKeyB64 = prefs.getString(KEY_PRIVATE_KEY_ENCRYPTED, null) ?: return null
        val ivB64 = prefs.getString(KEY_PRIVATE_KEY_IV, null) ?: return null

        try {
            val publicKey = Base64.decode(publicKeyB64, Base64.NO_WRAP)
            val encryptedPrivateKey = Base64.decode(encryptedPrivateKeyB64, Base64.NO_WRAP)
            val iv = Base64.decode(ivB64, Base64.NO_WRAP)

            // Decrypt private key
            val encryptionKey = getOrCreateEncryptionKey()
            val cipher = Cipher.getInstance(ENCRYPTION_TRANSFORMATION)
            val spec = GCMParameterSpec(GCM_TAG_LENGTH, iv)
            cipher.init(Cipher.DECRYPT_MODE, encryptionKey, spec)

            val privateKey = cipher.doFinal(encryptedPrivateKey)

            Log.d(TAG, "Loaded server keypair from storage")
            return Ed25519Keypair(privateKey, publicKey)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to load keypair from storage", e)
            // Clear corrupted data
            prefs
                .edit()
                .remove(KEY_PRIVATE_KEY_ENCRYPTED)
                .remove(KEY_PUBLIC_KEY)
                .remove(KEY_PRIVATE_KEY_IV)
                .apply()
            return null
        }
    }

    private fun getOrCreateEncryptionKey(): SecretKey {
        // Check if key already exists
        if (keyStore.containsAlias(KEYSTORE_ALIAS)) {
            return keyStore.getKey(KEYSTORE_ALIAS, null) as SecretKey
        }

        // Generate new encryption key in Android Keystore
        val keyGenerator =
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER)

        val keyGenParameterSpec =
            KeyGenParameterSpec.Builder(
                    KEYSTORE_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(false) // Don't require auth for every use
                .build()

        keyGenerator.init(keyGenParameterSpec)
        return keyGenerator.generateKey()
    }

    /** Get or create a symmetric HMAC key stored in Android Keystore for use with HmacSHA256. */
    fun getOrCreateHmacKey(): SecretKey {
        // If key already exists in keystore, return it
        if (keyStore.containsAlias(KEYSTORE_HMAC_ALIAS)) {
            return keyStore.getKey(KEYSTORE_HMAC_ALIAS, null) as SecretKey
        }

        // Generate new HMAC key in Android Keystore
        val keyGenerator =
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, KEYSTORE_PROVIDER)

        val keyGenParameterSpec =
            KeyGenParameterSpec.Builder(KEYSTORE_HMAC_ALIAS, KeyProperties.PURPOSE_SIGN)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(false)
                .build()

        keyGenerator.init(keyGenParameterSpec)
        return keyGenerator.generateKey()
    }

    companion object {
        private const val TAG = "KeypairRepository"
        private const val PREFS_NAME = "tapauth_server_keypair"
        private const val KEY_PUBLIC_KEY = "public_key"
        private const val KEY_PRIVATE_KEY_ENCRYPTED = "private_key_encrypted"
        private const val KEY_PRIVATE_KEY_IV = "private_key_iv"
        private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
        private const val KEYSTORE_ALIAS = "tapauth_keypair_encryption_key"
        private const val KEYSTORE_HMAC_ALIAS = "tapauth_hmac_key"
        private const val ENCRYPTION_TRANSFORMATION = "AES/GCM/NoPadding"
        private const val GCM_TAG_LENGTH = 128
    }
}
