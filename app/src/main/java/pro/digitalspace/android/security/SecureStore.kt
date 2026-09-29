/* SPDX-License-Identifier: MIT */
package pro.digitalspace.android.security

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.system.Os
import java.io.File
import java.security.KeyStore
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Account-scoped encrypted local storage.
 *
 * The legacy namespace intentionally retains the v1.2 Digital Space path and
 * Android Keystore alias so an in-place upgrade can discover and migrate the
 * existing installation. New Authentiverse accounts are isolated into their
 * own no-backup directories and use distinct non-exportable Keystore keys.
 */
class SecureStore(
    private val context: Context,
    val namespace: String = LEGACY_NAMESPACE
) {
    companion object {
        const val LEGACY_NAMESPACE = "legacy"
        private const val LEGACY_ALIAS = "DigitalSpace-Local-Protection-v1"
        private val SAFE_NAMESPACE = Regex("[A-Za-z0-9_.-]{1,80}")
    }

    val isLegacy: Boolean get() = namespace == LEGACY_NAMESPACE

    val rootDirectory: File
        get() = if (isLegacy) {
            File(context.noBackupFilesDir, "secure").apply { mkdirs() }
        } else {
            File(context.noBackupFilesDir, "authentiverse/accounts/$namespace/secure").apply { mkdirs() }
        }

    private val alias: String by lazy {
        if (isLegacy) LEGACY_ALIAS else {
            val digest = MessageDigest.getInstance("SHA-256").digest(namespace.encodeToByteArray())
            val suffix = digest.take(12).joinToString("") { "%02x".format(it) }
            "Authentiverse-Local-Protection-v1-$suffix"
        }
    }

    init {
        require(namespace == LEGACY_NAMESPACE || SAFE_NAMESPACE.matches(namespace)) { "Invalid account namespace." }
    }

    private fun key(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(alias, null) as? SecretKey)?.let { return it }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run {
            init(
                KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setRandomizedEncryptionRequired(true)
                    .build()
            )
            generateKey()
        }
    }

    fun put(name: String, clear: ByteArray) {
        requireName(name)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key())
        val ciphertext = cipher.doFinal(clear)
        val out = ByteArray(5 + cipher.iv.size + ciphertext.size)
        "DSS01".encodeToByteArray().copyInto(out)
        cipher.iv.copyInto(out, 5)
        ciphertext.copyInto(out, 5 + cipher.iv.size)
        val target = file(name)
        val temporary = File(target.parentFile, target.name + ".tmp")
        try {
            temporary.outputStream().use { it.write(out); it.fd.sync() }
            Os.rename(temporary.absolutePath, target.absolutePath)
        } finally {
            temporary.delete()
            ciphertext.fill(0)
            out.fill(0)
        }
    }

    fun get(name: String): ByteArray? {
        requireName(name)
        val target = file(name)
        if (!target.exists()) return null
        val encoded = target.readBytes()
        try {
            require(encoded.size >= 5 + 12 + 16 && encoded.copyOfRange(0, 5).decodeToString() == "DSS01") {
                "The encrypted local state is malformed."
            }
            val nonce = encoded.copyOfRange(5, 17)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, nonce))
            return cipher.doFinal(encoded, 17, encoded.size - 17)
        } finally {
            encoded.fill(0)
        }
    }

    fun exists(name: String): Boolean {
        requireName(name)
        return file(name).exists()
    }

    fun delete(name: String) {
        requireName(name)
        file(name).delete()
    }

    fun deleteProtectionKey() {
        runCatching {
            val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            if (store.containsAlias(alias)) store.deleteEntry(alias)
        }
    }

    private fun requireName(name: String) {
        require(name.matches(Regex("[A-Za-z0-9_.-]{1,96}"))) { "Invalid secure-store item name." }
    }

    private fun file(name: String): File = File(rootDirectory, "$name.dss")
}
