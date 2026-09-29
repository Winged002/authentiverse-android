/* SPDX-License-Identifier: MIT */
package pro.digitalspace.android.security

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import java.io.ByteArrayOutputStream
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/**
 * Account-scoped identity keys. New signing keys use AndroidKeyStore and are
 * non-exportable. ECDH exchange keys use AndroidKeyStore on Android 12+ where
 * PURPOSE_AGREE_KEY exists; older devices retain the v1 encrypted-software
 * fallback and are reported as not high-assurance for exchange operations.
 */
class IdentityKeyStore(private val store: SecureStore) {
    fun keyPair(name: String): KeyPair {
        // Preserve upgrade compatibility with v1.2 packed EC private keys.
        store.get("ec-$name")?.let { packed ->
            try {
                require(packed.size > 4)
                val privateLength = ((packed[0].toInt() and 0xff) shl 8) or (packed[1].toInt() and 0xff)
                require(privateLength in 1 until packed.size - 2)
                val privateKey = packed.copyOfRange(2, 2 + privateLength)
                val publicKey = packed.copyOfRange(2 + privateLength, packed.size)
                return DigitalSpaceCrypto.keyPair(privateKey, publicKey).also {
                    privateKey.fill(0); publicKey.fill(0)
                }
            } finally { packed.fill(0) }
        }

        val alias = alias(name)
        val android = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val privateKey = android.getKey(alias, null) as? java.security.PrivateKey
        val certificate = android.getCertificate(alias)
        if (privateKey != null && certificate != null) return KeyPair(certificate.publicKey, privateKey)

        val isExchange = name == "exchange"
        if (isExchange && Build.VERSION.SDK_INT < 31) return createSoftware(name)

        return createAndroidKeyStore(alias, isExchange)
    }

    fun publicSpki(name: String): ByteArray = keyPair(name).public.encoded
    fun sign(name: String, payload: ByteArray): ByteArray = DigitalSpaceCrypto.signP1363(keyPair(name).private, payload)

    fun isHardwareBacked(name: String): Boolean = runCatching {
        val privateKey = keyPair(name).private
        // java.security.PrivateKey does not expose a provider property. AndroidKeyStore
        // private keys are non-exportable, and KeyInfo can only be obtained through
        // the AndroidKeyStore KeyFactory for keys backed by that provider.
        if (privateKey.encoded != null) return@runCatching false
        val factory = KeyFactory.getInstance(privateKey.algorithm, "AndroidKeyStore")
        factory.getKeySpec(privateKey, KeyInfo::class.java).isInsideSecureHardware
    }.getOrDefault(false)

    fun isNonExportable(name: String): Boolean = runCatching { keyPair(name).private.encoded == null }.getOrDefault(false)

    fun csrPem(name: String, commonName: String): String {
        val pair = keyPair(name)
        val subject = seq(set(seq(oid("2.5.4.3"), utf8(commonName.take(64)))))
        val cri = seq(integerZero(), subject, pair.public.encoded, byteArrayOf(0xA0.toByte(), 0x00))
        val signature = Signature.getInstance("SHA256withECDSA").run { initSign(pair.private); update(cri); sign() }
        val csr = seq(cri, seq(oid("1.2.840.10045.4.3.2")), bitString(signature))
        val body = java.util.Base64.getMimeEncoder(64, "\n".encodeToByteArray()).encodeToString(csr)
        return "-----BEGIN CERTIFICATE REQUEST-----\n$body\n-----END CERTIFICATE REQUEST-----\n"
    }

    private fun createAndroidKeyStore(alias: String, exchange: Boolean): KeyPair {
        val purposes = if (exchange && Build.VERSION.SDK_INT >= 31) KeyProperties.PURPOSE_AGREE_KEY else KeyProperties.PURPOSE_SIGN
        val builder = KeyGenParameterSpec.Builder(alias, purposes)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setUserAuthenticationRequired(false)
        if (!exchange) builder.setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
        return KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").run {
            initialize(builder.build())
            generateKeyPair()
        }
    }

    private fun createSoftware(name: String): KeyPair {
        val created = DigitalSpaceCrypto.newP256()
        val encodedPrivate = created.private.encoded
        val encodedPublic = created.public.encoded
        require(encodedPrivate.size <= 65535)
        val packed = byteArrayOf((encodedPrivate.size ushr 8).toByte(), encodedPrivate.size.toByte()) + encodedPrivate + encodedPublic
        try { store.put("ec-$name", packed) } finally { encodedPrivate.fill(0); packed.fill(0) }
        return created
    }

    private fun alias(name: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(store.namespace.encodeToByteArray())
            .take(8).joinToString("") { "%02x".format(it) }
        val safe = name.replace(Regex("[^A-Za-z0-9_.-]"), "-").take(48)
        return "Authentiverse-$digest-$safe"
    }

    private fun seq(vararg values: ByteArray) = tlv(0x30, values.fold(ByteArray(0), ByteArray::plus))
    private fun set(value: ByteArray) = tlv(0x31, value)
    private fun utf8(value: String) = tlv(0x0C, value.encodeToByteArray())
    private fun integerZero() = byteArrayOf(0x02, 0x01, 0x00)
    private fun bitString(value: ByteArray) = tlv(0x03, byteArrayOf(0) + value)
    private fun tlv(tag: Int, value: ByteArray) = byteArrayOf(tag.toByte()) + length(value.size) + value
    private fun length(value: Int): ByteArray = when {
        value < 128 -> byteArrayOf(value.toByte())
        value < 256 -> byteArrayOf(0x81.toByte(), value.toByte())
        else -> byteArrayOf(0x82.toByte(), (value ushr 8).toByte(), value.toByte())
    }
    private fun oid(value: String): ByteArray {
        val parts = value.split('.').map(String::toLong)
        val out = ByteArrayOutputStream().apply { write((parts[0] * 40 + parts[1]).toInt()) }
        for (part in parts.drop(2)) {
            var current = part
            val stack = ArrayDeque<Int>()
            stack.addFirst((current and 0x7f).toInt())
            while (current ushr 7 != 0L) {
                current = current ushr 7
                stack.addFirst(((current and 0x7f) or 0x80).toInt())
            }
            stack.forEach(out::write)
        }
        return tlv(0x06, out.toByteArray())
    }
}
