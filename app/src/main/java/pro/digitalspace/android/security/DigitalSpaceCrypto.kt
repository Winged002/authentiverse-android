/* SPDX-License-Identifier: MIT */
package pro.digitalspace.android.security

import android.util.Base64
import pro.digitalspace.android.model.ContactCard
import pro.digitalspace.android.model.AgreementState
import pro.digitalspace.android.model.NdaAgreement
import pro.digitalspace.android.model.NdaParticipant
import pro.digitalspace.android.model.SignedFileDescriptor
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPrivateKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.time.Instant
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

object DigitalSpaceCrypto {
    private val random = SecureRandom()
    fun random(count: Int) = ByteArray(count).also(random::nextBytes)
    fun sha256(value: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(value)
    fun hex(value: ByteArray): String = value.joinToString("") { "%02X".format(it) }
    fun b64(value: ByteArray): String = Base64.encodeToString(value, Base64.NO_WRAP)
    fun unb64(value: String): ByteArray = Base64.decode(value, Base64.DEFAULT)

    fun newP256(): KeyPair = KeyPairGenerator.getInstance("EC").run {
        initialize(ECGenParameterSpec("secp256r1"), random); generateKeyPair()
    }

    fun keyPair(privatePkcs8: ByteArray, publicSpki: ByteArray): KeyPair {
        val factory = KeyFactory.getInstance("EC")
        return KeyPair(factory.generatePublic(X509EncodedKeySpec(publicSpki)), factory.generatePrivate(PKCS8EncodedKeySpec(privatePkcs8)))
    }

    fun signP1363(privateKey: java.security.PrivateKey, payload: ByteArray): ByteArray {
        val der = Signature.getInstance("SHA256withECDSA").run { initSign(privateKey); update(payload); sign() }
        return derToP1363(der, 32)
    }

    fun verifyP1363(publicKey: java.security.PublicKey, payload: ByteArray, signature: ByteArray): Boolean =
        runCatching { Signature.getInstance("SHA256withECDSA").run {
            initVerify(publicKey); update(payload); verify(p1363ToDer(signature))
        }}.getOrDefault(false)

    fun publicKeyFromCertificate(encoded: String) = certificate(encoded).publicKey
    fun certificate(encoded: String): X509Certificate = CertificateFactory.getInstance("X.509")
        .generateCertificate(unb64(encoded).inputStream()) as X509Certificate

    fun derive(privateKey: java.security.PrivateKey, peerSpki: ByteArray, context: String, id: String): ByteArray {
        val peer = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(peerSpki))
        val secret = KeyAgreement.getInstance("ECDH").run { init(privateKey); doPhase(peer, true); generateSecret() }
        return sha256(context.encodeToByteArray() + secret + id.encodeToByteArray()).also { secret.fill(0) }
    }

    data class Sealed(val ciphertext: ByteArray, val tag: ByteArray)
    fun seal(clear: ByteArray, key: ByteArray, nonce: ByteArray, aad: ByteArray): Sealed {
        val output = Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce)); updateAAD(aad); doFinal(clear)
        }
        return Sealed(output.copyOf(output.size - 16), output.copyOfRange(output.size - 16, output.size))
    }

    fun open(ciphertext: ByteArray, tag: ByteArray, key: ByteArray, nonce: ByteArray, aad: ByteArray): ByteArray =
        Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce)); updateAAD(aad)
            doFinal(ciphertext + tag)
        }

    fun filePayload(v: SignedFileDescriptor) = listOf(
        "digitalspace-file-v1", v.fileId, v.fileName, v.contentType, v.size.toString(), v.sha256,
        v.addedAt.epochSecond.toString(), v.signerIdentityId, v.signerProfileId, v.signerHandle
    ).joinToString("\n").encodeToByteArray()

    fun contactPayload(v: ContactCard): ByteArray {
        val values = if (v.format == "digitalspace-contact-v2") listOf(
            v.format, v.contactId, v.identityId, v.profileId, v.handle, v.exchangePublicKey,
            v.pqKemAlgorithm.orEmpty(), v.pqKemPublicKey.orEmpty(),
            v.pqSignatureAlgorithm.orEmpty(), v.pqSigningPublicKey.orEmpty(),
            v.signingIssuerCertificate, v.issuedAt.epochSecond.toString(), v.expiresAt.epochSecond.toString()
        ) else listOf(
            v.format, v.contactId, v.identityId, v.profileId, v.handle, v.exchangePublicKey,
            v.signingIssuerCertificate, v.issuedAt.epochSecond.toString(), v.expiresAt.epochSecond.toString()
        )
        return values.joinToString("\n").encodeToByteArray()
    }

    fun agreementPayload(v: NdaAgreement) = listOf(
        v.format, v.ndaId, v.title, v.purpose, v.termsSha256, v.issuerIdentityId,
        v.issuerProfileId, v.issuerHandle, v.createdAt.epochSecond.toString(), v.validFrom.epochSecond.toString(),
        v.validUntil.epochSecond.toString(), v.postExpiryPolicy.name, v.fileIds.sorted().joinToString(","),
        v.participants.map { it.contactId }.sorted().joinToString(",")
    ).joinToString("\n").encodeToByteArray()

    fun decisionPayload(agreement: NdaAgreement, participant: NdaParticipant) = listOf(
        "digitalspace-nda-decision-v1", agreement.ndaId, agreement.termsSha256, participant.contactId,
        participant.profileId, participant.state.name, participant.respondedAt?.epochSecond?.toString() ?: ""
    ).joinToString("\n").encodeToByteArray()

    fun acceptancePayload(agreement: NdaAgreement, participant: NdaParticipant) = listOf(
        "digitalspace-nda-acceptance-v1", agreement.ndaId, agreement.termsSha256, participant.contactId,
        participant.profileId, participant.respondedAt?.epochSecond?.toString() ?: ""
    ).joinToString("\n").encodeToByteArray()

    fun verifyAgreementDecision(agreement: NdaAgreement, participant: NdaParticipant?): Boolean {
        if (participant == null || participant.state == AgreementState.Pending || participant.respondedAt == null ||
            participant.acceptanceCertificate.isNullOrBlank() || participant.acceptanceSignature.isNullOrBlank()) return false
        val publicKey = runCatching { publicKeyFromCertificate(participant.acceptanceCertificate!!) }.getOrNull() ?: return false
        val signature = runCatching { unb64(participant.acceptanceSignature!!) }.getOrNull() ?: return false
        return when (participant.state) {
            AgreementState.Accepted -> verifyP1363(publicKey, acceptancePayload(agreement, participant), signature)
            AgreementState.Declined -> verifyP1363(publicKey, decisionPayload(agreement, participant), signature)
            AgreementState.Pending -> false
        }
    }

    fun validateContact(card: ContactCard) {
        require(card.format in setOf("digitalspace-contact-v1", "digitalspace-contact-v2") && card.expiresAt.isAfter(Instant.now())) {
            "The contact is invalid or expired."
        }
        val public = unb64(card.exchangePublicKey)
        require(card.contactId == "contact_" + hex(sha256(public)).take(32).lowercase()) { "The contact identifier is invalid." }
        val payload = contactPayload(card)
        require(verifyP1363(publicKeyFromCertificate(card.signingCertificate), payload, unb64(card.signature))) {
            "The contact signature is invalid."
        }
        if (card.format == "digitalspace-contact-v2") {
            require(card.pqKemAlgorithm == PostQuantumIdentityKeyStore.KEM &&
                card.pqSignatureAlgorithm == PostQuantumIdentityKeyStore.SIGNATURE &&
                !card.pqKemPublicKey.isNullOrBlank() && !card.pqSigningPublicKey.isNullOrBlank() && !card.pqSignature.isNullOrBlank()) {
                "The contact post-quantum identity is incomplete."
            }
            require(PostQuantumIdentityKeyStore.verify(card.pqSigningPublicKey!!, payload, card.pqSignature!!)) {
                "The contact ML-DSA-87 signature is invalid."
            }
        }
    }

    fun validateAgreement(agreement: NdaAgreement) {
        require(agreement.format == "digitalspace-nda-v1" && agreement.ndaId.startsWith("nda_") &&
            agreement.title.trim().length in 3..120 && agreement.purpose.trim().length in 5..500 &&
            agreement.terms.length >= 20 && agreement.terms.encodeToByteArray().size <= 65536 &&
            agreement.validUntil.isAfter(agreement.validFrom) &&
            agreement.fileIds.isNotEmpty() && agreement.fileIds.size <= 1000 &&
            agreement.fileIds.distinct().size == agreement.fileIds.size && agreement.participants.isNotEmpty() &&
            agreement.participants.size <= 100 && agreement.participants.map { it.contactId }.distinct().size == agreement.participants.size &&
            agreement.participants.all { it.contactId.isNotBlank() && it.profileId.isNotBlank() && it.handle.isNotBlank() }) {
            "The NDA is invalid."
        }
        require(hex(sha256(agreement.terms.encodeToByteArray())).equals(agreement.termsSha256, true)) { "The NDA terms hash is invalid." }
        require(verifyP1363(publicKeyFromCertificate(agreement.issuerCertificate), agreementPayload(agreement), unb64(agreement.issuerSignature))) {
            "The NDA signature is invalid."
        }
    }

    private fun derToP1363(der: ByteArray, width: Int): ByteArray {
        var p = 0
        require(der[p++].toInt() == 0x30)
        val seqLength = readDerLength(der, p); p += seqLength.second
        require(der[p++].toInt() == 0x02); val rLen = readDerLength(der, p); p += rLen.second
        val r = der.copyOfRange(p, p + rLen.first); p += rLen.first
        require(der[p++].toInt() == 0x02); val sLen = readDerLength(der, p); p += sLen.second
        val s = der.copyOfRange(p, p + sLen.first)
        return fixed(r, width) + fixed(s, width)
    }

    private fun p1363ToDer(raw: ByteArray): ByteArray {
        require(raw.size % 2 == 0)
        fun integer(v: ByteArray): ByteArray {
            val unsigned = v.dropWhile { it == 0.toByte() }.toByteArray()
            val stripped = if (unsigned.isEmpty()) byteArrayOf(0) else unsigned
            val positive = if (stripped[0].toInt() and 0x80 != 0) byteArrayOf(0) + stripped else stripped
            return byteArrayOf(0x02) + derLength(positive.size) + positive
        }
        val half = raw.size / 2; val body = integer(raw.copyOfRange(0, half)) + integer(raw.copyOfRange(half, raw.size))
        return byteArrayOf(0x30) + derLength(body.size) + body
    }

    private fun fixed(value: ByteArray, width: Int): ByteArray {
        val unsigned = value.dropWhile { it == 0.toByte() }.toByteArray()
        require(unsigned.size <= width)
        return ByteArray(width - unsigned.size) + unsigned
    }
    private fun readDerLength(v: ByteArray, offset: Int): Pair<Int, Int> {
        val first = v[offset].toInt() and 0xff
        if (first < 128) return first to 1
        val count = first and 0x7f; var value = 0
        repeat(count) { value = (value shl 8) or (v[offset + 1 + it].toInt() and 0xff) }
        return value to (1 + count)
    }
    private fun derLength(value: Int): ByteArray = when {
        value < 128 -> byteArrayOf(value.toByte())
        value < 256 -> byteArrayOf(0x81.toByte(), value.toByte())
        else -> byteArrayOf(0x82.toByte(), (value ushr 8).toByte(), value.toByte())
    }
}
