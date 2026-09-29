/* SPDX-License-Identifier: MIT */
package pro.digitalspace.android.chat

import org.json.JSONObject
import pro.digitalspace.android.model.ContactCard
import pro.digitalspace.android.security.DigitalSpaceCrypto
import pro.digitalspace.android.security.IdentityKeyStore
import pro.digitalspace.android.security.PostQuantumIdentityKeyStore
import java.security.MessageDigest
import java.time.Instant
import java.time.temporal.ChronoUnit
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** Windows-compatible digitalspace-chat-v1 hybrid envelope. */
class HybridChatCrypto(private val keys: IdentityKeyStore, private val pq: PostQuantumIdentityKeyStore) {
    fun encrypt(sender: ContactCard, recipient: ContactCard, content: ChatContent, policy: ChatMessagePolicy, expiresAt: Instant?): ChatEnvelope {
        requirePq(sender, "Your contact card"); requirePq(recipient, "The recipient contact card")
        require(content.kind in setOf("text", "call_invite", "call_decline"))
        val now = Instant.now()
        if (policy == ChatMessagePolicy.ExpireAfter) require(expiresAt != null && expiresAt.isAfter(now) && expiresAt.isBefore(now.plus(30, ChronoUnit.DAYS)))
        else require(expiresAt == null) { "Only disappearing messages may have an expiry." }

        val envelope = ChatEnvelope(messageId = "chat_" + java.util.UUID.randomUUID().toString().replace("-", ""), sender = sender,
            recipientContactId = recipient.contactId, createdAt = now, expiresAt = expiresAt, policy = policy)
        val ephemeral = DigitalSpaceCrypto.newP256()
        envelope.ephemeralPublicKey = DigitalSpaceCrypto.b64(ephemeral.public.encoded)
        val classical = DigitalSpaceCrypto.derive(ephemeral.private, DigitalSpaceCrypto.unb64(recipient.exchangePublicKey),
            "DigitalSpace/ChatECDH/v1", envelope.messageId)
        val kem = pq.encapsulate(requireNotNull(recipient.pqKemPublicKey))
        envelope.pqKemCiphertext = DigitalSpaceCrypto.b64(kem.ciphertext)
        val contentKey = deriveContentKey(classical, kem.sharedSecret, envelope)
        val clear = content.toJson().toString().encodeToByteArray()
        require(clear.size <= 64 * 1024) { "A private chat message may not exceed 64 KiB." }
        val nonce = DigitalSpaceCrypto.random(12)
        try {
            val sealed = DigitalSpaceCrypto.seal(clear, contentKey, nonce, aad(envelope))
            envelope.nonce = DigitalSpaceCrypto.b64(nonce)
            envelope.ciphertext = DigitalSpaceCrypto.b64(sealed.ciphertext)
            envelope.tag = DigitalSpaceCrypto.b64(sealed.tag)
            val payload = signaturePayload(envelope)
            try {
                envelope.classicalSignature = DigitalSpaceCrypto.b64(keys.sign("foundational", payload))
                envelope.pqSignature = pq.sign(payload)
            } finally { payload.fill(0) }
            sealed.ciphertext.fill(0); sealed.tag.fill(0)
            return envelope
        } finally {
            classical.fill(0); kem.ciphertext.fill(0); kem.sharedSecret.fill(0); contentKey.fill(0); clear.fill(0); nonce.fill(0)
        }
    }

    fun decrypt(envelope: ChatEnvelope, ownCard: ContactCard, now: Instant = Instant.now()): ChatContent {
        validateEnvelope(envelope, ownCard, now)
        val signature = signaturePayload(envelope)
        try {
            require(DigitalSpaceCrypto.verifyP1363(DigitalSpaceCrypto.publicKeyFromCertificate(envelope.sender.signingCertificate),
                signature, DigitalSpaceCrypto.unb64(envelope.classicalSignature))) { "The chat sender's classical signature is invalid." }
            require(PostQuantumIdentityKeyStore.verify(requireNotNull(envelope.sender.pqSigningPublicKey), signature, envelope.pqSignature)) {
                "The chat sender's ML-DSA-87 signature is invalid."
            }
        } finally { signature.fill(0) }

        val classical = DigitalSpaceCrypto.derive(keys.keyPair("exchange").private, DigitalSpaceCrypto.unb64(envelope.ephemeralPublicKey),
            "DigitalSpace/ChatECDH/v1", envelope.messageId)
        val quantum = pq.decapsulate(envelope.pqKemCiphertext)
        val contentKey = deriveContentKey(classical, quantum, envelope)
        val nonce = DigitalSpaceCrypto.unb64(envelope.nonce)
        val ciphertext = DigitalSpaceCrypto.unb64(envelope.ciphertext)
        val tag = DigitalSpaceCrypto.unb64(envelope.tag)
        try {
            require(nonce.size == 12 && tag.size == 16 && ciphertext.size <= 64 * 1024) { "The encrypted chat payload is malformed." }
            val clear = DigitalSpaceCrypto.open(ciphertext, tag, contentKey, nonce, aad(envelope))
            try {
                val content = ChatContent.fromJson(JSONObject(clear.decodeToString()))
                require(content.kind in setOf("text", "call_invite", "call_decline")) { "The private chat content type is invalid." }
                return content
            } finally { clear.fill(0) }
        } finally { classical.fill(0); quantum.fill(0); contentKey.fill(0); nonce.fill(0); ciphertext.fill(0); tag.fill(0) }
    }

    private fun validateEnvelope(v: ChatEnvelope, own: ContactCard, now: Instant) {
        require(v.format == "digitalspace-chat-v1" && v.messageId.matches(Regex("chat_[0-9a-f]{32}"))) { "The private chat envelope is invalid." }
        requirePq(v.sender, "The sender contact card"); requirePq(own, "Your contact card")
        require(v.recipientContactId == own.contactId) { "This private message was encrypted for a different contact." }
        require(!v.createdAt.isAfter(now.plus(2, ChronoUnit.MINUTES)) && !v.createdAt.isBefore(now.minus(31, ChronoUnit.DAYS))) { "The chat timestamp is invalid." }
        if (v.policy == ChatMessagePolicy.ExpireAfter) require(v.expiresAt != null && v.expiresAt.isAfter(v.createdAt) && !v.expiresAt.isAfter(v.createdAt.plus(30, ChronoUnit.DAYS)))
        else require(v.expiresAt == null)
        if (v.expiresAt?.isAfter(now) == false) throw IllegalStateException("This private message has expired.")
        require(v.ephemeralPublicKey.isNotBlank() && v.pqKemCiphertext.isNotBlank() && v.nonce.isNotBlank() &&
            v.ciphertext.isNotBlank() && v.tag.isNotBlank() && v.classicalSignature.isNotBlank() && v.pqSignature.isNotBlank())
    }

    private fun requirePq(card: ContactCard, label: String) {
        DigitalSpaceCrypto.validateContact(card)
        require(card.format == "digitalspace-contact-v2" && card.pqKemAlgorithm == PostQuantumIdentityKeyStore.KEM &&
            card.pqSignatureAlgorithm == PostQuantumIdentityKeyStore.SIGNATURE && !card.pqKemPublicKey.isNullOrBlank() && !card.pqSigningPublicKey.isNullOrBlank()) {
            "$label is a legacy contact card. Re-export it with Authentiverse before using high-assurance private chat."
        }
    }

    private fun aad(v: ChatEnvelope) = listOf("DigitalSpace/Chat/AAD/v1", v.format, v.messageId, v.sender.contactId, v.recipientContactId,
        v.createdAt.toEpochMilli().toString(), v.expiresAt?.toEpochMilli()?.toString().orEmpty(), v.policy.name,
        v.ephemeralPublicKey, v.pqKemCiphertext).joinToString("\n").encodeToByteArray()

    private fun signaturePayload(v: ChatEnvelope): ByteArray {
        val ciphertext = DigitalSpaceCrypto.unb64(v.ciphertext)
        val hash = try { DigitalSpaceCrypto.hex(MessageDigest.getInstance("SHA-512").digest(ciphertext)) } finally { ciphertext.fill(0) }
        return listOf("DigitalSpace/Chat/EnvelopeSignature/v1", v.format, v.messageId, v.sender.contactId, v.recipientContactId,
            v.createdAt.toEpochMilli().toString(), v.expiresAt?.toEpochMilli()?.toString().orEmpty(), v.policy.name,
            v.ephemeralPublicKey, v.pqKemCiphertext, v.nonce, v.tag, hash).joinToString("\n").encodeToByteArray()
    }

    private fun deriveContentKey(classical: ByteArray, quantum: ByteArray, v: ChatEnvelope): ByteArray {
        val ikm = classical + quantum
        val salt = MessageDigest.getInstance("SHA-512").digest(listOf("DigitalSpace/Chat/KDFSalt/v1", v.messageId,
            v.sender.contactId, v.recipientContactId).joinToString("\n").encodeToByteArray())
        val info = "DigitalSpace/Chat/ContentKey/v1|ECDH-P256+ML-KEM-1024|AES-256-GCM".encodeToByteArray()
        return try { hkdf(ikm, salt, info, 32) } finally { ikm.fill(0); salt.fill(0); info.fill(0) }
    }

    private fun hkdf(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        val extract = Mac.getInstance("HmacSHA512").apply { init(SecretKeySpec(salt, "HmacSHA512")) }
        val prk = extract.doFinal(ikm)
        return try {
            val result = ByteArray(length); var previous = ByteArray(0); var offset = 0; var counter = 1
            while (offset < length) {
                val mac = Mac.getInstance("HmacSHA512").apply { init(SecretKeySpec(prk, "HmacSHA512")); update(previous); update(info); update(counter.toByte()) }
                val block = mac.doFinal(); previous.fill(0); previous = block
                val count = minOf(block.size, length - offset); block.copyInto(result, offset, 0, count); offset += count; counter++
            }
            previous.fill(0); result
        } finally { prk.fill(0) }
    }
}
