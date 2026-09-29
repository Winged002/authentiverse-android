/* SPDX-License-Identifier: MIT */
package pro.digitalspace.android.passwords

import org.json.JSONObject
import pro.digitalspace.android.data.ExchangeService
import pro.digitalspace.android.data.InformationStore
import pro.digitalspace.android.model.ContactCard
import pro.digitalspace.android.model.PersistentState
import pro.digitalspace.android.security.DigitalSpaceCrypto
import pro.digitalspace.android.security.IdentityKeyStore
import java.time.Instant

class PasswordCredentialShareService(
    private val passwords: PasswordVaultStore,
    private val information: InformationStore,
    private val exchange: ExchangeService,
    private val keys: IdentityKeyStore
) {
    fun createShare(credentialId: String, recipientId: String, policy: PasswordCredentialAccessPolicy, state: PersistentState): ByteArray {
        require(policy.canAutofill || policy.canCopy || policy.canReveal) { "A shared credential must permit at least one use." }
        require(policy.expiresAt == null || policy.expiresAt!!.isAfter(Instant.now().plusSeconds(60))) { "Choose a credential expiry in the future." }
        val recipient = information.load().contacts.firstOrNull { it.card.contactId == recipientId }
            ?: throw IllegalArgumentException("Choose a verified Vault contact.")
        DigitalSpaceCrypto.validateContact(recipient.card)
        val source = passwords.loadRecord(credentialId)
        try {
            passwords.ensureUsable(source)
            val shareId = "cshare_" + id()
            val packageKey = DigitalSpaceCrypto.random(32)
            val ephemeral = DigitalSpaceCrypto.newP256()
            val recipientPublic = DigitalSpaceCrypto.unb64(recipient.card.exchangePublicKey)
            val fingerprint = DigitalSpaceCrypto.hex(DigitalSpaceCrypto.sha256(recipientPublic))
            val wrapKey = DigitalSpaceCrypto.derive(ephemeral.private, recipientPublic, "Authentiverse/CredentialShareWrap/v1", shareId)
            val wrapNonce = DigitalSpaceCrypto.random(12); val payloadNonce = DigitalSpaceCrypto.random(12)
            try {
                val wrapped = DigitalSpaceCrypto.seal(packageKey, wrapKey, wrapNonce, "$shareId:$fingerprint".encodeToByteArray())
                val own = exchange.ownContact(state)
                val payloadRecord = PasswordCredentialRecord(source.credentialId, source.title, source.username, source.passwordUtf8.copyOf(),
                    source.url, source.allowedOrigins.toMutableList(), source.notes, source.totpSecret.copyOf(), PasswordCredentialScope.Shared,
                    source.teamId, source.teamName, own.contactId, own,
                    PasswordCredentialAccessPolicy(policy.canReveal, policy.canCopy, policy.canAutofill, policy.expiresAt, null, own.contactId, shareId),
                    mutableListOf(), source.createdAt, source.updatedAt, source.passwordChangedAt)
                val clear = payloadRecord.toJson().toString().encodeToByteArray()
                payloadRecord.destroy()
                try {
                    val sealed = DigitalSpaceCrypto.seal(clear, packageKey, payloadNonce, "Authentiverse/CredentialSharePayload/v1\n$shareId".encodeToByteArray())
                    val root = JSONObject().put("format", "authentiverse-credential-share-v1").put("share_id", shareId)
                        .put("credential_id", source.credentialId).put("sender", own.toJson()).put("recipient_contact_id", recipientId)
                        .put("recipient_key_sha256", fingerprint).put("ephemeral_public_key", DigitalSpaceCrypto.b64(ephemeral.public.encoded))
                        .put("wrap_nonce", DigitalSpaceCrypto.b64(wrapNonce)).put("wrapped_key", DigitalSpaceCrypto.b64(wrapped.ciphertext))
                        .put("wrap_tag", DigitalSpaceCrypto.b64(wrapped.tag)).put("payload_nonce", DigitalSpaceCrypto.b64(payloadNonce))
                        .put("payload", DigitalSpaceCrypto.b64(sealed.ciphertext)).put("payload_tag", DigitalSpaceCrypto.b64(sealed.tag))
                        .put("access", policy.toJson()).put("issued_at", Instant.now().toString()).put("signature", "")
                    root.put("signature", DigitalSpaceCrypto.b64(keys.sign("foundational", canonical(root))))
                    source.issuedShares.add(PasswordIssuedShare(shareId, recipientId, Instant.now(), policy.expiresAt))
                    source.updatedAt = Instant.now(); passwords.saveRecord(source)
                    wrapped.ciphertext.fill(0); wrapped.tag.fill(0); sealed.ciphertext.fill(0); sealed.tag.fill(0)
                    return root.toString(2).encodeToByteArray()
                } finally { clear.fill(0) }
            } finally { packageKey.fill(0); recipientPublic.fill(0); wrapKey.fill(0); wrapNonce.fill(0); payloadNonce.fill(0) }
        } finally { source.destroy() }
    }

    fun importShare(bytes: ByteArray): String {
        require(bytes.size in 1..4*1024*1024)
        val root = JSONObject(bytes.decodeToString()); validatePackage(root)
        val sender = ContactCard.fromJson(root.getJSONObject("sender")); val shareId = root.getString("share_id")
        val ownPublic = keys.publicSpki("exchange"); val fingerprint = DigitalSpaceCrypto.hex(DigitalSpaceCrypto.sha256(ownPublic))
        try {
            require(root.getString("recipient_key_sha256").equals(fingerprint, true)) { "This credential package was encrypted for another Authentiverse contact." }
            val wrapKey = DigitalSpaceCrypto.derive(keys.keyPair("exchange").private, DigitalSpaceCrypto.unb64(root.getString("ephemeral_public_key")),
                "Authentiverse/CredentialShareWrap/v1", shareId)
            try {
                val packageKey = DigitalSpaceCrypto.open(DigitalSpaceCrypto.unb64(root.getString("wrapped_key")), DigitalSpaceCrypto.unb64(root.getString("wrap_tag")),
                    wrapKey, DigitalSpaceCrypto.unb64(root.getString("wrap_nonce")), "$shareId:$fingerprint".encodeToByteArray())
                try {
                    val clear = DigitalSpaceCrypto.open(DigitalSpaceCrypto.unb64(root.getString("payload")), DigitalSpaceCrypto.unb64(root.getString("payload_tag")),
                        packageKey, DigitalSpaceCrypto.unb64(root.getString("payload_nonce")), "Authentiverse/CredentialSharePayload/v1\n$shareId".encodeToByteArray())
                    try {
                        val record = PasswordCredentialRecord.fromJson(JSONObject(clear.decodeToString()))
                        try {
                            require(record.scope == PasswordCredentialScope.Shared && record.access.shareId == shareId && record.access.issuerContactId == sender.contactId)
                            require(record.access.usable()) { "The shared credential is expired or revoked." }
                            passwords.knownRevocation(shareId, sender.contactId)?.let { record.access.revokedAt = it; passwords.ensureUsable(record) }
                            record.issuerCard = sender; record.updatedAt = Instant.now(); passwords.saveRecord(record)
                            ensureIndexed(record.credentialId)
                            return record.credentialId
                        } finally { record.destroy() }
                    } finally { clear.fill(0) }
                } finally { packageKey.fill(0) }
            } finally { wrapKey.fill(0) }
        } finally { ownPublic.fill(0) }
    }

    fun createRevocation(credentialId: String, shareId: String, state: PersistentState): ByteArray {
        val record = passwords.loadRecord(credentialId)
        try {
            val issued = record.issuedShares.firstOrNull { it.shareId == shareId } ?: throw IllegalArgumentException("The selected credential share does not exist.")
            val at = Instant.now(); issued.revokedAt = at; record.updatedAt = at; passwords.saveRecord(record)
            val own = exchange.ownContact(state)
            val root = JSONObject().put("format", "authentiverse-credential-revocation-v1").put("share_id", shareId)
                .put("credential_id", credentialId).put("issuer_contact_id", own.contactId).put("revoked_at", at.toString())
                .put("signing_certificate", own.signingCertificate).put("signature", "")
            root.put("signature", DigitalSpaceCrypto.b64(keys.sign("foundational", canonical(root))))
            return root.toString(2).encodeToByteArray()
        } finally { record.destroy() }
    }

    fun importRevocation(bytes: ByteArray) {
        val root = JSONObject(bytes.decodeToString())
        require(root.optString("format") == "authentiverse-credential-revocation-v1") { "The credential revocation package is invalid." }
        val shareId=root.getString("share_id");val issuer=root.getString("issuer_contact_id");val at=Instant.parse(root.getString("revoked_at"))
        require(!at.isAfter(Instant.now().plusSeconds(60)))
        val contact = information.load().contacts.firstOrNull { it.card.contactId == issuer }
            ?: throw IllegalStateException("The credential revocation issuer is not a verified Vault contact.")
        DigitalSpaceCrypto.validateContact(contact.card)
        require(contact.card.signingCertificate == root.getString("signing_certificate")) { "The revocation certificate does not match the verified contact." }
        require(DigitalSpaceCrypto.verifyP1363(DigitalSpaceCrypto.publicKeyFromCertificate(contact.card.signingCertificate), canonical(root),
            DigitalSpaceCrypto.unb64(root.getString("signature")))) { "The credential revocation signature is invalid." }
        passwords.recordRevocation(shareId, issuer, at)
        passwords.list().firstOrNull { it.access.shareId==shareId && it.access.issuerContactId==issuer }?.let { summary ->
            val record=passwords.loadRecord(summary.credentialId);try{record.access.revokedAt=at;passwords.saveRecord(record)}finally{record.destroy()}
        }
    }

    private fun validatePackage(root:JSONObject){require(root.optString("format")=="authentiverse-credential-share-v1");val sender=ContactCard.fromJson(root.getJSONObject("sender"));DigitalSpaceCrypto.validateContact(sender);val issued=Instant.parse(root.getString("issued_at"));require(!issued.isAfter(Instant.now().plusSeconds(60)));val access=PasswordCredentialAccessPolicy.fromJson(root.getJSONObject("access"));require(access.usable());require(DigitalSpaceCrypto.verifyP1363(DigitalSpaceCrypto.publicKeyFromCertificate(sender.signingCertificate),canonical(root),DigitalSpaceCrypto.unb64(root.getString("signature")))){"The credential share signature is invalid."}}
    private fun canonical(root:JSONObject):ByteArray{val copy=JSONObject(root.toString());copy.put("signature","");return copy.toString().encodeToByteArray()}
    private fun ensureIndexed(id:String){
        // PasswordVaultStore keeps index details private; a one-record backup/import is avoided by using its public upsert helper.
        passwords.indexExisting(id)
    }
    private fun id()=java.util.UUID.randomUUID().toString().replace("-","")
}
