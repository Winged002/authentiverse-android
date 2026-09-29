/* SPDX-License-Identifier: MIT */
package pro.digitalspace.android.data

import android.content.Context
import android.net.Uri
import org.json.JSONObject
import pro.digitalspace.android.model.*
import pro.digitalspace.android.security.DigitalSpaceCrypto
import pro.digitalspace.android.security.IdentityKeyStore
import pro.digitalspace.android.security.PostQuantumIdentityKeyStore
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.OutputStream
import java.security.MessageDigest
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.UUID
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

sealed class ImportResult {
    data class Contact(val record: ContactRecord) : ImportResult()
    data class Nda(
        val agreement: NdaAgreement,
        val sender: String,
        val isResponse: Boolean = false,
        val decision: AgreementState? = null,
        val importedFiles: Int = 0
    ) : ImportResult()
    data class Shared(val record: SharedFileRecord) : ImportResult()
}

class ExchangeService(
    private val context: Context,
    private val store: InformationStore,
    private val keys: IdentityKeyStore,
    private val pq: PostQuantumIdentityKeyStore
) {
    companion object {
        private const val MAXIMUM_ENVELOPE_BYTES = 4 * 1024 * 1024
        private const val MAXIMUM_INDOOR_PACKAGE_BYTES = 64 * 1024 * 1024
        private const val MAXIMUM_NDA_ATTACHMENTS = 100
    }

    private data class ParsedShare(
        val record: SharedFileRecord,
        val sender: ContactCard,
        val agreement: NdaAgreement?
    )

    fun ownContact(state: PersistentState): ContactCard {
        val identity = requireNotNull(state.identityId); val profile = requireNotNull(state.profileId)
        val handle = requireNotNull(state.profileHandle); val cert = requireNotNull(state.foundationalCertificate)
        val issuer = requireNotNull(state.foundationalIssuerCertificate)
        val exchange = keys.publicSpki("exchange")
        val now = Instant.now()
        val public = pq.publicMaterial()
        val card = ContactCard(format = "digitalspace-contact-v2",
            contactId = "contact_" + DigitalSpaceCrypto.hex(DigitalSpaceCrypto.sha256(exchange)).take(32).lowercase(),
            identityId = identity, profileId = profile, handle = handle,
            exchangePublicKey = DigitalSpaceCrypto.b64(exchange), signingCertificate = cert,
            signingIssuerCertificate = issuer, issuedAt = now, expiresAt = now.plus(365, ChronoUnit.DAYS), signature = "",
            pqKemAlgorithm = PostQuantumIdentityKeyStore.KEM, pqKemPublicKey = public.kemPublicKey,
            pqSignatureAlgorithm = PostQuantumIdentityKeyStore.SIGNATURE, pqSigningPublicKey = public.signingPublicKey)
        val payload = DigitalSpaceCrypto.contactPayload(card)
        card.signature = DigitalSpaceCrypto.b64(keys.sign("foundational", payload))
        card.pqSignature = pq.sign(payload)
        return card
    }

    fun createAgreement(title: String, purpose: String, terms: String, validUntil: Instant,
                        policy: PostExpiryAccessPolicy, contactIds: List<String>, fileIds: List<String>,
                        state: PersistentState): NdaAgreement {
        require(title.trim().length in 3..120) { "Use a title between three and 120 characters." }
        require(purpose.trim().length in 5..500) { "Describe the purpose in five to 500 characters." }
        require(terms.trim().length >= 20 && terms.trim().encodeToByteArray().size <= 65536) {
            "Use terms between 20 characters and 64 KiB."
        }
        val now = Instant.now()
        require(validUntil.isAfter(now.plus(5, ChronoUnit.MINUTES)) && validUntil.isBefore(now.plus(3653, ChronoUnit.DAYS))) {
            "Choose an expiry between five minutes and ten years from now."
        }
        require(contactIds.isNotEmpty() && contactIds.distinct().size <= 100) { "Choose between one and 100 people." }
        require(fileIds.isNotEmpty() && fileIds.distinct().size <= 1000) { "Choose between one and 1,000 protected files." }
        val manifest = store.load(); val contacts = manifest.contacts.filter { it.card.contactId in contactIds }
        require(contacts.size == contactIds.distinct().size && manifest.ownedFiles.count { it.descriptor.fileId in fileIds } == fileIds.distinct().size)
        val nda = NdaAgreement(ndaId = "nda_" + id(), title = title.trim(), purpose = purpose.trim(),
            terms = terms.trim(), termsSha256 = DigitalSpaceCrypto.hex(DigitalSpaceCrypto.sha256(terms.trim().encodeToByteArray())),
            issuerIdentityId = requireNotNull(state.identityId), issuerProfileId = requireNotNull(state.profileId),
            issuerHandle = requireNotNull(state.profileHandle), createdAt = now, validFrom = now, validUntil = validUntil,
            postExpiryPolicy = policy, fileIds = fileIds.distinct().sorted(),
            participants = contacts.map { NdaParticipant(it.card.contactId, it.card.profileId, it.card.handle, AgreementState.Pending) }.toMutableList(),
            issuerCertificate = requireNotNull(state.foundationalCertificate), issuerSignature = "")
        nda.issuerSignature = DigitalSpaceCrypto.b64(keys.sign("foundational", DigitalSpaceCrypto.agreementPayload(nda)))
        store.addAgreement(nda); return nda
    }

    fun exportContact(destination: Uri, state: PersistentState) = write(destination, ownContact(state).toJson().toString(2).encodeToByteArray())

    fun exportNda(ndaId: String, recipientContactId: String, destination: Uri, state: PersistentState) {
        val agreement = store.load().agreements.first { it.ndaId == ndaId }
        if (agreement.issuerCertificate == state.foundationalCertificate) {
            context.contentResolver.openOutputStream(destination, "w").use { output ->
                requireNotNull(output); writeIssuedNdaPackage(agreement, recipientContactId, output, state)
            }
        } else {
            write(destination, createNdaEnvelope(ndaId, recipientContactId, state))
        }
    }

    fun createNdaPackageBytes(ndaId: String, recipientContactId: String, state: PersistentState): ByteArray {
        val agreement = store.load().agreements.first { it.ndaId == ndaId }
        if (agreement.issuerCertificate != state.foundationalCertificate) {
            return createNdaEnvelope(ndaId, recipientContactId, state)
        }
        val temporary = File.createTempFile("nda-", ".dsnda", context.cacheDir)
        return try {
            FileOutputStream(temporary).use { writeIssuedNdaPackage(agreement, recipientContactId, it, state) }
            require(temporary.length() <= MAXIMUM_INDOOR_PACKAGE_BYTES) {
                "This NDA package is too large for Indoor delivery. Export it as a .dsnda file instead."
            }
            temporary.readBytes()
        } finally { temporary.delete() }
    }

    fun createNdaEnvelope(ndaId: String, recipientContactId: String, state: PersistentState): ByteArray {
        val manifest = store.load(); val agreement = manifest.agreements.first { it.ndaId == ndaId }
        val recipient = manifest.contacts.first { it.card.contactId == recipientContactId }
        DigitalSpaceCrypto.validateAgreement(agreement); DigitalSpaceCrypto.validateContact(recipient.card)
        val own = ownContact(state)
        val issuedByMe = agreement.issuerCertificate == state.foundationalCertificate
        if (issuedByMe) {
            val participant = agreement.participants.firstOrNull { it.contactId == recipientContactId }
            require(participant != null && participant.profileId == recipient.card.profileId &&
                participant.handle == recipient.card.handle) { "This person is not part of the NDA." }
        } else {
            val decision = agreement.participants.firstOrNull { it.contactId == own.contactId }
            require(DigitalSpaceCrypto.verifyAgreementDecision(agreement, decision)) {
                "Sign your decision before returning this NDA."
            }
            require(recipient.card.signingCertificate == agreement.issuerCertificate) {
                "A signed NDA response can only be returned to its issuer."
            }
        }
        val clear = agreement.toJson().toString(2).encodeToByteArray(); require(clear.size in 1..MAXIMUM_ENVELOPE_BYTES)
        val exchangeId = "ndax_" + id(); val ephemeral = DigitalSpaceCrypto.newP256()
        val key = DigitalSpaceCrypto.derive(ephemeral.private, DigitalSpaceCrypto.unb64(recipient.card.exchangePublicKey),
            "DigitalSpace/NdaExchange/v1", exchangeId)
        val fingerprint = DigitalSpaceCrypto.hex(DigitalSpaceCrypto.sha256(DigitalSpaceCrypto.unb64(recipient.card.exchangePublicKey)))
        val nonce = DigitalSpaceCrypto.random(12)
        val sealed = DigitalSpaceCrypto.seal(clear, key, nonce, "$exchangeId:$recipientContactId:$fingerprint".encodeToByteArray())
        val envelope = JSONObject().put("format", "digitalspace-nda-exchange-v1").put("exchange_id", exchangeId)
            .put("sender", own.toJson()).put("recipient_contact_id", recipientContactId)
            .put("recipient_key_sha256", fingerprint).put("ephemeral_public_key", DigitalSpaceCrypto.b64(ephemeral.public.encoded))
            .put("nonce", DigitalSpaceCrypto.b64(nonce)).put("ciphertext", DigitalSpaceCrypto.b64(sealed.ciphertext))
            .put("tag", DigitalSpaceCrypto.b64(sealed.tag)).put("created_at", Instant.now().toString()).put("signature", "")
        envelope.put("signature", DigitalSpaceCrypto.b64(keys.sign("foundational", ndaEnvelopePayload(envelope))))
        key.fill(0); clear.fill(0); return envelope.toString(2).encodeToByteArray()
    }

    fun exportShare(fileId: String, recipientId: String, ndaId: String?, destination: Uri, state: PersistentState,
                    allowPending: Boolean = false) {
        context.contentResolver.openOutputStream(destination, "w").use { output ->
            requireNotNull(output); writeSharePackage(fileId, recipientId, ndaId, output, state, allowPending)
        }
    }

    private fun writeSharePackage(fileId: String, recipientId: String, ndaId: String?, output: OutputStream,
                                  state: PersistentState, allowPending: Boolean = false) {
        val m = store.load(); val owned = m.ownedFiles.first { it.descriptor.fileId == fileId }
        val recipient = m.contacts.first { it.card.contactId == recipientId }
        val nda = ndaId?.let { id -> m.agreements.first { it.ndaId == id } }
        if (nda != null) {
            DigitalSpaceCrypto.validateAgreement(nda)
            val participant = nda.participants.first { it.contactId == recipientId }
            require(Instant.now().isBefore(nda.validUntil)) { "This NDA has expired." }
            require(nda.fileIds.contains(fileId) && (allowPending ||
                DigitalSpaceCrypto.verifyAgreementDecision(nda, participant) && participant.state == AgreementState.Accepted))
        }
        val shareId = "share_" + id(); val packageKey = DigitalSpaceCrypto.random(32); val ephemeral = DigitalSpaceCrypto.newP256()
        val recipientPublic = DigitalSpaceCrypto.unb64(recipient.card.exchangePublicKey)
        val fingerprint = DigitalSpaceCrypto.hex(DigitalSpaceCrypto.sha256(recipientPublic))
        val wrapKey = DigitalSpaceCrypto.derive(ephemeral.private, recipientPublic, "DigitalSpace/ShareWrap/v1", shareId)
        val wrapNonce = DigitalSpaceCrypto.random(12)
        val wrapped = DigitalSpaceCrypto.seal(packageKey, wrapKey, wrapNonce, "$shareId:$fingerprint".encodeToByteArray())
        val temporary = File.createTempFile("share-", ".dsvault", context.cacheDir)
        try {
            store.vaultFile(owned.vaultName).inputStream().use { input -> temporary.outputStream().use { output ->
                VaultCipher.reencrypt(input, output, DigitalSpaceCrypto.unb64(owned.contentKey), owned.descriptor.fileId, packageKey, shareId)
            }}
            val encryptedHash = DigitalSpaceCrypto.hex(hash(temporary))
            val manifest = JSONObject().put("format", "digitalspace-share-v1").put("share_id", shareId)
                .put("sender", ownContact(state).toJson()).put("recipient_contact_id", recipientId)
                .put("recipient_key_sha256", fingerprint).put("file", owned.descriptor.toJson()).putOpt("nda", nda?.toJson())
                .put("ephemeral_public_key", DigitalSpaceCrypto.b64(ephemeral.public.encoded))
                .put("wrapped_content_key", DigitalSpaceCrypto.b64(wrapped.ciphertext)).put("wrap_nonce", DigitalSpaceCrypto.b64(wrapNonce))
                .put("wrap_tag", DigitalSpaceCrypto.b64(wrapped.tag)).put("encrypted_sha256", encryptedHash)
                .put("created_at", Instant.now().toString()).put("bundle_signature", "")
            manifest.put("bundle_signature", DigitalSpaceCrypto.b64(keys.sign("foundational", sharePayload(manifest))))
            ZipOutputStream(output).use { zip ->
                    zip.putNextEntry(ZipEntry("content.dsvault").apply { method = ZipEntry.STORED; size = temporary.length(); compressedSize = size; crc = crc32(temporary) })
                    temporary.inputStream().use { it.copyTo(zip) }; zip.closeEntry()
                    zip.putNextEntry(ZipEntry("manifest.json")); zip.write(manifest.toString(2).encodeToByteArray()); zip.closeEntry()
            }
        } finally { temporary.delete(); packageKey.fill(0); wrapKey.fill(0) }
    }

    private fun writeIssuedNdaPackage(agreement: NdaAgreement, recipientId: String, output: OutputStream, state: PersistentState) {
        DigitalSpaceCrypto.validateAgreement(agreement)
        require(agreement.issuerCertificate == state.foundationalCertificate) { "Only the issuer can send the original NDA." }
        require(agreement.fileIds.size <= MAXIMUM_NDA_ATTACHMENTS) {
            "A single .dsnda package supports up to $MAXIMUM_NDA_ATTACHMENTS files."
        }
        val covered = store.load().ownedFiles.filter { it.descriptor.fileId in agreement.fileIds }
        require(covered.size == agreement.fileIds.size) { "One or more protected files are no longer available." }
        require(covered.all { it.descriptor.signerCertificate == agreement.issuerCertificate }) {
            "A covered file was signed by a different identity certificate. Create a new protected copy first."
        }
        val envelope = createNdaEnvelope(agreement.ndaId, recipientId, state)
        ZipOutputStream(output).use { zip ->
            zip.putNextEntry(ZipEntry("agreement.envelope")); zip.write(envelope); zip.closeEntry()
            covered.sortedBy { agreement.fileIds.indexOf(it.descriptor.fileId) }.forEachIndexed { index, record ->
                val share = File.createTempFile("nda-share-", ".dsshare", context.cacheDir)
                try {
                    FileOutputStream(share).use { writeSharePackage(record.descriptor.fileId, recipientId,
                        agreement.ndaId, it, state, allowPending = true) }
                    zip.putNextEntry(ZipEntry("files/${index.toString().padStart(4, '0')}.dsshare").apply {
                        method = ZipEntry.STORED; size = share.length(); compressedSize = size; crc = crc32(share)
                    })
                    share.inputStream().use { it.copyTo(zip) }; zip.closeEntry()
                } finally { share.delete() }
            }
        }
    }

    fun import(uri: Uri, state: PersistentState): ImportResult {
        val temporary = File.createTempFile("import-", ".package", context.cacheDir)
        try {
            context.contentResolver.openInputStream(uri).use { input -> requireNotNull(input); temporary.outputStream().use(input::copyTo) }
            return importFile(temporary, state)
        } finally { temporary.delete() }
    }

    fun importBytes(bytes: ByteArray, state: PersistentState): ImportResult {
        val temporary = File.createTempFile("inbox-", ".package", context.cacheDir)
        return try { temporary.writeBytes(bytes); importFile(temporary, state) }
        finally { temporary.delete() }
    }

    private fun importFile(file: File, state: PersistentState): ImportResult {
        require(file.length() in 1..(16L * 1024 * 1024 * 1024)) { "The Digital Space package has an invalid size." }
        return if (FileInputStream(file).use { it.read() } == '{'.code) importJson(file.readText(), state)
        else if (isNdaPackage(file)) importNdaPackage(file, state) else importShare(file, state)
    }

    private fun importJson(text: String, state: PersistentState): ImportResult {
        val root = JSONObject(text)
        return when (root.optString("format")) {
            "digitalspace-contact-v1" -> {
                val card = ContactCard.fromJson(root); validateTrustedContact(card, state)
                val record = ContactRecord(card, "@${card.handle}", Instant.now()); store.addContact(record); ImportResult.Contact(record)
            }
            "digitalspace-nda-exchange-v1" -> importNdaEnvelope(root, state, persist = true)
            else -> throw IllegalArgumentException("Unsupported Digital Space package.")
        }
    }

    private fun importNdaEnvelope(root: JSONObject, state: PersistentState, persist: Boolean): ImportResult.Nda {
        require(root.optString("format") == "digitalspace-nda-exchange-v1" &&
            root.optString("exchange_id").matches(Regex("ndax_[a-f0-9]{32}"))) { "The NDA envelope is invalid." }
        val createdAt = Instant.parse(root.getString("created_at"))
        require(!createdAt.isAfter(Instant.now().plus(1, ChronoUnit.MINUTES))) { "The NDA envelope timestamp is invalid." }
        val sender = ContactCard.fromJson(root.getJSONObject("sender")); validateTrustedContact(sender, state)
        require(DigitalSpaceCrypto.verifyP1363(DigitalSpaceCrypto.publicKeyFromCertificate(sender.signingCertificate),
            ndaEnvelopePayload(root), DigitalSpaceCrypto.unb64(root.getString("signature"))))
        val own = ownContact(state); require(root.getString("recipient_contact_id") == own.contactId)
        val fingerprint = DigitalSpaceCrypto.hex(DigitalSpaceCrypto.sha256(keys.publicSpki("exchange")))
        require(fingerprint.equals(root.getString("recipient_key_sha256"), true))
        val key = DigitalSpaceCrypto.derive(keys.keyPair("exchange").private, DigitalSpaceCrypto.unb64(root.getString("ephemeral_public_key")),
            "DigitalSpace/NdaExchange/v1", root.getString("exchange_id"))
        val clear = try {
            DigitalSpaceCrypto.open(DigitalSpaceCrypto.unb64(root.getString("ciphertext")), DigitalSpaceCrypto.unb64(root.getString("tag")),
                key, DigitalSpaceCrypto.unb64(root.getString("nonce")),
                "${root.getString("exchange_id")}:${own.contactId}:$fingerprint".encodeToByteArray())
        } finally { key.fill(0) }
        try {
            require(clear.size in 1..MAXIMUM_ENVELOPE_BYTES)
            val agreement = NdaAgreement.fromJson(JSONObject(clear.decodeToString()))
            DigitalSpaceCrypto.validateAgreement(agreement)
            val manifest = store.load()
            val existing = manifest.agreements.firstOrNull { it.ndaId == agreement.ndaId }
            val senderIsIssuer = sender.signingCertificate == agreement.issuerCertificate
            if (senderIsIssuer) {
                require(agreement.participants.any { it.contactId == own.contactId }) { "You are not a participant in this NDA." }
                if (existing != null) {
                    require(existing.issuerSignature == agreement.issuerSignature) { "This NDA conflicts with an existing agreement." }
                    val prior = existing.participants.firstOrNull { it.contactId == own.contactId }
                    val received = agreement.participants.first { it.contactId == own.contactId }
                    if (DigitalSpaceCrypto.verifyAgreementDecision(existing, prior)) {
                        copyDecision(requireNotNull(prior), received)
                    } else {
                        received.state = AgreementState.Pending
                        received.respondedAt = null
                        received.acceptanceCertificate = null
                        received.acceptanceSignature = null
                    }
                } else {
                    agreement.participants.first { it.contactId == own.contactId }.apply {
                        this.state = AgreementState.Pending
                        respondedAt = null
                        acceptanceCertificate = null
                        acceptanceSignature = null
                    }
                }
                if (persist) {
                    store.addContact(ContactRecord(sender, "@${sender.handle}", Instant.now()))
                    store.addAgreement(agreement)
                }
                return ImportResult.Nda(agreement, sender.handle)
            }

            require(existing != null && existing.issuerSignature == agreement.issuerSignature &&
                existing.issuerCertificate == state.foundationalCertificate) { "This is not a valid response to an NDA you issued." }
            val response = agreement.participants.firstOrNull { it.contactId == sender.contactId }
            require(response != null && response.profileId == sender.profileId &&
                response.acceptanceCertificate == sender.signingCertificate &&
                DigitalSpaceCrypto.verifyAgreementDecision(agreement, response)) { "The participant signature is invalid." }
            val local = existing.participants.first { it.contactId == response.contactId }
            require(local.profileId == sender.profileId && local.handle == sender.handle) {
                "The response identity does not match the NDA participant."
            }
            copyDecision(response, local)
            if (persist) {
                manifest.contacts.removeAll { it.card.contactId == sender.contactId }
                manifest.contacts.add(ContactRecord(sender, "@${sender.handle}", Instant.now()))
                store.save(manifest)
            }
            return ImportResult.Nda(existing, sender.handle, isResponse = true, decision = local.state)
        } finally { clear.fill(0) }
    }

    private fun importShare(packageFile: File, state: PersistentState): ImportResult.Shared {
        val parsed = parseShare(packageFile, state)
        return try {
            commitShare(parsed, includeAgreement = true)
            ImportResult.Shared(parsed.record)
        } catch (error: Throwable) {
            store.vaultFile(parsed.record.vaultName).delete()
            throw error
        }
    }

    private fun parseShare(packageFile: File, state: PersistentState): ParsedShare {
        val content = File.createTempFile("shared-", ".dsvault", context.cacheDir)
        try {
            val manifest = ZipFile(packageFile).use { zip ->
                val entries = zip.entries().asSequence().toList()
                require(entries.size == 2 && entries.map { it.name }.toSet() == setOf("content.dsvault", "manifest.json"))
                val contentEntry = requireNotNull(zip.getEntry("content.dsvault"))
                val manifestEntry = requireNotNull(zip.getEntry("manifest.json"))
                require(contentEntry.size in 1..(16L * 1024 * 1024 * 1024) && manifestEntry.size in 1..(2L * 1024 * 1024))
                zip.getInputStream(contentEntry).use { input -> content.outputStream().use(input::copyTo) }
                JSONObject(zip.getInputStream(manifestEntry).bufferedReader().use { it.readText() })
            }
            require(manifest.getString("format") == "digitalspace-share-v1")
            val sender = ContactCard.fromJson(manifest.getJSONObject("sender")); validateTrustedContact(sender, state)
            require(DigitalSpaceCrypto.verifyP1363(DigitalSpaceCrypto.publicKeyFromCertificate(sender.signingCertificate), sharePayload(manifest),
                DigitalSpaceCrypto.unb64(manifest.getString("bundle_signature"))))
            require(DigitalSpaceCrypto.hex(hash(content)).equals(manifest.getString("encrypted_sha256"), true))
            val own = ownContact(state); require(manifest.getString("recipient_contact_id") == own.contactId)
            val fingerprint = DigitalSpaceCrypto.hex(DigitalSpaceCrypto.sha256(keys.publicSpki("exchange")))
            require(fingerprint.equals(manifest.getString("recipient_key_sha256"), true))
            val shareId = manifest.getString("share_id")
            val wrapKey = DigitalSpaceCrypto.derive(keys.keyPair("exchange").private, DigitalSpaceCrypto.unb64(manifest.getString("ephemeral_public_key")),
                "DigitalSpace/ShareWrap/v1", shareId)
            val contentKey = DigitalSpaceCrypto.open(DigitalSpaceCrypto.unb64(manifest.getString("wrapped_content_key")),
                DigitalSpaceCrypto.unb64(manifest.getString("wrap_tag")), wrapKey, DigitalSpaceCrypto.unb64(manifest.getString("wrap_nonce")),
                "$shareId:$fingerprint".encodeToByteArray())
            val descriptor = SignedFileDescriptor.fromJson(manifest.getJSONObject("file"))
            require(DigitalSpaceCrypto.verifyP1363(DigitalSpaceCrypto.publicKeyFromCertificate(descriptor.signerCertificate),
                DigitalSpaceCrypto.filePayload(descriptor), DigitalSpaceCrypto.unb64(descriptor.signature)))
            val nda = manifest.optJSONObject("nda")?.let(NdaAgreement::fromJson)
            nda?.let { DigitalSpaceCrypto.validateAgreement(it) }
            val destination = store.vaultFile("$shareId-${id().take(8)}.dsvault")
            content.copyTo(destination, overwrite = false)
            val record = SharedFileRecord(shareId, descriptor, sender.contactId, own.contactId, destination.name,
                DigitalSpaceCrypto.b64(contentKey), manifest.getString("encrypted_sha256"), nda?.ndaId, Instant.now())
            wrapKey.fill(0); contentKey.fill(0); return ParsedShare(record, sender, nda)
        } finally { content.delete() }
    }

    private fun importNdaPackage(packageFile: File, state: PersistentState): ImportResult.Nda {
        val staged = mutableListOf<ParsedShare>()
        try {
            return ZipFile(packageFile).use { zip ->
                val entries = zip.entries().asSequence().toList()
                require(entries.size in 2..(MAXIMUM_NDA_ATTACHMENTS + 1)) { "The NDA package has an invalid number of files." }
                val agreementEntry = requireNotNull(zip.getEntry("agreement.envelope")) { "The NDA agreement is missing." }
                require(agreementEntry.size in 1..MAXIMUM_ENVELOPE_BYTES.toLong()) { "The NDA agreement is too large." }
                val fileEntries = entries.filter { it.name.matches(Regex("files/[0-9]{4}\\.dsshare")) }.sortedBy { it.name }
                require(fileEntries.size == entries.size - 1) { "The NDA package contains an unexpected file." }
                val envelopeBytes = zip.getInputStream(agreementEntry).use { it.readBytes() }
                val root = JSONObject(envelopeBytes.decodeToString())
                val preview = importNdaEnvelope(root, state, persist = false)
                val envelopeSender = ContactCard.fromJson(root.getJSONObject("sender"))
                require(!preview.isResponse && fileEntries.size == preview.agreement.fileIds.size) {
                    "The NDA package does not contain every protected file."
                }
                fileEntries.forEach { entry ->
                    val temporary = File.createTempFile("nda-import-", ".dsshare", context.cacheDir)
                    try {
                        zip.getInputStream(entry).use { input -> temporary.outputStream().use(input::copyTo) }
                        staged.add(parseShare(temporary, state))
                    } finally { temporary.delete() }
                }
                val importedIds = staged.map { it.record.descriptor.fileId }
                require(importedIds.distinct().size == importedIds.size && importedIds.toSet() == preview.agreement.fileIds.toSet() &&
                    staged.all { parsed -> parsed.agreement?.let { agreement ->
                        agreement.ndaId == preview.agreement.ndaId &&
                            agreement.issuerSignature == preview.agreement.issuerSignature &&
                            parsed.sender.contactId == envelopeSender.contactId &&
                            parsed.sender.signingCertificate == preview.agreement.issuerCertificate &&
                            parsed.record.descriptor.signerCertificate == preview.agreement.issuerCertificate
                    } == true }) {
                    "An attached file is not covered by this NDA."
                }
                store.addNdaPackage(ContactRecord(envelopeSender, "@${envelopeSender.handle}", Instant.now()),
                    preview.agreement, staged.map { it.record })
                preview.copy(importedFiles = staged.size)
            }
        } catch (error: Throwable) {
            staged.forEach { store.vaultFile(it.record.vaultName).delete() }
            throw error
        }
    }

    private fun commitShare(parsed: ParsedShare, includeAgreement: Boolean) {
        store.addContact(ContactRecord(parsed.sender, "@${parsed.sender.handle}", Instant.now()))
        if (includeAgreement) parsed.agreement?.let(store::addAgreement)
        store.addShared(parsed.record)
    }

    private fun copyDecision(source: NdaParticipant, destination: NdaParticipant) {
        destination.state = source.state
        destination.respondedAt = source.respondedAt
        destination.acceptanceCertificate = source.acceptanceCertificate
        destination.acceptanceSignature = source.acceptanceSignature
    }

    private fun isNdaPackage(file: File): Boolean = ZipFile(file).use { it.getEntry("agreement.envelope") != null }

    private fun validateTrustedContact(card: ContactCard, state: PersistentState) {
        DigitalSpaceCrypto.validateContact(card)
        val trusted = requireNotNull(state.foundationalIssuerCertificate) { "The trusted Digital Space authority is missing." }
        require(DigitalSpaceCrypto.sha256(DigitalSpaceCrypto.unb64(card.signingIssuerCertificate))
            .contentEquals(DigitalSpaceCrypto.sha256(DigitalSpaceCrypto.unb64(trusted)))) { "The contact authority is not trusted." }
        DigitalSpaceCrypto.certificate(card.signingCertificate).verify(DigitalSpaceCrypto.certificate(card.signingIssuerCertificate).publicKey)
    }

    private fun ndaEnvelopePayload(v: JSONObject) = listOf(v.getString("format"), v.getString("exchange_id"),
        v.getJSONObject("sender").getString("contact_id"), v.getString("recipient_contact_id"), v.getString("recipient_key_sha256"),
        v.getString("ephemeral_public_key"), v.getString("nonce"), v.getString("tag"),
        DigitalSpaceCrypto.hex(DigitalSpaceCrypto.sha256(DigitalSpaceCrypto.unb64(v.getString("ciphertext")))),
        Instant.parse(v.getString("created_at")).epochSecond.toString()).joinToString("\n").encodeToByteArray()

    private fun sharePayload(v: JSONObject) = listOf(v.getString("format"), v.getString("share_id"),
        v.getJSONObject("sender").getString("contact_id"), v.getString("recipient_contact_id"), v.getString("recipient_key_sha256"),
        v.getJSONObject("file").getString("file_id"), v.getJSONObject("file").getString("sha256"),
        v.optJSONObject("nda")?.optString("nda_id") ?: "", v.getString("ephemeral_public_key"), v.getString("wrapped_content_key"),
        v.getString("wrap_nonce"), v.getString("wrap_tag"), v.getString("encrypted_sha256"),
        Instant.parse(v.getString("created_at")).epochSecond.toString()).joinToString("\n").encodeToByteArray()

    private fun hash(file: File): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(1024 * 1024)
            while (true) { val n = input.read(buffer); if (n < 0) break; digest.update(buffer, 0, n) }
            buffer.fill(0)
        }
        return digest.digest()
    }
    private fun crc32(file: File) = java.util.zip.CRC32().apply { file.inputStream().use { input ->
        val buffer = ByteArray(1024 * 1024); while (true) { val n = input.read(buffer); if (n < 0) break; update(buffer, 0, n) }
    }}.value
    private fun write(uri: Uri, bytes: ByteArray) = context.contentResolver.openOutputStream(uri, "w").use { requireNotNull(it).write(bytes) }
    private fun id() = UUID.randomUUID().toString().replace("-", "").lowercase()
}
