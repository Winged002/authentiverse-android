/* SPDX-License-Identifier: MIT */
package pro.digitalspace.android.data

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import pro.digitalspace.android.model.*
import pro.digitalspace.android.security.DigitalSpaceCrypto
import pro.digitalspace.android.security.IdentityKeyStore
import pro.digitalspace.android.security.SecureStore
import pro.digitalspace.android.security.VaultSession
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.time.Instant
import java.util.UUID

class InformationStore(
    private val context: Context,
    private val secure: SecureStore,
    private val vaultSession: VaultSession,
    private val keys: IdentityKeyStore
) {
    companion object { private const val MAX_MEMORY_VIEW_BYTES = 64L * 1024 * 1024 }

    private val vault = if (secure.isLegacy) {
        File(context.noBackupFilesDir, "information-vault")
    } else {
        File(context.noBackupFilesDir, "authentiverse/accounts/${secure.namespace}/information-vault")
    }.apply { mkdirs() }

    @Synchronized
    fun load(): InformationManifest {
        vaultSession.get("information-manifest")?.let { clear ->
            try { return InformationManifest.fromJson(org.json.JSONObject(clear.decodeToString())) }
            finally { clear.fill(0) }
        }
        // In-place v1.2 migration: once the user establishes/unlocks the Vault,
        // move the old Keystore-only manifest behind the new PIN/VMK layer.
        secure.get("information-manifest")?.let { legacy ->
            try {
                val parsed = InformationManifest.fromJson(org.json.JSONObject(legacy.decodeToString()))
                save(parsed)
                secure.delete("information-manifest")
                return parsed
            } finally { legacy.fill(0) }
        }
        return InformationManifest()
    }

    @Synchronized
    fun save(value: InformationManifest) {
        require(vaultSession.isUnlocked) { "Unlock Vault to continue." }
        val clear = value.toJson().toString().encodeToByteArray()
        try { vaultSession.put("information-manifest", clear) } finally { clear.fill(0) }
    }

    @Synchronized
    fun addOwnedFile(uri: Uri, state: PersistentState, folderPath: String = ""): OwnedFileRecord {
        require(state.enrolled && state.identityId != null && state.profileId != null && state.profileHandle != null)
        require(vaultSession.isUnlocked) { "Unlock Vault to protect files." }
        val certificate = requireNotNull(state.foundationalCertificate) { "The foundational certificate is unavailable." }
        val metadata = context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE), null, null, null)?.use { c ->
            if (!c.moveToFirst()) null else c.getString(0) to c.getLong(1)
        }
        val name = sanitize(metadata?.first ?: uri.lastPathSegment ?: "protected-file")
        val fileId = "file_" + UUID.randomUUID().toString().replace("-", "")
        val key = DigitalSpaceCrypto.random(32)
        val target = File(vault, "$fileId.dsvault")
        val hash = context.contentResolver.openInputStream(uri).use { input ->
            requireNotNull(input)
            FileOutputStream(target).use { output -> VaultCipher.encrypt(input, output, key, fileId) }
        }
        val now = Instant.now()
        var descriptor = SignedFileDescriptor(
            fileId, name, context.contentResolver.getType(uri) ?: "application/octet-stream",
            metadata?.second ?: 0L, DigitalSpaceCrypto.hex(hash), now, state.identityId!!, state.profileId!!,
            state.profileHandle!!, certificate, ""
        )
        descriptor = descriptor.copy(signature = DigitalSpaceCrypto.b64(keys.sign("foundational", DigitalSpaceCrypto.filePayload(descriptor))))
        val folder = normalizeVaultFolder(folderPath)
        val record = OwnedFileRecord(descriptor, target.name, DigitalSpaceCrypto.b64(key), folder, name)
        val manifest = load()
        if (folder.isNotBlank() && folder !in manifest.folders) manifest.folders.add(folder)
        manifest.ownedFiles.removeAll { it.descriptor.fileId == fileId }
        manifest.ownedFiles.add(record)
        save(manifest)
        key.fill(0)
        return record
    }

    @Synchronized
    fun createFolder(path: String) {
        val clean = normalizeVaultFolder(path)
        require(clean.isNotBlank()) { "Folder name is required." }
        val m = load()
        val segments = clean.split('/')
        var current = ""
        segments.forEach { segment ->
            current = if (current.isBlank()) segment else "$current/$segment"
            if (current !in m.folders) m.folders.add(current)
        }
        save(m)
    }

    @Synchronized
    fun moveOwnedFile(fileId: String, folderPath: String) {
        val folder = normalizeVaultFolder(folderPath)
        val m = load()
        if (folder.isNotBlank() && folder !in m.folders) createFolder(folder)
        m.ownedFiles.first { it.descriptor.fileId == fileId }.folderPath = folder
        save(m)
    }

    @Synchronized
    fun renameOwnedFile(fileId: String, displayName: String) {
        val clean = sanitize(displayName)
        require(clean.isNotBlank())
        val m = load()
        m.ownedFiles.first { it.descriptor.fileId == fileId }.displayName = clean
        save(m)
    }

    @Synchronized
    fun deleteOwnedFile(fileId: String) {
        val m = load()
        val record = m.ownedFiles.first { it.descriptor.fileId == fileId }
        require(m.agreements.none { fileId in it.fileIds }) { "This file is referenced by an NDA and cannot be deleted." }
        m.ownedFiles.remove(record)
        save(m)
        runCatching { vaultFile(record.vaultName).delete() }
    }

    @Synchronized
    fun deleteFolder(path: String) {
        val clean = normalizeVaultFolder(path)
        require(clean.isNotBlank())
        val m = load()
        require(m.ownedFiles.none { it.folderPath == clean || it.folderPath.startsWith("$clean/") }) { "Move or delete files in this folder first." }
        m.folders.removeAll { it == clean || it.startsWith("$clean/") }
        save(m)
    }

    @Synchronized
    fun addContact(record: ContactRecord) {
        DigitalSpaceCrypto.validateContact(record.card)
        val m = load(); m.contacts.removeAll { it.card.contactId == record.card.contactId }; m.contacts.add(record); save(m)
    }

    @Synchronized
    fun addAgreement(value: NdaAgreement) {
        DigitalSpaceCrypto.validateAgreement(value)
        val m = load(); m.agreements.removeAll { it.ndaId == value.ndaId }; m.agreements.add(value); save(m)
    }

    @Synchronized
    fun addShared(value: SharedFileRecord) {
        val m = load()
        val replaced = m.sharedFiles.firstOrNull { it.shareId == value.shareId }
        m.sharedFiles.removeAll { it.shareId == value.shareId }; m.sharedFiles.add(value); save(m)
        if (replaced != null && replaced.vaultName != value.vaultName) runCatching { vaultFile(replaced.vaultName).delete() }
    }

    @Synchronized
    fun addNdaPackage(contact: ContactRecord, agreement: NdaAgreement, files: List<SharedFileRecord>) {
        DigitalSpaceCrypto.validateContact(contact.card)
        DigitalSpaceCrypto.validateAgreement(agreement)
        require(files.isNotEmpty() && files.all { it.ndaId == agreement.ndaId }) { "The NDA package files are invalid." }
        val m = load()
        val replaced = m.sharedFiles.filter { prior -> files.any {
            it.shareId == prior.shareId || (it.ndaId == prior.ndaId &&
                it.descriptor.fileId == prior.descriptor.fileId && it.recipientContactId == prior.recipientContactId)
        } }
        m.contacts.removeAll { it.card.contactId == contact.card.contactId }; m.contacts.add(contact)
        m.agreements.removeAll { it.ndaId == agreement.ndaId }; m.agreements.add(agreement)
        m.sharedFiles.removeAll { it in replaced }; m.sharedFiles.addAll(files)
        save(m)
        replaced.filter { prior -> files.none { it.vaultName == prior.vaultName } }
            .forEach { runCatching { vaultFile(it.vaultName).delete() } }
    }

    @Synchronized
    fun decide(ndaId: String, ownContactId: String, accepted: Boolean, state: PersistentState): NdaAgreement {
        val m = load(); val nda = m.agreements.first { it.ndaId == ndaId }
        DigitalSpaceCrypto.validateAgreement(nda)
        require(Instant.now().isBefore(nda.validUntil)) { "This NDA has expired and can no longer be signed." }
        val participant = nda.participants.first { it.contactId == ownContactId }
        require(participant.profileId == state.profileId && state.foundationalCertificate != null) {
            "This NDA was not issued to your active Authentiverse identity."
        }
        participant.state = if (accepted) AgreementState.Accepted else AgreementState.Declined
        participant.respondedAt = Instant.now(); participant.acceptanceCertificate = state.foundationalCertificate
        val payload = if (accepted) DigitalSpaceCrypto.acceptancePayload(nda, participant)
            else DigitalSpaceCrypto.decisionPayload(nda, participant)
        participant.acceptanceSignature = DigitalSpaceCrypto.b64(keys.sign("foundational", payload))
        save(m); return nda
    }

    fun readOwnedBytes(fileId: String): ByteArray {
        val record = load().ownedFiles.first { it.descriptor.fileId == fileId }
        require(record.descriptor.size <= MAX_MEMORY_VIEW_BYTES) { "This file is too large for the memory-only Secure Viewer." }
        return decryptToMemory(vaultFile(record.vaultName), DigitalSpaceCrypto.unb64(record.contentKey), record.descriptor.fileId, record.descriptor.sha256)
    }

    fun readSharedBytes(shareId: String): ByteArray {
        val record = load().sharedFiles.first { it.shareId == shareId }
        enforceSharedAccess(record)
        require(record.descriptor.size <= MAX_MEMORY_VIEW_BYTES) { "This file is too large for the memory-only Secure Viewer." }
        return decryptToMemory(vaultFile(record.vaultName), DigitalSpaceCrypto.unb64(record.contentKey), record.shareId, record.descriptor.sha256)
    }

    /** Legacy export helper retained for interoperability/manual workflows. */
    fun decryptOwned(fileId: String, destination: File) {
        val record = load().ownedFiles.first { it.descriptor.fileId == fileId }
        decryptManaged(destination) { temporary -> vaultFile(record.vaultName).inputStream().use { input -> temporary.outputStream().use { output ->
            val key = DigitalSpaceCrypto.unb64(record.contentKey)
            try {
                val hash = VaultCipher.decrypt(input, output, key, record.descriptor.fileId)
                require(DigitalSpaceCrypto.hex(hash).equals(record.descriptor.sha256, true)) { "Protected file integrity check failed." }
            } finally { key.fill(0) }
        } } }
    }

    /** Legacy export helper retained for interoperability/manual workflows. */
    fun decryptShared(shareId: String, destination: File) {
        val record = load().sharedFiles.first { it.shareId == shareId }
        enforceSharedAccess(record)
        decryptManaged(destination) { temporary -> vaultFile(record.vaultName).inputStream().use { input -> temporary.outputStream().use { output ->
            val key = DigitalSpaceCrypto.unb64(record.contentKey)
            try {
                val hash = VaultCipher.decrypt(input, output, key, record.shareId)
                require(DigitalSpaceCrypto.hex(hash).equals(record.descriptor.sha256, true)) { "Shared file integrity check failed." }
            } finally { key.fill(0) }
        } } }
    }

    fun vaultFile(name: String): File {
        require(name.matches(Regex("[A-Za-z0-9_.-]{1,160}"))); return File(vault, name)
    }

    private fun enforceSharedAccess(record: SharedFileRecord) {
        val nda = record.ndaId?.let { id -> load().agreements.firstOrNull { it.ndaId == id } }
        if (nda != null) {
            val own = nda.participants.firstOrNull { it.contactId == record.recipientContactId }
            require(own?.state == AgreementState.Accepted && DigitalSpaceCrypto.verifyAgreementDecision(nda, own)) {
                "Accept and sign the NDA before viewing this file."
            }
            if (Instant.now().isAfter(nda.validUntil) && nda.postExpiryPolicy == PostExpiryAccessPolicy.RevokeManagedAccess)
                throw IllegalStateException("The NDA expired and managed access has been revoked.")
        }
    }

    private fun decryptToMemory(source: File, key: ByteArray, id: String, expectedSha256: String): ByteArray {
        try {
            val out = ByteArrayOutputStream()
            source.inputStream().use { input ->
                val hash = VaultCipher.decrypt(input, out, key, id)
                require(DigitalSpaceCrypto.hex(hash).equals(expectedSha256, true)) { "Secure Viewer integrity check failed." }
            }
            return out.toByteArray()
        } finally { key.fill(0) }
    }

    private fun decryptManaged(destination: File, block: (File) -> Unit) {
        val temporary = File(destination.parentFile, destination.name + ".part")
        try {
            temporary.delete(); block(temporary); destination.delete()
            check(temporary.renameTo(destination)) { "Could not open the managed file." }
        } finally { temporary.delete() }
    }

    private fun sanitize(name: String): String = name.replace(Regex("[\\u0000-\\u001f\\\\/:*?\"<>|]"), "_").take(180).ifBlank { "protected-file" }
}
