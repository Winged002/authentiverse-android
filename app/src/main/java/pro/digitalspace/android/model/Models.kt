/* SPDX-License-Identifier: MIT */
package pro.digitalspace.android.model

import org.json.JSONArray
import org.json.JSONObject
import java.time.Instant

enum class SpaceState { UNINITIALIZED, OUTDOORS, ENROLLING, JOINING_AREA, ENTERING, INDOORS, LEAVING, ERROR }

data class PersistentState(
    var identityId: String? = null,
    var profileId: String? = null,
    var deviceId: String? = null,
    var selectedAreaId: String? = null,
    var wireGuardPrivateKey: String? = null,
    var wireGuardPublicKey: String? = null,
    var profileHandle: String? = null,
    var deviceName: String? = null,
    var enrolled: Boolean = false,
    var currentAreaName: String? = null,
    var deviceCertificate: String? = null,
    var deviceIssuerCertificate: String? = null,
    var foundationalCertificate: String? = null,
    var foundationalIssuerCertificate: String? = null,
    var profileCertificate: String? = null,
    var profileIssuerCertificate: String? = null,
    var indoorServerCaCertificate: String? = null,
    var isolatedIndoor: Boolean = false
) {
    fun toJson() = JSONObject().apply {
        putOpt("identity_id", identityId); putOpt("profile_id", profileId); putOpt("device_id", deviceId)
        putOpt("selected_area_id", selectedAreaId); putOpt("wg_private_key", wireGuardPrivateKey)
        putOpt("wg_public_key", wireGuardPublicKey); putOpt("profile_handle", profileHandle)
        putOpt("device_name", deviceName); put("enrolled", enrolled); putOpt("current_area_name", currentAreaName)
        putOpt("device_certificate", deviceCertificate); putOpt("device_issuer_certificate", deviceIssuerCertificate)
        putOpt("foundational_certificate", foundationalCertificate)
        putOpt("foundational_issuer_certificate", foundationalIssuerCertificate)
        putOpt("profile_certificate", profileCertificate); putOpt("profile_issuer_certificate", profileIssuerCertificate)
        putOpt("indoor_server_ca_certificate", indoorServerCaCertificate)
        put("isolated_indoor", isolatedIndoor)
    }

    companion object {
        fun fromJson(o: JSONObject) = PersistentState(
            o.optStringOrNull("identity_id"), o.optStringOrNull("profile_id"), o.optStringOrNull("device_id"),
            o.optStringOrNull("selected_area_id"), o.optStringOrNull("wg_private_key"),
            o.optStringOrNull("wg_public_key"), o.optStringOrNull("profile_handle"),
            o.optStringOrNull("device_name"), o.optBoolean("enrolled"), o.optStringOrNull("current_area_name"),
            o.optStringOrNull("device_certificate"), o.optStringOrNull("device_issuer_certificate"),
            o.optStringOrNull("foundational_certificate"), o.optStringOrNull("foundational_issuer_certificate"),
            o.optStringOrNull("profile_certificate"), o.optStringOrNull("profile_issuer_certificate"),
            o.optStringOrNull("indoor_server_ca_certificate"), o.optBoolean("isolated_indoor", false)
        )
    }
}

data class Area(val id: String, val name: String, val description: String = "", val available: Boolean = true) {
    companion object { fun fromJson(o: JSONObject) = Area(
        o.stringAny("area_id", "id"), o.stringAny("area_name", "name", "display_name"), o.optString("description"),
        o.optBoolean("available", true) && !o.optBoolean("disabled", false)) }
}

data class TunnelInfo(
    val areaId: String,
    val areaName: String,
    val deviceId: String,
    val address: String,
    val serverPublicKey: String,
    val endpoint: String,
    val allowedIps: List<String>,
    val persistentKeepalive: Int,
    val dns: List<String>
) {
    companion object { fun fromJson(o: JSONObject) = TunnelInfo(
        o.stringAny("area_id"), o.optString("area_name"), o.stringAny("device_id"), o.stringAny("address"),
        o.stringAny("server_public_key"), o.stringAny("endpoint"),
        o.optJSONArray("allowed_ips").strings().ifEmpty { listOf("10.200.0.0/16") },
        o.optInt("persistent_keepalive", 25), o.optJSONArray("dns").strings()) }
}

data class SignedFileDescriptor(
    val fileId: String, val fileName: String, val contentType: String, val size: Long,
    val sha256: String, val addedAt: Instant, val signerIdentityId: String,
    val signerProfileId: String, val signerHandle: String, val signerCertificate: String,
    val signature: String
) {
    fun toJson() = JSONObject().apply {
        put("file_id", fileId); put("file_name", fileName); put("content_type", contentType); put("size", size)
        put("sha256", sha256); put("added_at", addedAt.toString()); put("signer_identity_id", signerIdentityId)
        put("signer_profile_id", signerProfileId); put("signer_handle", signerHandle)
        put("signer_certificate", signerCertificate); put("signature", signature)
    }
    companion object { fun fromJson(o: JSONObject) = SignedFileDescriptor(
        o.getString("file_id"), o.getString("file_name"), o.optString("content_type", "application/octet-stream"),
        o.getLong("size"), o.getString("sha256"), o.instant("added_at"), o.getString("signer_identity_id"),
        o.getString("signer_profile_id"), o.getString("signer_handle"), o.getString("signer_certificate"),
        o.getString("signature")) }
}

data class OwnedFileRecord(
    val descriptor: SignedFileDescriptor, val vaultName: String, val contentKey: String,
    var folderPath: String = "", var displayName: String = descriptor.fileName
) {
    fun toJson() = JSONObject().put("descriptor", descriptor.toJson()).put("vault_name", vaultName)
        .put("content_key", contentKey).put("folder_path", folderPath).put("display_name", displayName)
    companion object { fun fromJson(o: JSONObject) = OwnedFileRecord(
        SignedFileDescriptor.fromJson(o.getJSONObject("descriptor")), o.getString("vault_name"), o.getString("content_key"),
        o.optString("folder_path"), o.optString("display_name").ifBlank { o.getJSONObject("descriptor").optString("file_name", "Protected file") }) }
}

data class SharedFileRecord(
    val shareId: String, val descriptor: SignedFileDescriptor, val senderContactId: String,
    val recipientContactId: String, val vaultName: String, val contentKey: String,
    val encryptedSha256: String, val ndaId: String?, val receivedAt: Instant
) {
    fun toJson() = JSONObject().apply {
        put("share_id", shareId); put("descriptor", descriptor.toJson()); put("sender_contact_id", senderContactId)
        put("recipient_contact_id", recipientContactId); put("vault_name", vaultName); put("content_key", contentKey)
        put("encrypted_sha256", encryptedSha256); putOpt("nda_id", ndaId); put("received_at", receivedAt.toString())
    }
    companion object { fun fromJson(o: JSONObject) = SharedFileRecord(
        o.getString("share_id"), SignedFileDescriptor.fromJson(o.getJSONObject("descriptor")),
        o.getString("sender_contact_id"), o.getString("recipient_contact_id"), o.getString("vault_name"),
        o.getString("content_key"), o.getString("encrypted_sha256"), o.optStringOrNull("nda_id"), o.instant("received_at")) }
}

data class ContactCard(
    val format: String = "digitalspace-contact-v1", val contactId: String, val identityId: String,
    val profileId: String, val handle: String, val exchangePublicKey: String,
    val signingCertificate: String, val signingIssuerCertificate: String,
    val issuedAt: Instant, val expiresAt: Instant, var signature: String,
    val pqKemAlgorithm: String? = null, val pqKemPublicKey: String? = null,
    val pqSignatureAlgorithm: String? = null, val pqSigningPublicKey: String? = null,
    var pqSignature: String? = null
) {
    fun toJson() = JSONObject().apply {
        put("format", format); put("contact_id", contactId); put("identity_id", identityId); put("profile_id", profileId)
        put("handle", handle); put("exchange_public_key", exchangePublicKey); put("signing_certificate", signingCertificate)
        put("signing_issuer_certificate", signingIssuerCertificate); put("issued_at", issuedAt.toString())
        put("expires_at", expiresAt.toString()); put("signature", signature)
        putOpt("pq_kem_algorithm", pqKemAlgorithm); putOpt("pq_kem_public_key", pqKemPublicKey)
        putOpt("pq_signature_algorithm", pqSignatureAlgorithm); putOpt("pq_signing_public_key", pqSigningPublicKey)
        putOpt("pq_signature", pqSignature)
    }
    companion object { fun fromJson(o: JSONObject) = ContactCard(
        o.optString("format", "digitalspace-contact-v1"), o.getString("contact_id"), o.getString("identity_id"),
        o.getString("profile_id"), o.getString("handle"), o.getString("exchange_public_key"),
        o.getString("signing_certificate"), o.getString("signing_issuer_certificate"),
        o.instant("issued_at"), o.instant("expires_at"), o.getString("signature"),
        o.optStringOrNull("pq_kem_algorithm"), o.optStringOrNull("pq_kem_public_key"),
        o.optStringOrNull("pq_signature_algorithm"), o.optStringOrNull("pq_signing_public_key"),
        o.optStringOrNull("pq_signature")) }
}

data class ContactRecord(val card: ContactCard, val displayName: String, val addedAt: Instant) {
    fun toJson() = JSONObject().put("card", card.toJson()).put("display_name", displayName).put("added_at", addedAt.toString())
    companion object { fun fromJson(o: JSONObject) = ContactRecord(ContactCard.fromJson(o.getJSONObject("card")), o.getString("display_name"), o.instant("added_at")) }
}

enum class PostExpiryAccessPolicy { RetainAccess, RevokeManagedAccess }
enum class AgreementState { Pending, Accepted, Declined }

data class NdaParticipant(
    val contactId: String, val profileId: String, val handle: String, var state: AgreementState,
    var respondedAt: Instant? = null, var acceptanceCertificate: String? = null,
    var acceptanceSignature: String? = null
) {
    fun toJson() = JSONObject().apply {
        put("contact_id", contactId); put("profile_id", profileId); put("handle", handle); put("state", state.name)
        putOpt("responded_at", respondedAt?.toString()); putOpt("acceptance_certificate", acceptanceCertificate)
        putOpt("acceptance_signature", acceptanceSignature)
    }
    companion object { fun fromJson(o: JSONObject) = NdaParticipant(
        o.getString("contact_id"), o.getString("profile_id"), o.getString("handle"),
        runCatching { AgreementState.valueOf(o.getString("state")) }.getOrDefault(AgreementState.Pending),
        o.optStringOrNull("responded_at")?.let(Instant::parse), o.optStringOrNull("acceptance_certificate"),
        o.optStringOrNull("acceptance_signature")) }
}

data class NdaAgreement(
    val format: String = "digitalspace-nda-v1", val ndaId: String, val title: String,
    val purpose: String, val terms: String, val termsSha256: String,
    val issuerIdentityId: String, val issuerProfileId: String, val issuerHandle: String,
    val createdAt: Instant, val validFrom: Instant, val validUntil: Instant,
    val postExpiryPolicy: PostExpiryAccessPolicy, val fileIds: List<String>,
    val participants: MutableList<NdaParticipant>, val issuerCertificate: String,
    var issuerSignature: String
) {
    fun toJson() = JSONObject().apply {
        put("format", format); put("nda_id", ndaId); put("title", title); put("purpose", purpose); put("terms", terms)
        put("terms_sha256", termsSha256); put("issuer_identity_id", issuerIdentityId)
        put("issuer_profile_id", issuerProfileId); put("issuer_handle", issuerHandle); put("created_at", createdAt.toString())
        put("valid_from", validFrom.toString()); put("valid_until", validUntil.toString())
        put("post_expiry_policy", postExpiryPolicy.name); put("file_ids", JSONArray(fileIds))
        put("participants", JSONArray(participants.map { it.toJson() })); put("issuer_certificate", issuerCertificate)
        put("issuer_signature", issuerSignature)
    }
    companion object { fun fromJson(o: JSONObject) = NdaAgreement(
        o.optString("format", "digitalspace-nda-v1"), o.getString("nda_id"), o.getString("title"),
        o.getString("purpose"), o.getString("terms"), o.getString("terms_sha256"),
        o.getString("issuer_identity_id"), o.getString("issuer_profile_id"), o.getString("issuer_handle"),
        o.instant("created_at"), o.instant("valid_from"), o.instant("valid_until"),
        runCatching { PostExpiryAccessPolicy.valueOf(o.getString("post_expiry_policy")) }.getOrDefault(PostExpiryAccessPolicy.RevokeManagedAccess),
        o.getJSONArray("file_ids").strings(), o.getJSONArray("participants").objects().map(NdaParticipant::fromJson).toMutableList(),
        o.getString("issuer_certificate"), o.getString("issuer_signature")) }
}

data class InformationManifest(
    val schemaVersion: Int = 2,
    val ownedFiles: MutableList<OwnedFileRecord> = mutableListOf(),
    val sharedFiles: MutableList<SharedFileRecord> = mutableListOf(),
    val contacts: MutableList<ContactRecord> = mutableListOf(),
    val agreements: MutableList<NdaAgreement> = mutableListOf(),
    val folders: MutableList<String> = mutableListOf()
) {
    fun toJson() = JSONObject().apply {
        put("schema_version", schemaVersion); put("owned_files", JSONArray(ownedFiles.map { it.toJson() }))
        put("shared_files", JSONArray(sharedFiles.map { it.toJson() })); put("contacts", JSONArray(contacts.map { it.toJson() }))
        put("agreements", JSONArray(agreements.map { it.toJson() })); put("folders", JSONArray(folders.sorted()))
    }
    companion object { fun fromJson(o: JSONObject) = InformationManifest(
        o.optInt("schema_version", 1), o.optJSONArray("owned_files").objects().map(OwnedFileRecord::fromJson).toMutableList(),
        o.optJSONArray("shared_files").objects().map(SharedFileRecord::fromJson).toMutableList(),
        o.optJSONArray("contacts").objects().map(ContactRecord::fromJson).toMutableList(),
        o.optJSONArray("agreements").objects().map(NdaAgreement::fromJson).toMutableList(),
        o.optJSONArray("folders").strings().map(::normalizeVaultFolder).distinct().filter(String::isNotBlank).toMutableList()) }
}

fun normalizeVaultFolder(value: String): String = value.split('/').map { it.trim() }.filter(String::isNotBlank)
    .joinToString("/") { it.replace(Regex("[\\:*?\"<>|\u0000-\u001f]"), "_").take(80) }.take(320)

internal fun JSONObject.optStringOrNull(name: String): String? = if (isNull(name)) null else optString(name).takeIf { it.isNotBlank() }
internal fun JSONObject.stringAny(vararg names: String): String = names.firstNotNullOfOrNull { optStringOrNull(it) } ?: ""
internal fun JSONObject.instant(name: String): Instant = Instant.parse(getString(name))
internal fun JSONArray?.strings(): List<String> = if (this == null) emptyList() else (0 until length()).map { getString(it) }
internal fun JSONArray?.objects(): List<JSONObject> = if (this == null) emptyList() else (0 until length()).map { getJSONObject(it) }
