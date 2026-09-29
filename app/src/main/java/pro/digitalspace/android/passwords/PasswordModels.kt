/* SPDX-License-Identifier: MIT */
package pro.digitalspace.android.passwords

import org.json.JSONArray
import org.json.JSONObject
import pro.digitalspace.android.model.ContactCard
import pro.digitalspace.android.security.DigitalSpaceCrypto
import java.time.Instant

enum class PasswordCredentialScope { Personal, Shared, Organization }
enum class PasswordAuditAction { Created, Updated, Revealed, Copied, Autofilled, AutofillDenied, Shared, Imported, Revoked, Deleted, BackupExported, BackupImported, TeamCreated, TeamUpdated }

data class PasswordCredentialAccessPolicy(
    var canReveal: Boolean = true, var canCopy: Boolean = true, var canAutofill: Boolean = true,
    var expiresAt: Instant? = null, var revokedAt: Instant? = null, var issuerContactId: String? = null, var shareId: String? = null
) {
    fun usable(now: Instant = Instant.now()) = revokedAt == null && (expiresAt == null || expiresAt!!.isAfter(now))
    fun toJson() = JSONObject().put("can_reveal", canReveal).put("can_copy", canCopy).put("can_autofill", canAutofill)
        .putOpt("expires_at", expiresAt?.toString()).putOpt("revoked_at", revokedAt?.toString())
        .putOpt("issuer_contact_id", issuerContactId).putOpt("share_id", shareId)
    companion object { fun fromJson(o: JSONObject?) = if (o == null) PasswordCredentialAccessPolicy() else PasswordCredentialAccessPolicy(
        o.optBoolean("can_reveal", true), o.optBoolean("can_copy", true), o.optBoolean("can_autofill", true),
        o.optString("expires_at").takeIf(String::isNotBlank)?.let(Instant::parse), o.optString("revoked_at").takeIf(String::isNotBlank)?.let(Instant::parse),
        o.optString("issuer_contact_id").takeIf(String::isNotBlank), o.optString("share_id").takeIf(String::isNotBlank)) }
}

data class PasswordIssuedShare(val shareId: String, val recipientContactId: String, val issuedAt: Instant,
    val expiresAt: Instant? = null, var revokedAt: Instant? = null) {
    fun toJson() = JSONObject().put("share_id", shareId).put("recipient_contact_id", recipientContactId).put("issued_at", issuedAt.toString())
        .putOpt("expires_at", expiresAt?.toString()).putOpt("revoked_at", revokedAt?.toString())
    companion object { fun fromJson(o: JSONObject) = PasswordIssuedShare(o.getString("share_id"), o.getString("recipient_contact_id"),
        Instant.parse(o.getString("issued_at")), o.optString("expires_at").takeIf(String::isNotBlank)?.let(Instant::parse),
        o.optString("revoked_at").takeIf(String::isNotBlank)?.let(Instant::parse)) }
}

data class PasswordCredentialRecord(
    val credentialId: String, var title: String, var username: String, var passwordUtf8: ByteArray,
    var url: String = "", var allowedOrigins: MutableList<String> = mutableListOf(), var notes: String = "",
    var totpSecret: ByteArray = ByteArray(0), var scope: PasswordCredentialScope = PasswordCredentialScope.Personal,
    var teamId: String? = null, var teamName: String? = null, var ownerContactId: String? = null,
    var issuerCard: ContactCard? = null, var access: PasswordCredentialAccessPolicy = PasswordCredentialAccessPolicy(),
    var issuedShares: MutableList<PasswordIssuedShare> = mutableListOf(), var createdAt: Instant = Instant.now(),
    var updatedAt: Instant = Instant.now(), var passwordChangedAt: Instant = Instant.now()
) {
    fun toJson() = JSONObject().put("credential_id", credentialId).put("title", title).put("username", username)
        .put("password_utf8", DigitalSpaceCrypto.b64(passwordUtf8)).put("url", url).put("allowed_origins", JSONArray(allowedOrigins))
        .put("notes", notes).put("totp_secret", DigitalSpaceCrypto.b64(totpSecret)).put("scope", scope.name)
        .putOpt("team_id", teamId).putOpt("team_name", teamName).putOpt("owner_contact_id", ownerContactId)
        .putOpt("issuer_card", issuerCard?.toJson()).put("access", access.toJson()).put("issued_shares", JSONArray(issuedShares.map(PasswordIssuedShare::toJson)))
        .put("created_at", createdAt.toString()).put("updated_at", updatedAt.toString()).put("password_changed_at", passwordChangedAt.toString())
    fun destroy() { passwordUtf8.fill(0); totpSecret.fill(0) }
    companion object { fun fromJson(o: JSONObject): PasswordCredentialRecord {
        val origins = o.optJSONArray("allowed_origins") ?: JSONArray(); val shares = o.optJSONArray("issued_shares") ?: JSONArray()
        return PasswordCredentialRecord(o.getString("credential_id"), o.optString("title"), o.optString("username"),
            DigitalSpaceCrypto.unb64(o.optString("password_utf8")), o.optString("url"),
            (0 until origins.length()).map { origins.getString(it) }.toMutableList(), o.optString("notes"),
            o.optString("totp_secret").takeIf(String::isNotBlank)?.let(DigitalSpaceCrypto::unb64) ?: ByteArray(0),
            runCatching { PasswordCredentialScope.valueOf(o.optString("scope", "Personal")) }.getOrDefault(PasswordCredentialScope.Personal),
            o.optString("team_id").takeIf(String::isNotBlank), o.optString("team_name").takeIf(String::isNotBlank),
            o.optString("owner_contact_id").takeIf(String::isNotBlank), o.optJSONObject("issuer_card")?.let(ContactCard::fromJson),
            PasswordCredentialAccessPolicy.fromJson(o.optJSONObject("access")),
            (0 until shares.length()).map { PasswordIssuedShare.fromJson(shares.getJSONObject(it)) }.toMutableList(),
            o.optString("created_at").takeIf(String::isNotBlank)?.let(Instant::parse) ?: Instant.now(),
            o.optString("updated_at").takeIf(String::isNotBlank)?.let(Instant::parse) ?: Instant.now(),
            o.optString("password_changed_at").takeIf(String::isNotBlank)?.let(Instant::parse) ?: Instant.now())
    }}
}

data class PasswordCredentialSummary(val credentialId: String, val title: String, val username: String, val url: String,
    val allowedOrigins: List<String>, val notes: String, val scope: PasswordCredentialScope, val teamId: String?, val teamName: String?,
    val access: PasswordCredentialAccessPolicy, val issuedShares: List<PasswordIssuedShare>, val passwordChangedAt: Instant, val hasTotp: Boolean, val isWeak: Boolean)

data class PasswordVaultTeam(val teamId: String, var name: String, var memberContactIds: MutableList<String>, val createdAt: Instant, var updatedAt: Instant) {
    fun toJson() = JSONObject().put("team_id", teamId).put("name", name).put("member_contact_ids", JSONArray(memberContactIds))
        .put("created_at", createdAt.toString()).put("updated_at", updatedAt.toString())
    companion object { fun fromJson(o: JSONObject): PasswordVaultTeam { val a=o.optJSONArray("member_contact_ids")?:JSONArray(); return PasswordVaultTeam(
        o.getString("team_id"),o.getString("name"),(0 until a.length()).map{a.getString(it)}.toMutableList(),Instant.parse(o.getString("created_at")),Instant.parse(o.getString("updated_at"))) } }
}

data class PasswordAuditEvent(val eventId: String, val credentialId: String?, val action: PasswordAuditAction, val origin: String?, val detail: String?, val at: Instant) {
    fun toJson() = JSONObject().put("event_id", eventId).putOpt("credential_id", credentialId).put("action", action.name)
        .putOpt("origin", origin).putOpt("detail", detail).put("at", at.toString())
    companion object { fun fromJson(o: JSONObject)=PasswordAuditEvent(o.getString("event_id"),o.optString("credential_id").takeIf(String::isNotBlank),
        PasswordAuditAction.valueOf(o.getString("action")),o.optString("origin").takeIf(String::isNotBlank),o.optString("detail").takeIf(String::isNotBlank),Instant.parse(o.getString("at"))) }
}

data class PasswordHealthSummary(val total: Int, val weak: Int, val reused: Int, val stale: Int, val withoutTotp: Int, val reusedCredentialIds: List<String>)
