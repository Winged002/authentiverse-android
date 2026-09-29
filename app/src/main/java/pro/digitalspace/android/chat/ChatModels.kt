/* SPDX-License-Identifier: MIT */
package pro.digitalspace.android.chat

import org.json.JSONObject
import pro.digitalspace.android.model.ContactCard
import java.time.Instant

enum class ChatMessagePolicy { Keep, ViewOnce, ExpireAfter }

data class ChatContent(
    val kind: String = "text",
    val text: String? = null,
    val callRoomId: String? = null,
    val callSecret: String? = null
) {
    fun toJson() = JSONObject().put("kind", kind).putOpt("text", text)
        .putOpt("call_room_id", callRoomId).putOpt("call_secret", callSecret)
    companion object {
        fun fromJson(o: JSONObject) = ChatContent(o.optString("kind", "text"),
            o.optString("text").takeIf(String::isNotBlank), o.optString("call_room_id").takeIf(String::isNotBlank),
            o.optString("call_secret").takeIf(String::isNotBlank))
    }
}

data class ChatEnvelope(
    val format: String = "digitalspace-chat-v1",
    val messageId: String,
    val sender: ContactCard,
    val recipientContactId: String,
    val createdAt: Instant,
    val expiresAt: Instant?,
    val policy: ChatMessagePolicy,
    var ephemeralPublicKey: String = "",
    var pqKemCiphertext: String = "",
    var nonce: String = "",
    var ciphertext: String = "",
    var tag: String = "",
    var classicalSignature: String = "",
    var pqSignature: String = ""
) {
    fun toJson() = JSONObject().put("format", format).put("message_id", messageId).put("sender", sender.toJson())
        .put("recipient_contact_id", recipientContactId).put("created_at", createdAt.toString())
        .putOpt("expires_at", expiresAt?.toString()).put("policy", policy.name)
        .put("ephemeral_public_key", ephemeralPublicKey).put("pq_kem_ciphertext", pqKemCiphertext)
        .put("nonce", nonce).put("ciphertext", ciphertext).put("tag", tag)
        .put("classical_signature", classicalSignature).put("pq_signature", pqSignature)

    companion object {
        fun fromJson(o: JSONObject) = ChatEnvelope(
            o.optString("format", "digitalspace-chat-v1"), o.getString("message_id"), ContactCard.fromJson(o.getJSONObject("sender")),
            o.getString("recipient_contact_id"), Instant.parse(o.getString("created_at")),
            o.optString("expires_at").takeIf(String::isNotBlank)?.let(Instant::parse),
            runCatching { ChatMessagePolicy.valueOf(o.getString("policy")) }.getOrElse { throw IllegalArgumentException("Unsupported chat policy.") },
            o.getString("ephemeral_public_key"), o.getString("pq_kem_ciphertext"), o.getString("nonce"),
            o.getString("ciphertext"), o.getString("tag"), o.getString("classical_signature"), o.getString("pq_signature")
        )
    }
}

data class ChatStoredMessage(
    val messageId: String,
    val contactId: String,
    val contactDisplayName: String,
    val outgoing: Boolean,
    val kind: String,
    var text: String?,
    val policy: ChatMessagePolicy,
    val createdAt: Instant,
    val expiresAt: Instant?,
    var viewConsumed: Boolean = false,
    var callRoomId: String? = null,
    var callSecret: String? = null,
    var callConsumed: Boolean = false
) {
    fun toJson() = JSONObject().put("message_id", messageId).put("contact_id", contactId).put("contact_display_name", contactDisplayName)
        .put("outgoing", outgoing).put("kind", kind).putOpt("text", text).put("policy", policy.name)
        .put("created_at", createdAt.toString()).putOpt("expires_at", expiresAt?.toString()).put("view_consumed", viewConsumed)
        .putOpt("call_room_id", callRoomId).putOpt("call_secret", callSecret).put("call_consumed", callConsumed)
    companion object {
        fun fromJson(o: JSONObject) = ChatStoredMessage(o.getString("message_id"), o.getString("contact_id"),
            o.optString("contact_display_name"), o.optBoolean("outgoing"), o.optString("kind", "text"),
            o.optString("text").takeIf(String::isNotBlank), ChatMessagePolicy.valueOf(o.optString("policy", "Keep")),
            Instant.parse(o.getString("created_at")), o.optString("expires_at").takeIf(String::isNotBlank)?.let(Instant::parse),
            o.optBoolean("view_consumed"), o.optString("call_room_id").takeIf(String::isNotBlank),
            o.optString("call_secret").takeIf(String::isNotBlank), o.optBoolean("call_consumed"))
    }
}

data class CallSession(val contactId: String, val displayName: String, val roomId: String, val secret: String, val expiresAt: Instant)
