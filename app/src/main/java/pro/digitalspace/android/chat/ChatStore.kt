/* SPDX-License-Identifier: MIT */
package pro.digitalspace.android.chat

import org.json.JSONArray
import org.json.JSONObject
import pro.digitalspace.android.security.VaultSession
import java.time.Instant

class ChatStore(private val vault: VaultSession) {
    companion object { private const val ITEM = "chat-store-v1"; private const val FORMAT = "authentiverse-chat-store-v1" }
    private data class Document(val messages: MutableList<ChatStoredMessage>, val seen: MutableList<String>)

    @Synchronized fun messages(contactId: String? = null): List<ChatStoredMessage> {
        val d = load(); prune(d); save(d)
        return d.messages.filter { contactId == null || it.contactId == contactId }.sortedBy { it.createdAt }
    }
    @Synchronized fun hasSeen(messageId: String): Boolean = load().seen.contains(messageId)
    @Synchronized fun add(value: ChatStoredMessage) {
        val d = load(); if (value.messageId in d.seen) return
        d.messages.removeAll { it.messageId == value.messageId }; d.messages.add(value); d.seen.add(value.messageId)
        while (d.messages.size > 500) d.messages.removeAt(0); while (d.seen.size > 2048) d.seen.removeAt(0)
        prune(d); save(d)
    }
    @Synchronized fun consumeViewOnce(messageId: String): ChatStoredMessage? {
        val d = load(); val m = d.messages.firstOrNull { it.messageId == messageId } ?: return null
        if (m.policy == ChatMessagePolicy.ViewOnce) { m.viewConsumed = true; m.text = null; m.callSecret = null; save(d) }
        return m
    }
    @Synchronized fun consumeCall(messageId: String): CallSession? {
        val d = load(); val m = d.messages.firstOrNull { it.messageId == messageId } ?: return null
        if (m.kind != "call_invite" || m.callConsumed || m.callRoomId.isNullOrBlank() || m.callSecret.isNullOrBlank()) return null
        if (m.expiresAt?.isBefore(Instant.now()) == true) return null
        m.callConsumed = true
        val result = CallSession(m.contactId, m.contactDisplayName, m.callRoomId!!, m.callSecret!!, m.expiresAt ?: Instant.now().plusSeconds(120))
        m.callSecret = null; save(d); return result
    }
    @Synchronized fun clearContact(contactId: String) { val d = load(); d.messages.removeAll { it.contactId == contactId }; save(d) }

    private fun prune(d: Document) {
        val now = Instant.now(); d.messages.removeAll { it.expiresAt?.isBefore(now) == true }
    }
    private fun load(): Document {
        val clear = vault.get(ITEM) ?: return Document(mutableListOf(), mutableListOf())
        return try {
            val root = JSONObject(clear.decodeToString()); require(root.optString("format") == FORMAT)
            val messages = root.optJSONArray("messages") ?: JSONArray(); val seen = root.optJSONArray("seen") ?: JSONArray()
            Document((0 until messages.length()).map { ChatStoredMessage.fromJson(messages.getJSONObject(it)) }.toMutableList(),
                (0 until seen.length()).map { seen.getString(it) }.toMutableList())
        } finally { clear.fill(0) }
    }
    private fun save(d: Document) {
        val clear = JSONObject().put("format", FORMAT).put("messages", JSONArray(d.messages.map(ChatStoredMessage::toJson)))
            .put("seen", JSONArray(d.seen)).toString().encodeToByteArray()
        try { vault.put(ITEM, clear) } finally { clear.fill(0) }
    }
}
