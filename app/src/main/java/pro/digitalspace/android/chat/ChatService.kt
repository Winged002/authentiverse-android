/* SPDX-License-Identifier: MIT */
package pro.digitalspace.android.chat

import pro.digitalspace.android.data.ExchangeService
import pro.digitalspace.android.data.InformationStore
import pro.digitalspace.android.model.PersistentState
import pro.digitalspace.android.network.ControlPlaneClient
import pro.digitalspace.android.security.DigitalSpaceCrypto
import java.time.Instant
import java.time.temporal.ChronoUnit

class ChatService(
    private val information: InformationStore,
    private val exchange: ExchangeService,
    private val crypto: HybridChatCrypto,
    private val store: ChatStore,
    private val client: ControlPlaneClient
) {
    fun messages(contactId: String? = null) = store.messages(contactId)

    suspend fun sendText(contactId: String, text: String, policy: ChatMessagePolicy, expiresAt: Instant?, state: PersistentState): ChatStoredMessage {
        val clean = text.trim(); require(clean.isNotBlank() && clean.encodeToByteArray().size <= 60 * 1024) { "Enter a message up to 60 KiB." }
        return send(contactId, ChatContent(text = clean), policy, expiresAt, state)
    }

    suspend fun inviteCall(contactId: String, state: PersistentState): ChatStoredMessage {
        val room = "call_" + DigitalSpaceCrypto.hex(DigitalSpaceCrypto.random(24)).lowercase()
        val secret = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(DigitalSpaceCrypto.random(32))
        return send(contactId, ChatContent("call_invite", callRoomId = room, callSecret = secret),
            ChatMessagePolicy.ExpireAfter, Instant.now().plus(2, ChronoUnit.MINUTES), state)
    }

    suspend fun declineCall(contactId: String, roomId: String, state: PersistentState) = send(contactId,
        ChatContent("call_decline", callRoomId = roomId), ChatMessagePolicy.ExpireAfter, Instant.now().plus(2, ChronoUnit.MINUTES), state)

    fun ingest(bytes: ByteArray, state: PersistentState): ChatStoredMessage? {
        val envelope = ChatEnvelope.fromJson(org.json.JSONObject(bytes.decodeToString()))
        if (store.hasSeen(envelope.messageId)) return null
        val own = exchange.ownContact(state)
        val content = crypto.decrypt(envelope, own)
        val contact = information.load().contacts.firstOrNull { it.card.contactId == envelope.sender.contactId }
            ?: throw IllegalStateException("Import the sender's verified Authentiverse contact card before accepting private messages.")
        require(contact.card.signingCertificate == envelope.sender.signingCertificate) { "The sender identity does not match the saved contact." }
        val stored = ChatStoredMessage(envelope.messageId, contact.card.contactId, contact.displayName.ifBlank { "@${contact.card.handle}" }, false,
            content.kind, content.text, envelope.policy, envelope.createdAt, envelope.expiresAt, callRoomId = content.callRoomId, callSecret = content.callSecret)
        store.add(stored); return stored
    }

    fun consumeViewOnce(messageId: String) = store.consumeViewOnce(messageId)
    fun consumeCall(messageId: String) = store.consumeCall(messageId)

    private suspend fun send(contactId: String, content: ChatContent, policy: ChatMessagePolicy, expiresAt: Instant?, state: PersistentState): ChatStoredMessage {
        val contact = information.load().contacts.firstOrNull { it.card.contactId == contactId } ?: throw IllegalArgumentException("Choose a verified contact.")
        val own = exchange.ownContact(state)
        val envelope = crypto.encrypt(own, contact.card, content, policy, expiresAt)
        client.uploadInbox(contactId, "chat", envelope.toJson().toString().encodeToByteArray())
        val stored = ChatStoredMessage(envelope.messageId, contactId, contact.displayName.ifBlank { "@${contact.card.handle}" }, true,
            content.kind, content.text, policy, envelope.createdAt, envelope.expiresAt, callRoomId = content.callRoomId, callSecret = content.callSecret)
        store.add(stored); return stored
    }
}
