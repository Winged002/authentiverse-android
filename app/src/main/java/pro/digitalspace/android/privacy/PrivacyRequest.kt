/* SPDX-License-Identifier: MIT */
package pro.digitalspace.android.privacy

import android.net.Uri
import android.util.Base64
import org.json.JSONObject
import java.net.URI
import java.time.Instant
import java.time.temporal.ChronoUnit

data class PrivacyRequest(
    val requestId: String,
    val verifierId: String,
    val verifierName: String,
    val purpose: String,
    val predicateId: String,
    val nonce: String,
    val issuedAt: Instant,
    val expiresAt: Instant,
    val callbackUri: String
)

object PrivacyRequestParser {
    private const val MAX_REQUEST_CHARS = 24 * 1024

    fun parse(uri: Uri, wallet: PrivateAttributeWallet, allowedVerifierOrigins: Set<String>): PrivacyRequest {
        require(((uri.scheme.equals("digitalspace", true) || uri.scheme.equals("authentiverse", true)) && uri.host.equals("present", true)) ||
            (uri.scheme.equals("moi", true) && uri.host.equals("request", true))) {
            "The Authentiverse privacy request URI is invalid."
        }
        val encoded = uri.getQueryParameter("request")
        require(!encoded.isNullOrBlank() && encoded.length <= MAX_REQUEST_CHARS && encoded.all { it.isLetterOrDigit() || it == '-' || it == '_' }) {
            "The Authentiverse privacy request is missing or malformed."
        }
        val root = runCatching { JSONObject(Base64.decode(encoded, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING).decodeToString()) }
            .getOrElse { throw IllegalArgumentException("The privacy request encoding is invalid.") }
        val request = PrivacyRequest(
            root.getString("request_id"), root.getString("verifier_id"), root.getString("verifier_name"),
            root.getString("purpose"), root.getString("predicate_id"), root.getString("nonce"),
            Instant.parse(root.getString("issued_at")), Instant.parse(root.getString("expires_at")), root.getString("callback_uri")
        )
        validate(request, wallet, allowedVerifierOrigins)
        return request
    }

    fun validate(request: PrivacyRequest, wallet: PrivateAttributeWallet, allowedVerifierOrigins: Set<String>) {
        wallet.requirePolicy(request.predicateId)
        requireText(request.requestId, 8, 128, "request identifier")
        requireText(request.verifierId, 3, 256, "verifier identifier")
        requireText(request.verifierName, 2, 80, "application name")
        requireText(request.purpose, 5, 240, "request purpose")
        val nonce = runCatching { Base64.decode(request.nonce, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING) }
            .getOrElse { throw IllegalArgumentException("The privacy request nonce is invalid.") }
        require(nonce.size in 16..64) { "The privacy request nonce has an invalid length." }
        val now = Instant.now()
        require(!request.issuedAt.isBefore(now.minus(2, ChronoUnit.MINUTES)) && !request.issuedAt.isAfter(now.plus(1, ChronoUnit.MINUTES)) &&
            request.expiresAt.isAfter(now) && !request.expiresAt.isAfter(request.issuedAt.plus(5, ChronoUnit.MINUTES))) {
            "The privacy request is expired or has an unsafe lifetime."
        }
        val callback = URI(request.callbackUri)
        require(callback.scheme.equals("https", true) && callback.userInfo == null && callback.fragment == null &&
            callback.host?.endsWith(".home.arpa", true) == true) { "The privacy response must return to an Indoor HTTPS application." }
        val callbackOrigin = "${callback.scheme.lowercase()}://${callback.host.lowercase()}" +
            if (callback.port == -1 || callback.port == 443) "" else ":${callback.port}"
        require(request.verifierId.trimEnd('/').equals(callbackOrigin, true)) { "The privacy callback does not belong to the requesting application." }
        require(allowedVerifierOrigins.any { it.trimEnd('/').equals(callbackOrigin, true) }) {
            "This Indoor application is not authorized to request private proofs."
        }
    }

    private fun requireText(value: String, minimum: Int, maximum: Int, label: String) {
        require(value.length in minimum..maximum && value.none(Char::isISOControl)) { "The privacy $label is invalid." }
    }
}
