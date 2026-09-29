/* SPDX-License-Identifier: MIT */
package pro.digitalspace.android.network

import android.net.Uri
import org.json.JSONArray
import org.json.JSONObject
import pro.digitalspace.android.model.Area
import pro.digitalspace.android.model.TunnelInfo
import pro.digitalspace.android.security.DigitalSpaceCrypto
import pro.digitalspace.android.security.IdentityKeyStore
import pro.digitalspace.android.security.SecureStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URL
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Principal
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.KeyManager
import javax.net.ssl.SSLContext
import javax.net.ssl.X509KeyManager
import javax.net.ssl.X509TrustManager

data class EnrollmentStart(val id: String, val emailCode: String?, val phoneCode: String?)
data class EnrollmentVerified(val identityId: String, val token: String)
data class IssuedCertificate(val certificateDer: ByteArray, val issuerDer: ByteArray)

class ControlPlaneClient(
    private val secureStore: SecureStore,
    private val keys: IdentityKeyStore
) {
    companion object {
        const val PUBLIC_BASE = "https://internal.syntal.pro/"
        const val INDOOR_BASE = "https://api.digitalspace.home.arpa/"
        const val PINNED_CA_SHA256 = "AFED586A711469936E15C0F13E371089D6DF6331C7FF3BDA348E05C998704E25"
    }

    var indoor = false
    var deviceCertificate: ByteArray? = null
    var deviceIssuerCertificate: ByteArray? = null
    var profileCertificate: ByteArray? = null
    var profileIssuerCertificate: ByteArray? = null
    var profileKeyAlias: String? = null
    var indoorServerCaCertificate: ByteArray? = null

    fun setToken(token: String) = secureStore.put("control-plane-session", token.encodeToByteArray())
    fun token(): String? = secureStore.get("control-plane-session")?.decodeToString()

    suspend fun startEnrollment(invitation: String, name: String, email: String, phone: String): EnrollmentStart {
        val o = post("v1/enrollment/start", JSONObject().put("invitation_code", invitation).put("full_name", name)
            .put("email", email).put("phone", phone), "enrollment")
        return EnrollmentStart(o.getString("enrollment_id"), o.optStringOrNull("development_email_code"), o.optStringOrNull("development_phone_code"))
    }

    suspend fun verifyEnrollment(id: String, emailCode: String, phoneCode: String): EnrollmentVerified {
        val o = post("v1/enrollment/verify", JSONObject().put("enrollment_id", id).put("email_code", emailCode)
            .put("phone_code", phoneCode), "enrollment")
        val result = EnrollmentVerified(o.getString("identity_id"), o.getString("session_token"))
        setToken(result.token); return result
    }

    suspend fun enrollIdentity(displayName: String): String {
        val o = post("v1/identity/enroll", JSONObject().put("display_name", displayName), "identity")
        return o.optString("identity_id").ifBlank { o.getString("id") }
    }

    suspend fun createProfile(identityId: String, handle: String, displayName: String): Pair<String, String> {
        val o = post("v1/profiles", JSONObject().put("identity_id", identityId).put("handle", handle)
            .put("display_name", displayName), "profile")
        return (o.optString("profile_id").ifBlank { o.getString("id") }) to o.optString("handle", handle)
    }

    suspend fun enrollDevice(identityId: String, profileId: String, name: String, publicKey: String): String {
        val o = post("v1/devices/enroll", JSONObject().put("identity_id", identityId).put("profile_id", profileId)
            .put("name", name).put("platform", "android").put("wg_public_key", publicKey), "device")
        return o.optString("device_id").ifBlank { o.getString("id") }
    }

    suspend fun serverCa(): Pair<ByteArray, String> {
        val o = get("v1/pki/server-ca", "pki")
        return pemCertificate(o.getString("certificate_pem")) to o.getString("sha256")
    }
    suspend fun issueFoundational(csr: String) = issue("v1/pki/foundational/certificate", JSONObject().put("csr_pem", csr))
    suspend fun issueDevice(deviceId: String, csr: String) = issue("v1/devices/${escape(deviceId)}/certificate", JSONObject().put("csr_pem", csr))
    suspend fun issueProfile(areaId: String, deviceId: String, profileId: String, csr: String) =
        issue("v1/areas/${escape(areaId)}/profile-certificate", JSONObject().put("csr_pem", csr)
            .put("device_id", deviceId).put("profile_id", profileId))

    suspend fun areas(): List<Area> = list("v1/areas", "areas").map(Area::fromJson)
    suspend fun join(areaId: String, deviceId: String, profileId: String) = post("v1/areas/${escape(areaId)}/join",
        JSONObject().put("device_id", deviceId).put("profile_id", profileId), "join", "membership")
    suspend fun tunnel(areaId: String, deviceId: String): TunnelInfo = TunnelInfo.fromJson(
        get("v1/areas/${escape(areaId)}/tunnel?device_id=${escape(deviceId)}", "tunnel"))

    suspend fun issuePredicateCredential(profileId: String, predicateId: String, evidence: Map<String, String>): JSONObject =
        post("v1/privacy/predicate-credentials", JSONObject().put("profile_id", profileId).put("predicate_id", predicateId)
            .put("private_evidence", JSONObject(evidence)), "credential")

    suspend fun registerInbox(body: JSONObject) = post("v1/indoor/inbox/register", body, "registration")
    suspend fun inboxItems(contactId: String): List<JSONObject> = list("v1/indoor/inbox/items?contact_id=${escape(contactId)}", "items")
    suspend fun acknowledge(itemId: String) = post("v1/indoor/inbox/items/${escape(itemId)}/acknowledge", JSONObject(), "acknowledgement")

    suspend fun downloadInboxItem(itemId: String): ByteArray = raw("GET", "v1/indoor/inbox/items/${escape(itemId)}/content", null)
    suspend fun uploadInbox(recipient: String, kind: String, content: ByteArray): JSONObject {
        val boundary = "DS-${System.currentTimeMillis()}"
        val prefix = "--$boundary\r\nContent-Disposition: form-data; name=\"recipient_contact_id\"\r\n\r\n$recipient\r\n" +
            "--$boundary\r\nContent-Disposition: form-data; name=\"package_kind\"\r\n\r\n$kind\r\n" +
            "--$boundary\r\nContent-Disposition: form-data; name=\"package\"; filename=\"package.bin\"\r\n" +
            "Content-Type: application/octet-stream\r\n\r\n"
        val suffix = "\r\n--$boundary--\r\n"
        val response = raw("POST", "v1/indoor/inbox/items", prefix.encodeToByteArray() + content + suffix.encodeToByteArray(),
            "multipart/form-data; boundary=$boundary")
        return unwrap(JSONObject(response.decodeToString()), arrayOf("item"))
    }

    private suspend fun issue(path: String, body: JSONObject): IssuedCertificate {
        val o = post(path, body, "certificate")
        return IssuedCertificate(pemCertificate(o.getString("certificate_pem")), pemCertificate(o.getString("issuer_pem")))
    }
    private suspend fun get(path: String, vararg wrappers: String) = unwrap(JSONObject(raw("GET", path, null).decodeToString()), wrappers)
    private suspend fun post(path: String, body: JSONObject, vararg wrappers: String) =
        unwrap(JSONObject(raw("POST", path, body.toString().encodeToByteArray()).decodeToString()), wrappers)
    private suspend fun list(path: String, wrapper: String): List<JSONObject> {
        val root = JSONObject(raw("GET", path, null).decodeToString())
        val data = if (root.opt("data") is JSONObject) root.getJSONObject("data") else root
        val a = data.optJSONArray(wrapper) ?: (data.opt("data") as? JSONArray) ?: JSONArray()
        return (0 until a.length()).map { a.getJSONObject(it) }
    }

    private suspend fun raw(method: String, path: String, body: ByteArray?, contentType: String = "application/json"): ByteArray = withContext(Dispatchers.IO) {
        val base = if (indoor) INDOOR_BASE else PUBLIC_BASE
        val url = URL(base + path.removePrefix("/"))
        val connection = url.openConnection() as HttpsURLConnection
        connection.requestMethod = method; connection.connectTimeout = 20_000; connection.readTimeout = 60_000
        connection.instanceFollowRedirects = false; connection.setRequestProperty("Accept", "application/json")
        connection.setRequestProperty("User-Agent", "Authentiverse-Android/1.7.0")
        token()?.let { connection.setRequestProperty("Authorization", "Bearer $it") }
        connection.sslSocketFactory = when {
            indoor -> indoorApiSslContext().socketFactory
            deviceCertificate != null && deviceIssuerCertificate != null -> deviceSslContext().socketFactory
            else -> connection.sslSocketFactory
        }
        if (body != null) { connection.doOutput = true; connection.setRequestProperty("Content-Type", contentType); connection.outputStream.use { it.write(body) } }
        val code = connection.responseCode
        val result = (if (code in 200..299) connection.inputStream else connection.errorStream)?.use { it.readBytes() } ?: ByteArray(0)
        if (code !in 200..299) {
            val message = runCatching { JSONObject(result.decodeToString()).optJSONObject("error")?.optString("code") }.getOrNull()
            throw IllegalStateException(errorMessage(code, message))
        }
        result
    }

    private fun deviceSslContext(): SSLContext {
        val cert = requireNotNull(deviceCertificate) { "The device certificate is unavailable." }
        val issuer = requireNotNull(deviceIssuerCertificate) { "The device certificate issuer is unavailable." }
        val chain = arrayOf(
            DigitalSpaceCrypto.certificate(DigitalSpaceCrypto.b64(cert)),
            DigitalSpaceCrypto.certificate(DigitalSpaceCrypto.b64(issuer))
        )
        val keyManager = FixedKeyManager(keys.keyPair("device").private, chain)

        // Passing null trust managers keeps Android's normal public CA trust for
        // internal.syntal.pro while adding the Digital Space device identity.
        return SSLContext.getInstance("TLS").apply {
            init(arrayOf<KeyManager>(keyManager), null, null)
        }
    }

    private fun indoorApiSslContext(): SSLContext {
        // The private control-plane API is authenticated by the enrolled device.
        // The short-lived profile certificate is reserved for Area applications
        // such as home.digitalspace.home.arpa and is not accepted by this listener.
        val cert = requireNotNull(deviceCertificate) { "The device certificate is unavailable." }
        val issuer = requireNotNull(deviceIssuerCertificate) { "The device certificate issuer is unavailable." }
        val serverCa = requireNotNull(indoorServerCaCertificate) { "The Indoor server authority is unavailable." }
        val root = DigitalSpaceCrypto.certificate(DigitalSpaceCrypto.b64(serverCa))
        require(DigitalSpaceCrypto.hex(DigitalSpaceCrypto.sha256(root.encoded)).equals(PINNED_CA_SHA256, true)) { "The Indoor authority pin does not match." }
        val chain = arrayOf(
            DigitalSpaceCrypto.certificate(DigitalSpaceCrypto.b64(cert)),
            DigitalSpaceCrypto.certificate(DigitalSpaceCrypto.b64(issuer))
        )
        val keyManager = FixedKeyManager(keys.keyPair("device").private, chain)
        val trust = object : X509TrustManager {
            override fun getAcceptedIssuers() = arrayOf(root)
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) = Unit
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
                require(!chain.isNullOrEmpty())
                val ks = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null); setCertificateEntry("root", root) }
                val factory = javax.net.ssl.TrustManagerFactory.getInstance(javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm())
                factory.init(ks); (factory.trustManagers.first { it is X509TrustManager } as X509TrustManager).checkServerTrusted(chain, authType)
            }
        }
        return SSLContext.getInstance("TLS").apply { init(arrayOf<KeyManager>(keyManager), arrayOf(trust), null) }
    }

    private class FixedKeyManager(private val key: PrivateKey, private val chain: Array<X509Certificate>) : X509KeyManager {
        override fun chooseClientAlias(keyType: Array<out String>?, issuers: Array<out Principal>?, socket: java.net.Socket?) = "digitalspace"
        override fun getClientAliases(keyType: String?, issuers: Array<out Principal>?) = arrayOf("digitalspace")
        override fun getCertificateChain(alias: String?) = chain
        override fun getPrivateKey(alias: String?) = key
        override fun chooseServerAlias(keyType: String?, issuers: Array<out Principal>?, socket: java.net.Socket?) = null
        override fun getServerAliases(keyType: String?, issuers: Array<out Principal>?) = null
    }

    private fun unwrap(root: JSONObject, wrappers: Array<out String>): JSONObject {
        var value = if (root.opt("data") is JSONObject) root.getJSONObject("data") else root
        wrappers.firstOrNull { value.opt(it) is JSONObject }?.let { value = value.getJSONObject(it) }
        return value
    }
    private fun escape(value: String) = Uri.encode(value)
    private fun pemCertificate(pem: String): ByteArray = CertificateFactory.getInstance("X.509").generateCertificate(pem.byteInputStream()).encoded
    private fun JSONObject.optStringOrNull(name: String) = if (isNull(name)) null else optString(name).takeIf(String::isNotBlank)
    private fun errorMessage(code: Int, value: String?) = when (value) {
        "invalid_invitation" -> "The invitation is invalid, expired, or already used."
        "invalid_verification_code" -> "One or both verification codes are incorrect."
        "device_revoked" -> "This device has been revoked."
        "mtls_required" -> "The device certificate is missing, expired, or revoked."
        "recipient_unavailable" -> "The recipient has not enabled Indoor delivery."
        "package_too_large" -> "The encrypted package exceeds the Indoor limit."
        else -> "The control plane rejected the request (HTTP $code${value?.let { ", $it" } ?: ""})."
    }
}
