/* SPDX-License-Identifier: MIT */
package pro.digitalspace.android.privacy

import org.json.JSONObject
import pro.digitalspace.android.model.PersistentState
import pro.digitalspace.android.network.ControlPlaneClient
import pro.digitalspace.android.security.DigitalSpaceCrypto
import pro.digitalspace.android.security.IdentityKeyStore
import java.net.URL
import java.security.KeyStore
import java.security.Signature
import java.security.cert.CertPathValidator
import java.security.cert.CertificateFactory
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import java.time.Instant
import java.time.temporal.ChronoUnit
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.KeyManager
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509KeyManager
import java.security.Principal
import java.security.PrivateKey

/** Windows-compatible issuer-signed predicate credential. */
data class SignedPredicateCredential(
    val format: String,
    val credentialId: String,
    val issuer: String,
    val schemaId: String,
    val assurance: String,
    val profileId: String,
    val predicateId: String,
    val result: Boolean,
    val issuedAt: Instant,
    val expiresAt: Instant,
    val issuerCertificatePem: String,
    val issuerSignature: String
) {
    fun toJson() = JSONObject().apply {
        put("format", format); put("credential_id", credentialId); put("issuer", issuer)
        put("schema_id", schemaId); put("assurance", assurance); put("profile_id", profileId)
        put("predicate_id", predicateId); put("result", result); put("issued_at", issuedAt.toString())
        put("expires_at", expiresAt.toString()); put("issuer_certificate_pem", issuerCertificatePem)
        put("issuer_signature", issuerSignature)
    }
    companion object {
        fun fromJson(o: JSONObject) = SignedPredicateCredential(
            o.getString("format"), o.getString("credential_id"), o.getString("issuer"),
            o.getString("schema_id"), o.getString("assurance"), o.getString("profile_id"),
            o.getString("predicate_id"), o.getBoolean("result"), Instant.parse(o.getString("issued_at")),
            Instant.parse(o.getString("expires_at")), o.getString("issuer_certificate_pem"),
            o.getString("issuer_signature")
        )
    }
}

class PrivacyProofService(
    private val wallet: PrivateAttributeWallet,
    private val client: ControlPlaneClient,
    private val keys: IdentityKeyStore
) {
    companion object {
        const val CREDENTIAL_FORMAT = "digitalspace-signed-predicate-v1"
        const val ATTRIBUTE_SCHEMA = "osmio-personal-attributes-v1"
        const val PRESENTATION_FORMAT = "digitalspace-predicate-presentation-v1"
    }

    suspend fun present(request: PrivacyRequest, state: PersistentState): Boolean {
        requireState(state)
        if (!wallet.evaluate(request.predicateId)) {
            sendCallback(request, state, JSONObject().put("status", "not_satisfied"))
            return false
        }
        var credential = wallet.load().credentials.mapNotNull { runCatching { SignedPredicateCredential.fromJson(it) }.getOrNull() }
            .firstOrNull { it.profileId == state.profileId && it.predicateId == request.predicateId && it.result && it.expiresAt.isAfter(Instant.now().plus(1, ChronoUnit.MINUTES)) }
        if (credential == null) {
            val evidence = wallet.evidenceFor(request.predicateId)
            val issued = client.issuePredicateCredential(requireNotNull(state.profileId), request.predicateId, evidence)
            credential = SignedPredicateCredential.fromJson(issued)
            validateCredential(credential, state)
            wallet.storeCredential(credential.toJson())
        } else validateCredential(credential, state)

        val created = Instant.now()
        val cert = DigitalSpaceCrypto.certificate(requireNotNull(state.profileCertificate))
        cert.checkValidity()
        val payload = listOf(PRESENTATION_FORMAT, request.requestId, request.verifierId, request.nonce,
            credential.credentialId, credential.predicateId, created.epochSecond.toString()).joinToString("\n").encodeToByteArray()
        val presentation = JSONObject().apply {
            put("format", PRESENTATION_FORMAT); put("request_id", request.requestId); put("verifier_id", request.verifierId)
            put("nonce", request.nonce); put("credential", credential.toJson())
            put("holder_certificate", DigitalSpaceCrypto.b64(cert.encoded))
            put("holder_signature", DigitalSpaceCrypto.b64(keys.sign("profile-${state.selectedAreaId}", payload)))
            put("created_at", created.toString())
        }
        sendCallback(request, state, JSONObject().put("status", "satisfied").put("presentation", presentation))
        return true
    }

    suspend fun decline(request: PrivacyRequest, state: PersistentState) {
        requireState(state)
        sendCallback(request, state, JSONObject().put("status", "not_satisfied"))
    }

    private fun requireState(state: PersistentState) {
        require(state.enrolled && !state.profileId.isNullOrBlank() && !state.profileCertificate.isNullOrBlank() &&
            !state.profileIssuerCertificate.isNullOrBlank() && !state.indoorServerCaCertificate.isNullOrBlank() &&
            !state.selectedAreaId.isNullOrBlank()) { "Go Indoors with the required username before approving this request." }
    }

    private fun validateCredential(value: SignedPredicateCredential, state: PersistentState) {
        val now = Instant.now()
        require(value.format == CREDENTIAL_FORMAT && value.credentialId.length in 1..128 && value.issuer.length in 1..256 &&
            value.schemaId == ATTRIBUTE_SCHEMA && value.assurance == "verified" && value.profileId == state.profileId &&
            value.predicateId in PrivateAttributeWallet.policies.map { it.id } && value.result &&
            !value.issuedAt.isAfter(now.plus(1, ChronoUnit.MINUTES)) && value.expiresAt.isAfter(now) &&
            !value.expiresAt.isAfter(value.issuedAt.plus(25, ChronoUnit.HOURS))) { "The issuer returned an invalid private predicate credential." }
        val issuer = CertificateFactory.getInstance("X.509").generateCertificate(value.issuerCertificatePem.byteInputStream()) as X509Certificate
        val root = DigitalSpaceCrypto.certificate(requireNotNull(state.indoorServerCaCertificate))
        issuer.checkValidity(); root.checkValidity()
        val path = CertificateFactory.getInstance("X.509").generateCertPath(listOf(issuer))
        val parameters = PKIXParameters(setOf(TrustAnchor(root, null))).apply { isRevocationEnabled = false }
        runCatching { CertPathValidator.getInstance("PKIX").validate(path, parameters) }
            .getOrElse { throw IllegalStateException("The predicate issuer certificate is not trusted.", it) }
        val canonical = listOf(CREDENTIAL_FORMAT, value.credentialId, value.issuer, value.schemaId, value.assurance,
            value.profileId, value.predicateId, if (value.result) "true" else "false",
            value.issuedAt.epochSecond.toString(), value.expiresAt.epochSecond.toString()).joinToString("\n").encodeToByteArray()
        val signature = DigitalSpaceCrypto.unb64(value.issuerSignature)
        val verified = DigitalSpaceCrypto.verifyP1363(issuer.publicKey, canonical, signature) || runCatching {
            Signature.getInstance("SHA256withECDSA").run { initVerify(issuer.publicKey); update(canonical); verify(signature) }
        }.getOrDefault(false)
        require(verified) { "The predicate credential signature is invalid." }
    }

    private suspend fun sendCallback(request: PrivacyRequest, state: PersistentState, body: JSONObject) {
        PrivacyRequestParser.validate(request, wallet, setOf("https://home.digitalspace.home.arpa"))
        val profile = DigitalSpaceCrypto.certificate(requireNotNull(state.profileCertificate))
        val issuer = DigitalSpaceCrypto.certificate(requireNotNull(state.profileIssuerCertificate))
        val root = DigitalSpaceCrypto.certificate(requireNotNull(state.indoorServerCaCertificate))
        val ssl = SSLContext.getInstance("TLS").apply {
            val km = FixedKeyManager(keys.keyPair("profile-${state.selectedAreaId}").private, arrayOf(profile, issuer))
            val trustStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null); setCertificateEntry("authentiverse-root", root) }
            val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(trustStore) }
            init(arrayOf<KeyManager>(km), tmf.trustManagers, null)
        }
        kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
            val connection = URL(request.callbackUri).openConnection() as HttpsURLConnection
            try {
                connection.requestMethod = "POST"; connection.connectTimeout = 15_000; connection.readTimeout = 15_000
                connection.instanceFollowRedirects = false; connection.sslSocketFactory = ssl.socketFactory
                connection.setRequestProperty("Accept", "application/json")
                connection.setRequestProperty("Content-Type", "application/json; charset=utf-8")
                connection.setRequestProperty("User-Agent", "Authentiverse-Android/1.7.0")
                val bytes = body.toString().encodeToByteArray()
                try { connection.doOutput = true; connection.outputStream.use { it.write(bytes) } } finally { bytes.fill(0) }
                val code = connection.responseCode
                connection.inputStreamOrError().use { it?.readBytes() }
                require(code in 200..299) { "The Indoor application rejected the privacy response (HTTP $code)." }
            } finally { connection.disconnect() }
        }
    }

    private fun HttpsURLConnection.inputStreamOrError() = runCatching { inputStream }.getOrElse { errorStream }

    private class FixedKeyManager(private val key: PrivateKey, private val chain: Array<X509Certificate>) : X509KeyManager {
        override fun chooseClientAlias(keyType: Array<out String>?, issuers: Array<out Principal>?, socket: java.net.Socket?) = "authentiverse"
        override fun getClientAliases(keyType: String?, issuers: Array<out Principal>?) = arrayOf("authentiverse")
        override fun getCertificateChain(alias: String?) = chain
        override fun getPrivateKey(alias: String?) = key
        override fun chooseServerAlias(keyType: String?, issuers: Array<out Principal>?, socket: java.net.Socket?) = null
        override fun getServerAliases(keyType: String?, issuers: Array<out Principal>?) = null
    }
}
