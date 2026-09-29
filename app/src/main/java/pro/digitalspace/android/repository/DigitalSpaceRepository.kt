/* SPDX-License-Identifier: MIT */
package pro.digitalspace.android.repository

import android.content.Context
import android.net.Uri
import android.os.Build
import org.json.JSONObject
import pro.digitalspace.android.data.ExchangeService
import pro.digitalspace.android.data.ImportResult
import pro.digitalspace.android.data.InformationStore
import pro.digitalspace.android.chat.ChatService
import pro.digitalspace.android.model.*
import pro.digitalspace.android.network.ControlPlaneClient
import pro.digitalspace.android.network.EnrollmentStart
import pro.digitalspace.android.privacy.PrivateAttributeWallet
import pro.digitalspace.android.security.DigitalSpaceCrypto
import pro.digitalspace.android.security.IdentityKeyStore
import pro.digitalspace.android.security.SecureStore
import pro.digitalspace.android.tunnel.DigitalSpaceTunnelManager
import pro.digitalspace.android.tunnel.TunnelMetrics
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.net.ConnectException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.time.Instant

data class AppSnapshot(
    val state: SpaceState,
    val persistent: PersistentState,
    val areas: List<Area>,
    val information: InformationManifest,
    val metrics: TunnelMetrics = TunnelMetrics(),
    val busy: Boolean = false,
    val message: String? = null
)

data class IndoorBrowserCredentials(
    val profilePrivateKey: PrivateKey,
    val profileCertificateChain: Array<X509Certificate>,
    val devicePrivateKey: PrivateKey,
    val deviceCertificateChain: Array<X509Certificate>,
    val serverAuthority: X509Certificate
)

class DigitalSpaceRepository(
    private val context: Context,
    private val secure: SecureStore,
    private val keys: IdentityKeyStore,
    private val client: ControlPlaneClient,
    private val tunnel: DigitalSpaceTunnelManager,
    val information: InformationStore,
    val exchange: ExchangeService,
    val privacy: PrivateAttributeWallet,
    val chat: ChatService
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var persistent = loadState()
    private var areas = emptyList<Area>()
    private val mutable = MutableStateFlow(AppSnapshot(if (persistent.enrolled) SpaceState.OUTDOORS else SpaceState.UNINITIALIZED,
        persistent.copy(), areas, information.load()))
    val snapshot: StateFlow<AppSnapshot> = mutable

    init {
        client.deviceCertificate = persistent.deviceCertificate?.let(DigitalSpaceCrypto::unb64)
        client.deviceIssuerCertificate = persistent.deviceIssuerCertificate?.let(DigitalSpaceCrypto::unb64)
        client.indoorServerCaCertificate = persistent.indoorServerCaCertificate?.let(DigitalSpaceCrypto::unb64)
        if (persistent.enrolled) scope.launch { runCatching { refreshAreas() } }
    }

    suspend fun startEnrollment(invitation: String, name: String, email: String, phone: String): EnrollmentStart = operation(SpaceState.ENROLLING) {
        client.startEnrollment(invitation.trim(), name.trim(), email.trim(), phone.trim())
    }

    suspend fun finishEnrollment(enrollmentId: String, emailCode: String, phoneCode: String,
                                 displayName: String, requestedHandle: String) = operation(SpaceState.ENROLLING) {
        val verified = client.verifyEnrollment(enrollmentId, emailCode.trim(), phoneCode.trim())
        val handle = normalizeHandle(requestedHandle)
        val wg = tunnel.newWireGuardKeyPair()
        val profile = client.createProfile(verified.identityId, handle, displayName.trim())
        val deviceName = "${Build.MANUFACTURER} ${Build.MODEL}".trim().take(80)
        val deviceId = client.enrollDevice(verified.identityId, profile.first, deviceName, wg.second)
        val ca = client.serverCa()
        require(DigitalSpaceCrypto.hex(DigitalSpaceCrypto.sha256(ca.first)).equals(ca.second, true) &&
            ca.second.equals(ControlPlaneClient.PINNED_CA_SHA256, true)) { "The server authority fingerprint does not match." }
        val foundational = client.issueFoundational(keys.csrPem("foundational", "Digital Space Identity ${verified.identityId}"))
        val device = client.issueDevice(deviceId, keys.csrPem("device", "Digital Space Android $deviceId"))
        persistent = PersistentState(identityId = verified.identityId, profileId = profile.first, deviceId = deviceId,
            wireGuardPrivateKey = wg.first, wireGuardPublicKey = wg.second, profileHandle = profile.second,
            deviceName = deviceName, enrolled = true,
            foundationalCertificate = DigitalSpaceCrypto.b64(foundational.certificateDer),
            foundationalIssuerCertificate = DigitalSpaceCrypto.b64(foundational.issuerDer),
            deviceCertificate = DigitalSpaceCrypto.b64(device.certificateDer),
            deviceIssuerCertificate = DigitalSpaceCrypto.b64(device.issuerDer),
            indoorServerCaCertificate = DigitalSpaceCrypto.b64(ca.first))
        client.deviceCertificate = device.certificateDer
        client.deviceIssuerCertificate = device.issuerDer
        client.indoorServerCaCertificate = ca.first
        saveState(); refreshAreas(); emit(SpaceState.OUTDOORS, message = "Identity and Android device enrolled.")
    }

    suspend fun refreshAreas() {
        if (!persistent.enrolled) return
        if (persistent.indoorServerCaCertificate.isNullOrBlank()) {
            val ca = client.serverCa()
            require(DigitalSpaceCrypto.hex(DigitalSpaceCrypto.sha256(ca.first)).equals(ca.second, true) &&
                ca.second.equals(ControlPlaneClient.PINNED_CA_SHA256, true)) {
                "The server authority fingerprint does not match."
            }
            persistent.indoorServerCaCertificate = DigitalSpaceCrypto.b64(ca.first)
            client.indoorServerCaCertificate = ca.first
        }
        areas = client.areas().filter { it.id.isNotBlank() && it.available }.sortedBy { it.name.lowercase() }
        if (persistent.selectedAreaId !in areas.map { it.id }) persistent.selectedAreaId = areas.firstOrNull()?.id
        saveState(); emit(mutable.value.state)
    }

    suspend fun enterArea(areaId: String) = operation(SpaceState.ENTERING) {
        require(persistent.enrolled); val device = requireNotNull(persistent.deviceId); val profile = requireNotNull(persistent.profileId)
        val area = areas.first { it.id == areaId }
        client.join(areaId, device, profile)
        val profileKeyAlias = "profile-$areaId"
        val profileCert = client.issueProfile(areaId, device, profile, keys.csrPem(profileKeyAlias, "${persistent.profileHandle}@$areaId"))
        val info = client.tunnel(areaId, device)
        tunnel.enter(info, requireNotNull(persistent.wireGuardPrivateKey))
        persistent.selectedAreaId = areaId; persistent.currentAreaName = area.name
        persistent.profileCertificate = DigitalSpaceCrypto.b64(profileCert.certificateDer)
        persistent.profileIssuerCertificate = DigitalSpaceCrypto.b64(profileCert.issuerDer)
        persistent.isolatedIndoor = info.allowedIps.map(String::trim) == listOf("0.0.0.0/0")
        client.profileCertificate = profileCert.certificateDer
        client.profileIssuerCertificate = profileCert.issuerDer
        client.profileKeyAlias = profileKeyAlias
        saveState(); client.indoor = true; registerInboxWhenReady(); emit(SpaceState.INDOORS, message = "Indoors in ${area.name}.")
        startIndoorLoop()
    }

    suspend fun goOutdoors() = operation(SpaceState.LEAVING) {
        client.indoor = false
        client.profileCertificate = null
        client.profileIssuerCertificate = null
        client.profileKeyAlias = null
        tunnel.leave(); persistent.currentAreaName = null
        persistent.profileCertificate = null; persistent.profileIssuerCertificate = null
        persistent.isolatedIndoor = false; saveState()
        emit(SpaceState.OUTDOORS, message = "You are Outdoors.")
    }

    suspend fun addProtectedFile(uri: Uri) = operation(mutable.value.state) {
        information.addOwnedFile(uri, persistent); emit(mutable.value.state, message = "File protected in My files.")
    }
    suspend fun importPackage(uri: Uri): ImportResult = operation(mutable.value.state) {
        exchange.import(uri, persistent).also { result ->
            val message = when (result) {
                is ImportResult.Contact -> "@${result.record.card.handle} added to People."
                is ImportResult.Shared -> "${result.record.descriptor.fileName} added to Shared with me."
                is ImportResult.Nda -> when {
                    result.isResponse -> "@${result.sender}'s signed ${result.decision?.name?.lowercase()} response was verified."
                    result.importedFiles > 0 -> "NDA and ${result.importedFiles} protected file${if (result.importedFiles == 1) "" else "s"} received."
                    else -> "NDA received from @${result.sender}."
                }
            }
            emit(mutable.value.state, message = message)
        }
    }
    suspend fun decideNda(ndaId: String, accepted: Boolean) = operation(mutable.value.state) {
        val own = exchange.ownContact(persistent)
        val nda = information.decide(ndaId, own.contactId, accepted, persistent)
        if (mutable.value.state == SpaceState.INDOORS) {
            val issuer = information.load().contacts.firstOrNull { it.card.signingCertificate == nda.issuerCertificate }
            issuer?.let { client.uploadInbox(it.card.contactId, "nda_response", exchange.createNdaEnvelope(ndaId, it.card.contactId, persistent)) }
        }
        emit(mutable.value.state, message = if (accepted) "NDA accepted." else "NDA rejected.")
    }
    suspend fun sendNdaIndoors(ndaId: String, recipientId: String) = operation(mutable.value.state) {
        require(mutable.value.state == SpaceState.INDOORS) { "Enter an Area before using Indoor delivery." }
        val agreement = information.load().agreements.first { it.ndaId == ndaId }
        val issuedByMe = agreement.issuerCertificate == persistent.foundationalCertificate
        registerInbox()
        client.uploadInbox(recipientId, if (issuedByMe) "nda" else "nda_response",
            exchange.createNdaPackageBytes(ndaId, recipientId, persistent))
        emit(SpaceState.INDOORS, message = if (issuedByMe)
            "Signed NDA and its protected files were sent securely."
        else "Your signed NDA response was sent securely.")
    }

    suspend fun syncInbox(): Int {
        if (mutable.value.state != SpaceState.INDOORS) return 0
        registerInbox(); val own = exchange.ownContact(persistent); var imported = 0
        for (item in client.inboxItems(own.contactId)) {
            val kind = item.optString("package_kind")
            if (kind !in setOf("nda", "nda_response", "chat")) continue
            val id = item.getString("item_id")
            runCatching {
                val bytes = client.downloadInboxItem(id)
                try {
                    if (kind == "chat") chat.ingest(bytes, persistent) else exchange.importBytes(bytes, persistent)
                    client.acknowledge(id)
                    imported++
                } finally { bytes.fill(0) }
            }
        }
        if (imported > 0) emit(SpaceState.INDOORS, message = "$imported Indoor item${if (imported == 1) "" else "s"} received.")
        return imported
    }

    suspend fun refreshMetrics() {
        if (mutable.value.state == SpaceState.INDOORS) mutable.value = mutable.value.copy(metrics = tunnel.metrics())
    }

    fun refreshLocal(message: String? = null) = emit(mutable.value.state, message)

    fun indoorBrowserCredentials(): IndoorBrowserCredentials {
        require(mutable.value.state == SpaceState.INDOORS) { "Enter an Area before opening Indoor Home." }
        val areaId = requireNotNull(persistent.selectedAreaId) { "The active Area is unavailable." }
        val profile = DigitalSpaceCrypto.certificate(requireNotNull(persistent.profileCertificate) {
            "The active profile certificate is unavailable. Go Outdoors and enter the Area again."
        })
        val profileIssuer = DigitalSpaceCrypto.certificate(requireNotNull(persistent.profileIssuerCertificate) {
            "The profile certificate issuer is unavailable."
        })
        val device = DigitalSpaceCrypto.certificate(requireNotNull(persistent.deviceCertificate) {
            "The enrolled device certificate is unavailable."
        })
        val deviceIssuer = DigitalSpaceCrypto.certificate(requireNotNull(persistent.deviceIssuerCertificate) {
            "The device certificate issuer is unavailable."
        })
        val authority = DigitalSpaceCrypto.certificate(requireNotNull(persistent.indoorServerCaCertificate) {
            "The Indoor server authority is unavailable."
        })
        require(DigitalSpaceCrypto.hex(DigitalSpaceCrypto.sha256(authority.encoded))
            .equals(ControlPlaneClient.PINNED_CA_SHA256, true)) { "The Indoor authority pin does not match." }
        profile.checkValidity()
        profileIssuer.checkValidity()
        device.checkValidity()
        deviceIssuer.checkValidity()
        authority.checkValidity()
        profile.verify(profileIssuer.publicKey)
        device.verify(deviceIssuer.publicKey)
        profileIssuer.verify(profileIssuer.publicKey)
        deviceIssuer.verify(deviceIssuer.publicKey)
        return IndoorBrowserCredentials(
            keys.keyPair("profile-$areaId").private,
            arrayOf(profile, profileIssuer),
            keys.keyPair("device").private,
            arrayOf(device, deviceIssuer),
            authority
        )
    }

    fun clearMessage() { mutable.value = mutable.value.copy(message = null) }

    private suspend fun registerInbox() {
        val own = exchange.ownContact(persistent)
        val payload = listOf("digitalspace-indoor-route-v1", own.contactId, persistent.profileId, persistent.deviceId)
            .joinToString("\n").encodeToByteArray()
        client.registerInbox(JSONObject().put("contact_id", own.contactId).put("profile_id", persistent.profileId)
            .put("foundational_certificate", persistent.foundationalCertificate).put("exchange_public_key", own.exchangePublicKey)
            .put("signature", DigitalSpaceCrypto.b64(keys.sign("foundational", payload))))
    }

    private suspend fun registerInboxWhenReady() {
        var lastFailure: Throwable? = null
        repeat(20) { attempt ->
            try {
                registerInbox()
                return
            } catch (error: Throwable) {
                lastFailure = error
                if (!error.isTransientIndoorReadinessFailure() || attempt == 19) throw error
                delay(500)
            }
        }
        throw lastFailure ?: IllegalStateException("The Indoor API did not become ready.")
    }

    private fun Throwable.isTransientIndoorReadinessFailure(): Boolean {
        var current: Throwable? = this
        while (current != null) {
            if (current is UnknownHostException || current is ConnectException || current is SocketTimeoutException) return true
            current = current.cause
        }
        return message?.contains("unable to resolve host", ignoreCase = true) == true
    }

    private fun startIndoorLoop() {
        scope.launch {
            while (mutable.value.state == SpaceState.INDOORS) {
                runCatching { syncInbox() }; runCatching { refreshMetrics() }; delay(10_000)
            }
        }
    }

    private suspend fun <T> operation(transitional: SpaceState, block: suspend () -> T): T {
        val previous = mutable.value.state
        mutable.value = mutable.value.copy(state = transitional, busy = true, message = null)
        return try { block() } catch (error: Throwable) {
            if (transitional == SpaceState.ENTERING) {
                client.indoor = false
                client.profileCertificate = null
                client.profileIssuerCertificate = null
                client.profileKeyAlias = null
                runCatching { tunnel.leave() }
                persistent.currentAreaName = null
                persistent.profileCertificate = null
                persistent.profileIssuerCertificate = null
                persistent.isolatedIndoor = false
                saveState()
            }
            val fallback = if (!persistent.enrolled) SpaceState.UNINITIALIZED
                else if (previous == SpaceState.INDOORS && transitional != SpaceState.LEAVING) SpaceState.INDOORS
                else SpaceState.OUTDOORS
            mutable.value = mutable.value.copy(state = fallback, busy = false, message = error.message ?: "Operation failed.")
            throw error
        } finally { mutable.value = mutable.value.copy(busy = false, information = information.load(), persistent = persistent.copy(), areas = areas) }
    }

    private fun emit(state: SpaceState, message: String? = null) {
        mutable.value = AppSnapshot(state, persistent.copy(), areas, information.load(), mutable.value.metrics, false, message)
    }
    private fun saveState() = secure.put("application-state", persistent.toJson().toString().encodeToByteArray())
    private fun loadState(): PersistentState = secure.get("application-state")?.let {
        try { PersistentState.fromJson(JSONObject(it.decodeToString())) } finally { it.fill(0) }
    } ?: PersistentState()
    private fun normalizeHandle(value: String): String = value.trim().lowercase().removePrefix("@").replace(Regex("[^a-z0-9_.-]"), "-")
        .trim('-').take(32).also { require(it.length >= 3) { "Username must contain at least three valid characters." } }
}
