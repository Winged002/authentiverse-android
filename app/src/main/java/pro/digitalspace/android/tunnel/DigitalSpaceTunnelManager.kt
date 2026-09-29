/* SPDX-License-Identifier: MIT */
package pro.digitalspace.android.tunnel

import android.content.Context
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Statistics
import com.wireguard.android.backend.Tunnel
import com.wireguard.config.Config
import com.wireguard.config.Interface
import com.wireguard.config.Peer
import com.wireguard.crypto.KeyPair
import pro.digitalspace.android.model.TunnelInfo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

data class TunnelMetrics(val received: Long = 0, val sent: Long = 0, val latestHandshakeMillis: Long = 0)

class DigitalSpaceTunnelManager(context: Context) {
    private val backend = GoBackend(context.applicationContext)
    private val tunnel = object : Tunnel {
        @Volatile var state = Tunnel.State.DOWN
        override fun getName() = "DigitalSpace"
        override fun onStateChange(newState: Tunnel.State) { state = newState }
    }

    suspend fun enter(info: TunnelInfo, privateKey: String) = withContext(Dispatchers.IO) {
        validate(info)
        val interfaceBuilder = Interface.Builder().parsePrivateKey(privateKey).parseAddresses(info.address)
        info.dns.filter(String::isNotBlank).take(2).forEach { interfaceBuilder.parseDnsServers(it) }
        val requestedRoutes = info.allowedIps.map(String::trim).filter(String::isNotBlank)
        val tunnelRoutes = if (requestedRoutes == listOf("0.0.0.0/0")) {
            // Capture IPv6 as well so isolated Indoor mode cannot leak public
            // Internet traffic around an IPv4-only full tunnel.
            listOf("0.0.0.0/0", "::/0")
        } else {
            requestedRoutes
        }
        val peer = Peer.Builder().parsePublicKey(info.serverPublicKey).parseEndpoint(info.endpoint)
            .parseAllowedIPs(tunnelRoutes.joinToString(","))
            .setPersistentKeepalive(info.persistentKeepalive.coerceIn(0, 65535)).build()
        val config = Config.Builder().setInterface(interfaceBuilder.build()).addPeer(peer).build()
        backend.setState(tunnel, Tunnel.State.UP, config)
    }

    suspend fun leave() = withContext(Dispatchers.IO) { backend.setState(tunnel, Tunnel.State.DOWN, null) }
    suspend fun isUp(): Boolean = withContext(Dispatchers.IO) { backend.getState(tunnel) == Tunnel.State.UP }
    suspend fun metrics(): TunnelMetrics = withContext(Dispatchers.IO) {
        val stats = backend.getStatistics(tunnel)
        var rx = 0L; var tx = 0L; var handshake = 0L
        stats.peers().forEach { key ->
            stats.peer(key)?.let { peer ->
                rx += peer.rxBytes(); tx += peer.txBytes()
                handshake = maxOf(handshake, peer.latestHandshakeEpochMillis())
            }
        }
        TunnelMetrics(rx, tx, handshake)
    }

    fun newWireGuardKeyPair(): Pair<String, String> = KeyPair().let { it.privateKey.toBase64() to it.publicKey.toBase64() }

    private fun validate(info: TunnelInfo) {
        require(info.address.matches(Regex("10\\.200\\.\\d{1,3}\\.\\d{1,3}/32"))) { "The assigned private address is invalid." }
        require(info.serverPublicKey.isNotBlank() && info.endpoint.contains(':')) { "The Area tunnel details are incomplete." }
        val routes = info.allowedIps.map(String::trim).filter(String::isNotBlank)
        val isolatedIndoor = routes == listOf("0.0.0.0/0")
        val splitArea = routes.isNotEmpty() && routes.all {
            it != "::/0" && (it.startsWith("10.200.") || it == "10.200.0.0/16")
        }
        require(isolatedIndoor || splitArea) { "Digital Space refuses an unknown or out-of-Area route." }
        if (isolatedIndoor) {
            require(info.dns.contains("10.200.0.1")) {
                "Isolated Indoor mode requires the private Area DNS server."
            }
        }
    }
}
