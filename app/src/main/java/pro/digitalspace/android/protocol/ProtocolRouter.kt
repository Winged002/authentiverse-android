/* SPDX-License-Identifier: MIT */
package pro.digitalspace.android.protocol

import android.net.Uri

enum class AuthentiverseRouteKind { PRIVACY_PRESENT, MOI_REQUEST, MOI_EVIDENCE, MOI_ATTRIBUTES, MOI_FILES, MOI_IMPORT, HTTPSA, INDOOR, APP, UNKNOWN }
data class AuthentiverseRoute(val kind: AuthentiverseRouteKind, val uri: Uri)

object ProtocolRouter {
    fun route(uri: Uri): AuthentiverseRoute {
        val scheme = uri.scheme?.lowercase().orEmpty()
        val host = uri.host?.lowercase().orEmpty()
        val kind = when {
            scheme in setOf("authentiverse", "digitalspace") && host == "present" -> AuthentiverseRouteKind.PRIVACY_PRESENT
            scheme == "moi" && host == "request" -> AuthentiverseRouteKind.MOI_REQUEST
            scheme == "moi" && host == "evidence" -> AuthentiverseRouteKind.MOI_EVIDENCE
            scheme == "moi" && host == "attributes" -> AuthentiverseRouteKind.MOI_ATTRIBUTES
            scheme == "moi" && host == "files" -> AuthentiverseRouteKind.MOI_FILES
            scheme == "moi" && host == "import" -> AuthentiverseRouteKind.MOI_IMPORT
            scheme == "httpsa" -> AuthentiverseRouteKind.HTTPSA
            scheme == "indoor" -> AuthentiverseRouteKind.INDOOR
            scheme in setOf("authentiverse", "digitalspace") -> AuthentiverseRouteKind.APP
            else -> AuthentiverseRouteKind.UNKNOWN
        }
        return AuthentiverseRoute(kind, uri)
    }
}
