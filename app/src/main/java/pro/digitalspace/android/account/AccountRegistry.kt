/* SPDX-License-Identifier: MIT */
package pro.digitalspace.android.account

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import pro.digitalspace.android.security.SecureStore
import java.io.File
import java.time.Instant
import java.util.UUID

/** Non-secret launcher metadata. Account secrets never live in this registry. */
data class AuthentiverseAccount(
    val id: String,
    var displayName: String,
    val namespace: String,
    val createdAt: Instant,
    var lastUsedAt: Instant,
    var lastKnownHandle: String? = null,
    val legacy: Boolean = false
) {
    fun toJson() = JSONObject().apply {
        put("format", "authentiverse-local-account-v1")
        put("id", id)
        put("display_name", displayName)
        put("namespace", namespace)
        put("created_at", createdAt.toString())
        put("last_used_at", lastUsedAt.toString())
        putOpt("last_known_handle", lastKnownHandle)
        put("legacy", legacy)
    }

    companion object {
        fun fromJson(o: JSONObject) = AuthentiverseAccount(
            id = o.getString("id"),
            displayName = o.optString("display_name").ifBlank { "Authentiverse" },
            namespace = o.getString("namespace"),
            createdAt = runCatching { Instant.parse(o.getString("created_at")) }.getOrDefault(Instant.EPOCH),
            lastUsedAt = runCatching { Instant.parse(o.getString("last_used_at")) }.getOrDefault(Instant.EPOCH),
            lastKnownHandle = o.optString("last_known_handle").takeIf(String::isNotBlank),
            legacy = o.optBoolean("legacy", false)
        )
    }
}

class AccountRegistry(private val context: Context) {
    private val launcherRoot = File(context.noBackupFilesDir, "authentiverse/launcher").apply { mkdirs() }
    private val accountsRoot = File(context.noBackupFilesDir, "authentiverse/accounts").apply { mkdirs() }
    private val registryFile = File(launcherRoot, "accounts.json")

    @Synchronized
    fun load(): List<AuthentiverseAccount> {
        val accounts = readRegistry().toMutableList()
        ensureLegacyRegistration(accounts)
        discoverLocalAccounts(accounts)
        writeRegistry(accounts)
        return accounts.sortedByDescending { it.lastUsedAt }
    }

    @Synchronized
    fun create(displayName: String): AuthentiverseAccount {
        val clean = displayName.trim().take(80).ifBlank { "Authentiverse account" }
        val id = UUID.randomUUID().toString().replace("-", "").lowercase().take(24)
        val now = Instant.now()
        val account = AuthentiverseAccount(id, clean, "acct_$id", now, now)
        accountDirectory(account).mkdirs()
        writeAccountMetadata(account)
        val list = readRegistry().filterNot { it.id == id }.toMutableList().apply { add(account) }
        writeRegistry(list)
        return account
    }

    @Synchronized
    fun markUsed(accountId: String, handle: String? = null) {
        val list = load().toMutableList()
        val account = list.firstOrNull { it.id == accountId } ?: return
        account.lastUsedAt = Instant.now()
        if (!handle.isNullOrBlank()) account.lastKnownHandle = handle.trim().removePrefix("@").take(80)
        writeAccountMetadata(account)
        writeRegistry(list)
    }

    @Synchronized
    fun rename(accountId: String, displayName: String) {
        val list = load().toMutableList()
        val account = list.firstOrNull { it.id == accountId } ?: return
        account.displayName = displayName.trim().take(80).ifBlank { account.displayName }
        writeAccountMetadata(account)
        writeRegistry(list)
    }

    /** Removes only the launcher registration. Account data remains reloadable on this device. */
    @Synchronized
    fun removeRegistration(accountId: String) {
        writeRegistry(readRegistry().filterNot { it.id == accountId })
    }

    @Synchronized
    fun reloadableAccounts(): List<AuthentiverseAccount> {
        val registered = readRegistry().map { it.id }.toSet()
        return accountsRoot.listFiles().orEmpty().filter(File::isDirectory).mapNotNull(::readAccountMetadata)
            .filterNot { it.id in registered }
            .sortedByDescending { it.lastUsedAt }
    }

    @Synchronized
    fun loadExisting(accountId: String): AuthentiverseAccount {
        val account = reloadableAccounts().firstOrNull { it.id == accountId }
            ?: throw IllegalArgumentException("That local Authentiverse account is not available.")
        val list = readRegistry().toMutableList().apply { add(account) }
        writeRegistry(list)
        return account
    }

    fun accountDirectory(account: AuthentiverseAccount): File =
        if (account.legacy) context.noBackupFilesDir else File(accountsRoot, account.namespace)

    private fun ensureLegacyRegistration(accounts: MutableList<AuthentiverseAccount>) {
        if (accounts.any { it.legacy }) return
        val legacySecure = File(context.noBackupFilesDir, "secure/application-state.dss")
        val legacyVault = File(context.noBackupFilesDir, "information-vault")
        if (!legacySecure.exists() && !legacyVault.exists()) return
        val legacy = AuthentiverseAccount(
            id = "legacy",
            displayName = "Authentiverse",
            namespace = SecureStore.LEGACY_NAMESPACE,
            createdAt = Instant.EPOCH,
            lastUsedAt = Instant.now(),
            legacy = true
        )
        accounts += legacy
    }

    private fun discoverLocalAccounts(accounts: MutableList<AuthentiverseAccount>) {
        val known = accounts.map { it.id }.toMutableSet()
        accountsRoot.listFiles().orEmpty().filter(File::isDirectory).forEach { directory ->
            val found = readAccountMetadata(directory) ?: return@forEach
            if (known.add(found.id)) accounts += found
        }
    }

    private fun readRegistry(): List<AuthentiverseAccount> = runCatching {
        if (!registryFile.exists()) return@runCatching emptyList()
        val root = JSONObject(registryFile.readText())
        require(root.optString("format") == "authentiverse-account-registry-v1")
        val array = root.optJSONArray("accounts") ?: JSONArray()
        (0 until array.length()).map { AuthentiverseAccount.fromJson(array.getJSONObject(it)) }
    }.getOrDefault(emptyList())

    private fun writeRegistry(accounts: List<AuthentiverseAccount>) {
        val unique = accounts.distinctBy { it.id }
        val root = JSONObject().put("format", "authentiverse-account-registry-v1")
            .put("accounts", JSONArray(unique.map { it.toJson() }))
        atomicWrite(registryFile, root.toString(2))
    }

    private fun writeAccountMetadata(account: AuthentiverseAccount) {
        if (account.legacy) return
        val directory = accountDirectory(account).apply { mkdirs() }
        atomicWrite(File(directory, "authentiverse-account.json"), account.toJson().toString(2))
    }

    private fun readAccountMetadata(directory: File): AuthentiverseAccount? = runCatching {
        val file = File(directory, "authentiverse-account.json")
        if (!file.exists()) return@runCatching null
        val account = AuthentiverseAccount.fromJson(JSONObject(file.readText()))
        require(account.namespace == directory.name)
        account
    }.getOrNull()

    private fun atomicWrite(target: File, value: String) {
        target.parentFile?.mkdirs()
        val temp = File(target.parentFile, target.name + ".tmp")
        temp.writeText(value)
        if (!temp.renameTo(target)) {
            target.delete()
            check(temp.renameTo(target)) { "Could not persist the Authentiverse account registry." }
        }
    }
}
