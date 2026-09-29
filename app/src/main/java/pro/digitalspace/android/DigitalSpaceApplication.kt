/* SPDX-License-Identifier: MIT */
package pro.digitalspace.android

import android.app.Application
import pro.digitalspace.android.account.AccountRegistry
import pro.digitalspace.android.account.AuthentiverseAccount
import pro.digitalspace.android.chat.ChatService
import pro.digitalspace.android.chat.ChatStore
import pro.digitalspace.android.chat.HybridChatCrypto
import pro.digitalspace.android.data.ExchangeService
import pro.digitalspace.android.data.InformationStore
import pro.digitalspace.android.idqa.IdqaStore
import pro.digitalspace.android.idqa.IdqaTrustService
import pro.digitalspace.android.network.ControlPlaneClient
import pro.digitalspace.android.passwords.PasswordCredentialShareService
import pro.digitalspace.android.passwords.PasswordVaultStore
import pro.digitalspace.android.privacy.PrivateAttributeWallet
import pro.digitalspace.android.repository.DigitalSpaceRepository
import pro.digitalspace.android.security.IdentityKeyStore
import pro.digitalspace.android.security.PostQuantumIdentityKeyStore
import pro.digitalspace.android.security.SecureStore
import pro.digitalspace.android.security.VaultSession
import pro.digitalspace.android.tunnel.DigitalSpaceTunnelManager

/**
 * Authentiverse process root. The historical class/package name is retained so
 * an upgrade does not break Android component/state references. Product-facing
 * identity is Authentiverse and new accounts use isolated Authentiverse stores.
 */
class DigitalSpaceApplication : Application() {
    data class ActiveServices(
        val account: AuthentiverseAccount,
        val secure: SecureStore,
        val vault: VaultSession,
        val keys: IdentityKeyStore,
        val pq: PostQuantumIdentityKeyStore,
        val information: InformationStore,
        val exchange: ExchangeService,
        val privacy: PrivateAttributeWallet,
        val client: ControlPlaneClient,
        val chat: ChatService,
        val passwords: PasswordVaultStore,
        val passwordShares: PasswordCredentialShareService,
        val idqa: IdqaStore,
        val repository: DigitalSpaceRepository
    )

    lateinit var accounts: AccountRegistry
        private set
    @Volatile var active: ActiveServices? = null
        private set

    val repository: DigitalSpaceRepository get() = requireNotNull(active) { "Unlock an Authentiverse account first." }.repository
    val vaultSession: VaultSession get() = requireNotNull(active).vault
    val chat: ChatService get() = requireNotNull(active).chat
    val passwords: PasswordVaultStore get() = requireNotNull(active).passwords
    val passwordShares: PasswordCredentialShareService get() = requireNotNull(active).passwordShares
    val idqa: IdqaStore get() = requireNotNull(active).idqa

    override fun onCreate() {
        super.onCreate()
        accounts = AccountRegistry(this)
    }

    @Synchronized
    fun createAccount(displayName: String, pin: String): ActiveServices {
        val account = accounts.create(displayName)
        return activate(account, pin, allowPinSetup = true)
    }

    @Synchronized
    fun unlockAccount(account: AuthentiverseAccount, pin: String): ActiveServices =
        activate(account, pin, allowPinSetup = !VaultSession(SecureStore(this, account.namespace)).hasPin)

    @Synchronized
    fun deactivate() {
        active?.vault?.lock()
        active = null
    }

    @Synchronized
    private fun activate(account: AuthentiverseAccount, pin: String, allowPinSetup: Boolean): ActiveServices {
        active?.vault?.lock()
        val secure = SecureStore(this, account.namespace)
        val vault = VaultSession(secure)
        if (!vault.hasPin) {
            require(allowPinSetup) { "This account has not established a Vault PIN." }
            vault.setup(pin)
        } else {
            require(vault.unlock(pin)) { "Incorrect Authentiverse PIN." }
        }

        val keys = IdentityKeyStore(secure)
        val pq = PostQuantumIdentityKeyStore(vault)
        val information = InformationStore(this, secure, vault, keys)
        val exchange = ExchangeService(this, information, keys, pq)
        val privacy = PrivateAttributeWallet(secure, vault)
        val client = ControlPlaneClient(secure, keys)
        val passwords = PasswordVaultStore(secure, vault)
        val passwordShares = PasswordCredentialShareService(passwords, information, exchange, keys)
        val chat = ChatService(information, exchange, HybridChatCrypto(keys, pq), ChatStore(vault), client)
        val pins = BuildConfig.IDQA_CORE_ROOT_SHA256.split(';').map(String::trim).filter(String::isNotBlank).toSet()
        val idqa = IdqaStore(vault, IdqaTrustService(pins))
        val repository = DigitalSpaceRepository(this, secure, keys, client, DigitalSpaceTunnelManager(this),
            information, exchange, privacy, chat)
        val services = ActiveServices(account, secure, vault, keys, pq, information, exchange, privacy, client,
            chat, passwords, passwordShares, idqa, repository)
        active = services
        accounts.markUsed(account.id, repository.snapshot.value.persistent.profileHandle)
        return services
    }
}
