/* SPDX-License-Identifier: MIT */
package pro.digitalspace.android.security

import android.os.SystemClock
import android.util.Base64
import org.json.JSONObject
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * PIN-gated, account-local Authentiverse Vault session.
 *
 * Android Keystore protects the on-device envelope. The user PIN independently
 * derives the key that unwraps a random 256-bit VMK. Vault data is then sealed
 * again under domain-separated VMK-derived keys, so selecting an account is not
 * sufficient to read Vault/Inbox/Password material.
 */
class VaultSession(private val secure: SecureStore) {
    companion object {
        private const val CONFIG = "vault-config-v1"
        private const val CONFIG_FORMAT = "authentiverse-vault-pin-v1"
        private const val ITERATIONS = 310_000
        private const val MIN_PIN = 6
        private const val MAX_PIN = 12
        private val random = SecureRandom()
    }

    @Volatile private var vmk: ByteArray? = null
    @Volatile private var lastActivityElapsed = 0L
    @Volatile var autoLockMinutes: Int = 10
        private set

    val hasPin: Boolean get() = secure.exists(CONFIG)

    val isUnlocked: Boolean
        get() {
            enforceTimeout()
            return vmk != null
        }

    @Synchronized
    fun setup(pin: String, autoLockMinutes: Int = 10) {
        require(!hasPin) { "This account already has a Vault PIN." }
        validatePin(pin)
        val generated = ByteArray(32).also(random::nextBytes)
        try {
            writeConfig(pin, generated, autoLockMinutes)
            setUnlocked(generated.copyOf(), autoLockMinutes)
        } finally {
            generated.fill(0)
        }
    }

    @Synchronized
    fun unlock(pin: String): Boolean {
        validatePin(pin)
        val clear = secure.get(CONFIG) ?: return false
        try {
            val root = JSONObject(clear.decodeToString())
            require(root.getString("format") == CONFIG_FORMAT) { "The Vault PIN record is not supported." }
            val salt = b64d(root.getString("salt"))
            val nonce = b64d(root.getString("nonce"))
            val wrapped = b64d(root.getString("wrapped_vmk"))
            val iterations = root.optInt("iterations", ITERATIONS).coerceIn(100_000, 2_000_000)
            val key = derivePinKey(pin, salt, iterations)
            return try {
                val unwrapped = Cipher.getInstance("AES/GCM/NoPadding").run {
                    init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
                    updateAAD((CONFIG_FORMAT + ":" + secure.namespace).encodeToByteArray())
                    doFinal(wrapped)
                }
                require(unwrapped.size == 32)
                setUnlocked(unwrapped, root.optInt("auto_lock_minutes", 10))
                true
            } catch (_: Exception) {
                false
            } finally {
                key.fill(0); salt.fill(0); nonce.fill(0); wrapped.fill(0)
            }
        } finally {
            clear.fill(0)
        }
    }

    @Synchronized
    fun changePin(oldPin: String, newPin: String) {
        require(unlock(oldPin)) { "The current Vault PIN is incorrect." }
        validatePin(newPin)
        val key = requireUnlockedCopy()
        try { writeConfig(newPin, key, autoLockMinutes) } finally { key.fill(0) }
        touch()
    }

    @Synchronized
    fun setAutoLock(minutes: Int) {
        require(minutes == 0 || minutes in 1..120) { "Auto-lock must be 1–120 minutes, or 0 for until app closes." }
        val configBytes = secure.get(CONFIG) ?: throw IllegalStateException("Set a Vault PIN first.")
        try {
            val root = JSONObject(configBytes.decodeToString())
            root.put("auto_lock_minutes", minutes)
            secure.put(CONFIG, root.toString().encodeToByteArray())
            autoLockMinutes = minutes
        } finally { configBytes.fill(0) }
        touch()
    }

    @Synchronized
    fun lock() {
        vmk?.fill(0)
        vmk = null
        lastActivityElapsed = 0L
    }

    fun touch() {
        if (vmk != null) lastActivityElapsed = SystemClock.elapsedRealtime()
    }

    @Synchronized
    fun put(name: String, clear: ByteArray) {
        val domain = derivedKey("Authentiverse/Vault/Data/$name/v1")
        val nonce = ByteArray(12).also(random::nextBytes)
        try {
            val ciphertext = Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.ENCRYPT_MODE, SecretKeySpec(domain, "AES"), GCMParameterSpec(128, nonce))
                updateAAD(("AVV01:" + secure.namespace + ":" + name).encodeToByteArray())
                doFinal(clear)
            }
            secure.put("vault-$name", "AVV01".encodeToByteArray() + nonce + ciphertext)
            ciphertext.fill(0)
            touch()
        } finally { domain.fill(0); nonce.fill(0) }
    }

    @Synchronized
    fun get(name: String): ByteArray? {
        val packed = secure.get("vault-$name") ?: return null
        val domain = derivedKey("Authentiverse/Vault/Data/$name/v1")
        try {
            require(packed.size >= 5 + 12 + 16 && packed.copyOfRange(0, 5).decodeToString() == "AVV01") {
                "The Vault record is malformed."
            }
            val nonce = packed.copyOfRange(5, 17)
            val clear = Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.DECRYPT_MODE, SecretKeySpec(domain, "AES"), GCMParameterSpec(128, nonce))
                updateAAD(("AVV01:" + secure.namespace + ":" + name).encodeToByteArray())
                doFinal(packed, 17, packed.size - 17)
            }
            touch()
            return clear
        } finally { packed.fill(0); domain.fill(0) }
    }

    fun exists(name: String): Boolean = secure.exists("vault-$name")
    fun delete(name: String) = secure.delete("vault-$name")

    /** Returns a caller-owned domain key that must be zeroed after use. */
    fun derivedKey(context: String, length: Int = 32): ByteArray {
        require(length in 16..64)
        val master = requireUnlockedCopy()
        return try { hkdfSha512(master, context.encodeToByteArray(), length) } finally { master.fill(0) }
    }

    private fun enforceTimeout() {
        val value = vmk ?: return
        if (autoLockMinutes <= 0 || lastActivityElapsed <= 0L) return
        val timeout = autoLockMinutes * 60_000L
        if (SystemClock.elapsedRealtime() - lastActivityElapsed >= timeout) {
            synchronized(this) {
                if (vmk === value) lock()
            }
        }
    }

    private fun requireUnlockedCopy(): ByteArray {
        enforceTimeout()
        val value = vmk ?: throw IllegalStateException("Unlock Vault to continue.")
        touch()
        return value.copyOf()
    }

    private fun setUnlocked(value: ByteArray, minutes: Int) {
        lock()
        vmk = value
        autoLockMinutes = if (minutes == 0) 0 else minutes.coerceIn(1, 120)
        lastActivityElapsed = SystemClock.elapsedRealtime()
    }

    private fun writeConfig(pin: String, master: ByteArray, minutes: Int) {
        val salt = ByteArray(16).also(random::nextBytes)
        val nonce = ByteArray(12).also(random::nextBytes)
        val key = derivePinKey(pin, salt, ITERATIONS)
        try {
            val wrapped = Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
                updateAAD((CONFIG_FORMAT + ":" + secure.namespace).encodeToByteArray())
                doFinal(master)
            }
            val root = JSONObject()
                .put("format", CONFIG_FORMAT)
                .put("iterations", ITERATIONS)
                .put("salt", b64(salt))
                .put("nonce", b64(nonce))
                .put("wrapped_vmk", b64(wrapped))
                .put("auto_lock_minutes", if (minutes == 0) 0 else minutes.coerceIn(1, 120))
            secure.put(CONFIG, root.toString().encodeToByteArray())
            wrapped.fill(0)
        } finally { salt.fill(0); nonce.fill(0); key.fill(0) }
    }

    private fun validatePin(pin: String) {
        require(pin.length in MIN_PIN..MAX_PIN && pin.all(Char::isDigit)) { "Use a 6–12 digit Vault PIN." }
    }

    private fun derivePinKey(pin: String, salt: ByteArray, iterations: Int): ByteArray {
        val chars = pin.toCharArray()
        return try {
            val spec = PBEKeySpec(chars, salt, iterations, 256)
            try { SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded }
            finally { spec.clearPassword() }
        } finally { chars.fill('\u0000') }
    }

    private fun hkdfSha512(ikm: ByteArray, info: ByteArray, length: Int): ByteArray {
        val salt = ByteArray(64)
        val extract = Mac.getInstance("HmacSHA512")
        extract.init(SecretKeySpec(salt, "HmacSHA512"))
        val prk = extract.doFinal(ikm)
        try {
            val result = ByteArray(length)
            var previous = ByteArray(0)
            var offset = 0
            var counter = 1
            while (offset < length) {
                val mac = Mac.getInstance("HmacSHA512")
                mac.init(SecretKeySpec(prk, "HmacSHA512"))
                mac.update(previous)
                mac.update(info)
                mac.update(counter.toByte())
                val block = mac.doFinal()
                previous.fill(0)
                previous = block
                val copy = minOf(block.size, length - offset)
                block.copyInto(result, offset, 0, copy)
                offset += copy
                counter++
            }
            previous.fill(0)
            return result
        } finally { prk.fill(0); salt.fill(0) }
    }

    private fun b64(value: ByteArray) = Base64.encodeToString(value, Base64.NO_WRAP)
    private fun b64d(value: String) = Base64.decode(value, Base64.DEFAULT)
}
