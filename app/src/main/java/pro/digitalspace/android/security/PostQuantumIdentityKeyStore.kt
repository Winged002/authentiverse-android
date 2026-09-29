/* SPDX-License-Identifier: MIT */
package pro.digitalspace.android.security

import org.bouncycastle.crypto.params.ParametersWithRandom
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyGenerationParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyPairGenerator
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner
import org.json.JSONObject
import java.security.SecureRandom

/**
 * Account-local ML-KEM-1024 / ML-DSA-87 identity used by Authentiverse private
 * communications. Seeds are held only inside the PIN-gated Vault envelope.
 * Android Keystore cannot currently generate these PQ algorithms directly, so
 * this is deliberately described as Vault-protected, not hardware-backed.
 */
@Suppress("DEPRECATION")
class PostQuantumIdentityKeyStore(private val vault: VaultSession) {
    data class PublicMaterial(val kemPublicKey: String, val signingPublicKey: String)
    data class Encapsulation(val ciphertext: ByteArray, val sharedSecret: ByteArray)

    companion object {
        const val KEM = "ML-KEM-1024"
        const val SIGNATURE = "ML-DSA-87"
        private const val STORE = "pq-identity-v1"
        private const val FORMAT = "authentiverse-pq-identity-v1"
        private const val KEM_SEED_BYTES = 64
        private const val DSA_SEED_BYTES = 32
        private val random = SecureRandom()

        fun verify(publicKeyB64: String, payload: ByteArray, signatureB64: String): Boolean = runCatching {
            val publicKey = MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_87, DigitalSpaceCrypto.unb64(publicKeyB64))
            val signer = MLDSASigner()
            signer.init(false, publicKey)
            signer.update(payload, 0, payload.size)
            signer.verifySignature(DigitalSpaceCrypto.unb64(signatureB64))
        }.getOrDefault(false)
    }

    @Synchronized
    fun publicMaterial(): PublicMaterial {
        val seeds = loadOrCreate()
        try {
            val kem = MLKEMPrivateKeyParameters(MLKEMParameters.ml_kem_1024, seeds.first)
            val dsa = MLDSAPrivateKeyParameters(MLDSAParameters.ml_dsa_87, seeds.second)
            return PublicMaterial(
                DigitalSpaceCrypto.b64(kem.publicKey),
                DigitalSpaceCrypto.b64(dsa.publicKey)
            )
        } finally { seeds.first.fill(0); seeds.second.fill(0) }
    }

    fun encapsulate(recipientPublicKeyB64: String): Encapsulation {
        val publicKey = MLKEMPublicKeyParameters(MLKEMParameters.ml_kem_1024, DigitalSpaceCrypto.unb64(recipientPublicKeyB64))
        val secret = MLKEMGenerator(random).generateEncapsulated(publicKey)
        return try { Encapsulation(secret.encapsulation.copyOf(), secret.secret.copyOf()) }
        finally { secret.destroy() }
    }

    @Synchronized
    fun decapsulate(ciphertextB64: String): ByteArray {
        val seeds = loadOrCreate()
        val ciphertext = DigitalSpaceCrypto.unb64(ciphertextB64)
        return try {
            MLKEMExtractor(MLKEMPrivateKeyParameters(MLKEMParameters.ml_kem_1024, seeds.first)).extractSecret(ciphertext)
        } finally { seeds.first.fill(0); seeds.second.fill(0); ciphertext.fill(0) }
    }

    @Synchronized
    fun sign(payload: ByteArray): String {
        val seeds = loadOrCreate()
        return try {
            val privateKey = MLDSAPrivateKeyParameters(MLDSAParameters.ml_dsa_87, seeds.second)
            val signer = MLDSASigner()
            signer.init(true, ParametersWithRandom(privateKey, random))
            signer.update(payload, 0, payload.size)
            DigitalSpaceCrypto.b64(signer.generateSignature())
        } finally { seeds.first.fill(0); seeds.second.fill(0) }
    }

    @Synchronized
    private fun loadOrCreate(): Pair<ByteArray, ByteArray> {
        val existing = vault.get(STORE)
        if (existing != null) {
            try {
                val root = JSONObject(existing.decodeToString())
                require(root.getString("format") == FORMAT) { "The post-quantum identity record is unsupported." }
                var kem = DigitalSpaceCrypto.unb64(root.getString("kem_seed"))
                val dsa = DigitalSpaceCrypto.unb64(root.getString("dsa_seed"))
                require(dsa.size == DSA_SEED_BYTES) { "The ML-DSA-87 identity seed is invalid." }
                if (kem.size == 32) {
                    // Repair the unusable v1.3.1-r2 seed shape in the same way as the Windows client.
                    kem.fill(0)
                    kem = DigitalSpaceCrypto.random(KEM_SEED_BYTES)
                    persist(kem, dsa)
                }
                require(kem.size == KEM_SEED_BYTES) { "The ML-KEM-1024 identity seed is invalid." }
                return kem to dsa
            } finally { existing.fill(0) }
        }

        // Generate through the implementation so seed format is provider-canonical.
        val kemGenerator = MLKEMKeyPairGenerator().apply {
            init(MLKEMKeyGenerationParameters(random, MLKEMParameters.ml_kem_1024))
        }
        val dsaGenerator = MLDSAKeyPairGenerator().apply {
            init(MLDSAKeyGenerationParameters(random, MLDSAParameters.ml_dsa_87))
        }
        val kemPrivate = kemGenerator.generateKeyPair().private as MLKEMPrivateKeyParameters
        val dsaPrivate = dsaGenerator.generateKeyPair().private as MLDSAPrivateKeyParameters
        val kem = requireNotNull(kemPrivate.seed) { "ML-KEM seed generation failed." }
        val dsa = requireNotNull(dsaPrivate.seed) { "ML-DSA seed generation failed." }
        require(kem.size == KEM_SEED_BYTES && dsa.size == DSA_SEED_BYTES)
        persist(kem, dsa)
        return kem to dsa
    }

    private fun persist(kem: ByteArray, dsa: ByteArray) {
        val clear = JSONObject()
            .put("format", FORMAT)
            .put("kem_seed", DigitalSpaceCrypto.b64(kem))
            .put("dsa_seed", DigitalSpaceCrypto.b64(dsa))
            .toString().encodeToByteArray()
        try { vault.put(STORE, clear) } finally { clear.fill(0) }
    }
}
