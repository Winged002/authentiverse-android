/* SPDX-License-Identifier: MIT */
package pro.digitalspace.android.privacy

import org.json.JSONArray
import org.json.JSONObject
import pro.digitalspace.android.security.SecureStore
import pro.digitalspace.android.security.VaultSession
import java.time.LocalDate
import java.time.Period

data class PrivateAttributeRecord(
    val dateOfBirth: String? = null,
    val gender: String? = null,
    val credentials: List<JSONObject> = emptyList()
) {
    fun toJson() = JSONObject().apply {
        put("schema_version", 1)
        putOpt("date_of_birth", dateOfBirth)
        putOpt("gender", gender)
        put("credentials", JSONArray(credentials))
    }

    companion object {
        fun fromJson(value: JSONObject): PrivateAttributeRecord {
            require(value.optInt("schema_version", 1) == 1) { "The privacy wallet uses an unsupported format." }
            val credentials = value.optJSONArray("credentials") ?: JSONArray()
            return PrivateAttributeRecord(
                value.optString("date_of_birth").takeIf(String::isNotBlank),
                value.optString("gender").takeIf(String::isNotBlank),
                (0 until credentials.length()).map { credentials.getJSONObject(it) }
            )
        }
    }
}

data class PredicatePolicy(val id: String, val description: String, val evidence: String, val highlySensitive: Boolean = false)

/** Holder-only attributes protected by the PIN-gated Authentiverse Vault. */
class PrivateAttributeWallet(private val secure: SecureStore, private val vault: VaultSession) {
    companion object {
        val policies = listOf(
            PredicatePolicy("age_over_18", "You are at least 18 years old", "date_of_birth"),
            PredicatePolicy("age_over_21", "You are at least 21 years old", "date_of_birth"),
            PredicatePolicy("gender_woman", "Your private gender value is Woman", "gender", true),
            PredicatePolicy("gender_man", "Your private gender value is Man", "gender", true),
            PredicatePolicy("gender_nonbinary", "Your private gender value is Non-binary", "gender", true)
        )
    }

    @Synchronized fun load(): PrivateAttributeRecord {
        vault.get("private-attributes")?.let { clear ->
            try { return PrivateAttributeRecord.fromJson(JSONObject(clear.decodeToString())) } finally { clear.fill(0) }
        }
        secure.get("private-attributes")?.let { legacy ->
            try {
                val record = PrivateAttributeRecord.fromJson(JSONObject(legacy.decodeToString()))
                val encoded = record.toJson().toString().encodeToByteArray()
                try { vault.put("private-attributes", encoded) } finally { encoded.fill(0) }
                secure.delete("private-attributes")
                return record
            } finally { legacy.fill(0) }
        }
        return PrivateAttributeRecord()
    }

    @Synchronized fun save(dateOfBirth: String?, gender: String?) {
        // Changing source data invalidates all previously derived credentials.
        val record = PrivateAttributeRecord(normalizeDate(dateOfBirth), normalizeGender(gender), emptyList())
        val encoded = record.toJson().toString().encodeToByteArray()
        try { vault.put("private-attributes", encoded) } finally { encoded.fill(0) }
    }

    @Synchronized fun clear() { vault.delete("private-attributes"); secure.delete("private-attributes") }

    fun evaluate(predicateId: String, today: LocalDate = LocalDate.now()): Boolean {
        val record = load()
        return when (requirePolicy(predicateId).id) {
            "age_over_18" -> age(record.dateOfBirth, today) >= 18
            "age_over_21" -> age(record.dateOfBirth, today) >= 21
            "gender_woman" -> record.gender == "woman"
            "gender_man" -> record.gender == "man"
            "gender_nonbinary" -> record.gender == "nonbinary"
            else -> error("The predicate evaluator is not implemented.")
        }
    }


    @Synchronized fun storeCredential(credential: JSONObject) {
        val current = load()
        val id = credential.optString("credential_id")
        val kept = current.credentials.filterNot { it.optString("credential_id") == id ||
            (it.optString("profile_id") == credential.optString("profile_id") && it.optString("predicate_id") == credential.optString("predicate_id")) }
        val record = current.copy(credentials = kept + JSONObject(credential.toString()))
        val encoded = record.toJson().toString().encodeToByteArray()
        try { vault.put("private-attributes", encoded) } finally { encoded.fill(0) }
    }

    fun evidenceFor(predicateId: String): Map<String, String> {
        val record = load()
        return when (requirePolicy(predicateId).evidence) {
            "date_of_birth" -> mapOf("date_of_birth" to requireNotNull(record.dateOfBirth) { "A date of birth has not been stored." })
            "gender" -> mapOf("gender" to requireNotNull(record.gender) { "A private gender value has not been stored." })
            else -> error("The private evidence selector is not implemented.")
        }
    }

    fun requirePolicy(id: String) = policies.firstOrNull { it.id == id }
        ?: throw IllegalArgumentException("The application requested a predicate that Authentiverse does not allow.")

    private fun normalizeDate(raw: String?): String? {
        if (raw.isNullOrBlank()) return null
        val value = runCatching { LocalDate.parse(raw.trim()) }.getOrNull()
            ?: throw IllegalArgumentException("Use YYYY-MM-DD for the private date of birth.")
        val today = LocalDate.now()
        require(!value.isAfter(today) && !value.isBefore(today.minusYears(130))) { "The private date of birth is invalid." }
        return value.toString()
    }

    private fun normalizeGender(raw: String?): String? {
        if (raw.isNullOrBlank()) return null
        return when (raw.trim().lowercase().replace("-", "").replace(" ", "")) {
            "woman" -> "woman"
            "man" -> "man"
            "nonbinary" -> "nonbinary"
            "other" -> "other"
            else -> throw IllegalArgumentException("The private gender value is invalid.")
        }
    }

    private fun age(raw: String?, today: LocalDate): Int {
        val date = raw?.let(LocalDate::parse) ?: throw IllegalStateException("A date of birth has not been stored.")
        return Period.between(date, today).years
    }
}
