/* SPDX-License-Identifier: MIT */
package pro.digitalspace.android.idqa

import org.json.JSONArray
import org.json.JSONObject
import java.time.Instant

enum class IdqaSubjectKind { Person, DevOps }
enum class IdqaAuthorityRole { RootInstitute, AttestationInstitute, AttestationOffice, AttestationOfficer }

data class IdqaScores(val values: List<Int>) {
    init { require(values.size == 8 && values.all { it in 0..9 }) }
    val total: Int get() = values.sum()
    fun toJson() = JSONObject()
        .put("1_degree_of_protection_of_personal_assets", values[0]).put("2_quality_of_enrollment_practices", values[1])
        .put("3_quality_of_means_of_assertion", values[2]).put("4_quality_of_authoritative_attestation", values[3])
        .put("5_self_sovereign_eoi_and_attestation_from_others", values[4]).put("6_quality_of_the_credential", values[5])
        .put("7_quality_of_assumption_of_liability", values[6]).put("8_reputation_of_the_credential", values[7]).put("total_idqa", total)
    companion object { fun fromJson(o:JSONObject)=IdqaScores(listOf(o.getInt("1_degree_of_protection_of_personal_assets"),o.getInt("2_quality_of_enrollment_practices"),o.getInt("3_quality_of_means_of_assertion"),o.getInt("4_quality_of_authoritative_attestation"),o.getInt("5_self_sovereign_eoi_and_attestation_from_others"),o.getInt("6_quality_of_the_credential"),o.getInt("7_quality_of_assumption_of_liability"),o.getInt("8_reputation_of_the_credential"))) }
}

data class IdqaAttestation(val format:String="authenticity-idqa-attestation-v1",val attestationId:String,val methodologyVersion:String,
    val subjectProfileId:String,val subjectCertificateSha256:String,val subjectKind:IdqaSubjectKind,val scores:IdqaScores,val evidenceDigestSha256:String,
    val assessmentPolicyId:String,val issuedAt:Instant,val expiresAt:Instant,val officerCertificate:String,val authorityChain:List<String>,val signature:String){
    fun toJson()=JSONObject().put("format",format).put("attestation_id",attestationId).put("methodology_version",methodologyVersion).put("subject_profile_id",subjectProfileId)
        .put("subject_certificate_sha256",subjectCertificateSha256).put("subject_kind",subjectKind.name).put("scores",scores.toJson()).put("evidence_digest_sha256",evidenceDigestSha256)
        .put("assessment_policy_id",assessmentPolicyId).put("issued_at",issuedAt.toString()).put("expires_at",expiresAt.toString()).put("officer_certificate",officerCertificate)
        .put("authority_chain",JSONArray(authorityChain)).put("signature",signature)
    companion object{fun fromJson(o:JSONObject):IdqaAttestation{val c=o.optJSONArray("authority_chain")?:JSONArray();return IdqaAttestation(o.optString("format","authenticity-idqa-attestation-v1"),o.getString("attestation_id"),o.getString("methodology_version"),o.getString("subject_profile_id"),o.getString("subject_certificate_sha256"),IdqaSubjectKind.valueOf(o.getString("subject_kind")),IdqaScores.fromJson(o.getJSONObject("scores")),o.getString("evidence_digest_sha256"),o.getString("assessment_policy_id"),Instant.parse(o.getString("issued_at")),Instant.parse(o.getString("expires_at")),o.getString("officer_certificate"),(0 until c.length()).map{c.getString(it)},o.getString("signature"))}}
}

data class IdqaTrustBundleApproval(val rootCertificate:String,val signature:String){companion object{fun fromJson(o:JSONObject)=IdqaTrustBundleApproval(o.getString("root_certificate"),o.getString("signature"))}}
data class IdqaTrustBundle(val format:String,val sequence:Long,val issuedAt:Instant,val expiresAt:Instant,val trustedRoots:List<String>,val revokedCertificateSerials:List<String>,val revokedAttestationIds:List<String>,val approvals:List<IdqaTrustBundleApproval>){
    companion object{fun fromJson(o:JSONObject):IdqaTrustBundle{fun arr(n:String):List<String>{val a=o.optJSONArray(n)?:JSONArray();return(0 until a.length()).map{a.getString(it)}};val ap=o.optJSONArray("approvals")?:JSONArray();return IdqaTrustBundle(o.optString("format"),o.getLong("sequence"),Instant.parse(o.getString("issued_at")),Instant.parse(o.getString("expires_at")),arr("trusted_roots"),arr("revoked_certificate_serials"),arr("revoked_attestation_ids"),(0 until ap.length()).map{IdqaTrustBundleApproval.fromJson(ap.getJSONObject(it))})}}
}

data class IdqaValidationResult(val isValid:Boolean,val status:String,val trustBundleSequence:Long,val officerName:String,val officeName:String,val instituteName:String,val rootInstituteName:String,val chainSummary:String)
data class IdqaStoredState(val attestation:IdqaAttestation?,val validation:IdqaValidationResult?,val highestBundleSequence:Long,val processedIds:List<String>)
