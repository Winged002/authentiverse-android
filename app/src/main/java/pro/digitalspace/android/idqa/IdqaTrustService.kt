/* SPDX-License-Identifier: MIT */
package pro.digitalspace.android.idqa

import pro.digitalspace.android.security.DigitalSpaceCrypto
import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.time.Duration
import java.time.Instant

class IdqaTrustService(private val coreRootPins:Set<String>,private val quorum:Int=1,private val maximumBundleLifetime:Duration=Duration.ofDays(14)){
    companion object{
        const val AUTHORITY_ROLE_OID="1.3.6.1.4.1.57264.1.1";const val ATTESTATION_SIGNING_EKU_OID="1.3.6.1.4.1.57264.1.2"
        fun normalizeFingerprint(v:String)=v.replace(":","").trim().uppercase().also{require(it.matches(Regex("[0-9A-F]{64}"))){"Invalid SHA-256 fingerprint."}}
        fun certificate(encoded:String):X509Certificate{val raw=DigitalSpaceCrypto.unb64(encoded);require(raw.size in 128..65536);return raw.useBytes{CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(it)) as X509Certificate}}
        fun certificateFingerprint(encoded:String)=DigitalSpaceCrypto.hex(DigitalSpaceCrypto.sha256(certificate(encoded).encoded))
        private inline fun <T> ByteArray.useBytes(block:(ByteArray)->T):T=try{block(this)}finally{fill(0)}
    }
    val configured:Boolean get()=coreRootPins.isNotEmpty()&&quorum in 1..16

    fun validateBundle(bundle:IdqaTrustBundle,now:Instant=Instant.now()){
        require(configured){"IDQA trust is not configured in this Authentiverse build."};require(bundle.format=="authenticity-idqa-trust-bundle-v1"&&bundle.sequence>=1)
        require(!bundle.issuedAt.isAfter(now.plusSeconds(300))&&bundle.expiresAt.isAfter(now)&&bundle.expiresAt.isAfter(bundle.issuedAt)&&Duration.between(bundle.issuedAt,bundle.expiresAt)<=maximumBundleLifetime)
        require(bundle.trustedRoots.size in 1..32);require(bundle.revokedAttestationIds.size<=100000&&bundle.revokedCertificateSerials.size<=100000)
        val payload=canonicalBundle(bundle);val approved=mutableSetOf<String>();try{bundle.approvals.forEach{approval->val root=certificate(approval.rootCertificate);val fp=DigitalSpaceCrypto.hex(DigitalSpaceCrypto.sha256(root.encoded));if(fp in coreRootPins&&approved.add(fp)){validateRoot(root,now);require(verify(root,payload,approval.signature)){"The IDQA trust-bundle approval signature is invalid."}}};require(approved.size>=quorum){"The IDQA trust bundle does not have the required core-institute approvals."}}finally{payload.fill(0)}
        val unique=mutableSetOf<String>();bundle.trustedRoots.forEach{encoded->val root=certificate(encoded);validateRoot(root,now);require(unique.add(DigitalSpaceCrypto.hex(DigitalSpaceCrypto.sha256(root.encoded)))){"The IDQA trust bundle contains a duplicate root."}}
    }

    fun validateAttestation(att:IdqaAttestation,expectedProfileId:String,subjectCertificate:X509Certificate,bundle:IdqaTrustBundle,now:Instant=Instant.now()):IdqaValidationResult{
        validateBundle(bundle,now);shape(att,expectedProfileId,subjectCertificate,now);require(att.attestationId !in bundle.revokedAttestationIds){"This IDQA attestation was revoked."}
        val officer=certificate(att.officerCertificate);val supplied=att.authorityChain.map(::certificate);val roots=bundle.trustedRoots.map(::certificate);val chain=buildChain(officer,supplied,roots,now)
        require(chain.size in 2..5);val descriptors=chain.map(::descriptor);require(descriptors.first().first==IdqaAuthorityRole.AttestationOfficer);require(descriptors.last().first==IdqaAuthorityRole.RootInstitute);require(scopeAllows(descriptors.first().second,att.subjectKind)){"This officer is not authorized for the IDQA subject category."}
        for(i in 0 until descriptors.lastIndex)require(canIssue(descriptors[i+1].first,descriptors[i].first)){"The IDQA certificate roles do not form an authorized delegation path."}
        val revoked=bundle.revokedCertificateSerials.map(::normalizeSerial).toSet();chain.forEach{require(normalizeSerial(it.serialNumber.toString(16)) !in revoked){"An IDQA authority certificate in this path was revoked."}}
        require(officer.basicConstraints<0);val usage=officer.keyUsage;require(usage!=null&&usage.isNotEmpty()&&usage[0]);require(officer.extendedKeyUsage?.contains(ATTESTATION_SIGNING_EKU_OID)==true){"The IDQA officer certificate lacks the attestation-signing purpose."}
        val payload=canonicalAttestation(att);try{require(verify(officer,payload,att.signature)){"The IDQA attestation signature is invalid."}}finally{payload.fill(0)}
        fun name(role:IdqaAuthorityRole)=chain.firstOrNull{descriptor(it).first==role}?.subjectX500Principal?.name.orEmpty()
        return IdqaValidationResult(true,"Valid",bundle.sequence,officer.subjectX500Principal.name,name(IdqaAuthorityRole.AttestationOffice),name(IdqaAuthorityRole.AttestationInstitute),name(IdqaAuthorityRole.RootInstitute),chain.joinToString(" → "){it.subjectX500Principal.name})
    }

    fun canonicalAttestation(v:IdqaAttestation)=listOf(v.format,v.attestationId,v.methodologyVersion,v.subjectProfileId,normalizeFingerprint(v.subjectCertificateSha256),if(v.subjectKind==IdqaSubjectKind.DevOps)"devops" else "person",*v.scores.values.map(Int::toString).toTypedArray(),v.scores.total.toString(),normalizeFingerprint(v.evidenceDigestSha256),v.assessmentPolicyId,v.issuedAt.epochSecond.toString(),v.expiresAt.epochSecond.toString(),certificateFingerprint(v.officerCertificate)).joinToString("\n").encodeToByteArray()
    fun canonicalBundle(v:IdqaTrustBundle)=listOf(v.format,v.sequence.toString(),v.issuedAt.epochSecond.toString(),v.expiresAt.epochSecond.toString(),v.trustedRoots.map(::certificateFingerprint).sorted().joinToString(","),v.revokedCertificateSerials.map(::normalizeSerial).sorted().joinToString(","),v.revokedAttestationIds.sorted().joinToString(",")).joinToString("\n").encodeToByteArray()

    private fun shape(v:IdqaAttestation,profile:String,cert:X509Certificate,now:Instant){require(v.format=="authenticity-idqa-attestation-v1");requireToken(v.attestationId,8,128);requireToken(v.methodologyVersion,1,64);requireToken(v.assessmentPolicyId,1,128);require(v.subjectProfileId==profile){"This IDQA attestation belongs to another profile."};require(normalizeFingerprint(v.subjectCertificateSha256)==DigitalSpaceCrypto.hex(DigitalSpaceCrypto.sha256(cert.encoded))){"This IDQA attestation is not bound to the active foundational certificate."};require(v.scores.total in 0..72);require(!v.issuedAt.isAfter(now.plusSeconds(300))&&v.expiresAt.isAfter(now)&&v.expiresAt.isAfter(v.issuedAt)&&Duration.between(v.issuedAt,v.expiresAt)<=Duration.ofDays(366));normalizeFingerprint(v.evidenceDigestSha256);require(v.authorityChain.size<=7);require(v.officerCertificate.isNotBlank()&&v.signature.isNotBlank())}
    private fun buildChain(leaf:X509Certificate,supplied:List<X509Certificate>,roots:List<X509Certificate>,now:Instant):List<X509Certificate>{val chain=mutableListOf<X509Certificate>();var current=leaf;val candidates=supplied+roots;repeat(5){current.checkValidity(java.util.Date.from(now));chain+=current;if(roots.any{it.encoded.contentEquals(current.encoded)}){current.verify(current.publicKey);return chain};val issuer=candidates.firstOrNull{it.subjectX500Principal==current.issuerX500Principal&&runCatching{current.verify(it.publicKey);true}.getOrDefault(false)}?:throw IllegalArgumentException("The IDQA certificate chain is invalid.");current=issuer};throw IllegalArgumentException("The IDQA certificate chain is too deep.")}
    private fun validateRoot(root:X509Certificate,now:Instant){root.checkValidity(java.util.Date.from(now));require(descriptor(root).first==IdqaAuthorityRole.RootInstitute);require(root.basicConstraints>=0);val usage=root.keyUsage;require(usage!=null&&usage.size>5&&usage[5]);require(root.subjectX500Principal==root.issuerX500Principal);root.verify(root.publicKey)}
    private fun descriptor(cert:X509Certificate):Pair<IdqaAuthorityRole,String>{val raw=cert.getExtensionValue(AUTHORITY_ROLE_OID)?:throw IllegalArgumentException("An IDQA authority certificate lacks its role constraint.");val text=String(unwrapOctet(raw),Charsets.UTF_8);val values=text.split(';').mapNotNull{val p=it.split('=',limit=2);if(p.size==2)p[0].trim().lowercase() to p[1].trim() else null}.toMap();val role=when(values["role"]?.lowercase()){ "root-institute"->IdqaAuthorityRole.RootInstitute;"attestation-institute"->IdqaAuthorityRole.AttestationInstitute;"attestation-office"->IdqaAuthorityRole.AttestationOffice;"attestation-officer"->IdqaAuthorityRole.AttestationOfficer;else->throw IllegalArgumentException("An IDQA authority role is unsupported.")};val scope=values["scope"].orEmpty();if(role==IdqaAuthorityRole.AttestationOfficer)require(scope.isNotBlank());return role to scope}
    private fun unwrapOctet(v:ByteArray):ByteArray{if(v.size<2||v[0].toInt()!=0x04)return v;var p=1;val first=v[p++].toInt() and 0xff;val len=if(first<128)first else{val n=first and 0x7f;var x=0;repeat(n){x=(x shl 8)or(v[p++].toInt()and 0xff)};x};require(p+len<=v.size);return v.copyOfRange(p,p+len)}
    private fun verify(cert:X509Certificate,payload:ByteArray,encoded:String):Boolean=runCatching{val sig=DigitalSpaceCrypto.unb64(encoded);try{if(Signature.getInstance("SHA256withECDSA").run{initVerify(cert.publicKey);update(payload);verify(sig)})true else DigitalSpaceCrypto.verifyP1363(cert.publicKey,payload,sig)}finally{sig.fill(0)}}.getOrDefault(false)
    private fun canIssue(issuer:IdqaAuthorityRole,subject:IdqaAuthorityRole)=when(issuer){IdqaAuthorityRole.RootInstitute->subject in setOf(IdqaAuthorityRole.AttestationInstitute,IdqaAuthorityRole.AttestationOffice,IdqaAuthorityRole.AttestationOfficer);IdqaAuthorityRole.AttestationInstitute->subject in setOf(IdqaAuthorityRole.AttestationOffice,IdqaAuthorityRole.AttestationOfficer);IdqaAuthorityRole.AttestationOffice->subject==IdqaAuthorityRole.AttestationOfficer;else->false}
    private fun scopeAllows(scope:String,kind:IdqaSubjectKind)=scope.split(',').map{it.trim().lowercase()}.any{it=="all"||it==(if(kind==IdqaSubjectKind.DevOps)"devops" else "person")}
    private fun normalizeSerial(v:String)=v.replace(":","").trimStart('0').uppercase().ifBlank{"0"}.also{require(it.matches(Regex("[0-9A-F]+")))}
    private fun requireToken(v:String,min:Int,max:Int)=require(v.length in min..max&&v.all{it.code in 0x21..0x7e})
}
