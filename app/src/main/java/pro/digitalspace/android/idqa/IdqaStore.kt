/* SPDX-License-Identifier: MIT */
package pro.digitalspace.android.idqa

import org.json.JSONArray
import org.json.JSONObject
import pro.digitalspace.android.model.PersistentState
import pro.digitalspace.android.security.DigitalSpaceCrypto
import pro.digitalspace.android.security.VaultSession
import java.time.Instant

class IdqaStore(private val vault:VaultSession,private val trust:IdqaTrustService){
    companion object{private const val BUNDLE="idqa-trust-bundle";private const val STATE="idqa-state"}
    fun isTrustConfigured()=trust.configured
    @Synchronized fun importTrustBundle(bytes:ByteArray):Long{require(bytes.size in 1..2*1024*1024);val bundle=IdqaTrustBundle.fromJson(JSONObject(bytes.decodeToString()));trust.validateBundle(bundle);val current=state();require(bundle.sequence>=current.highestBundleSequence){"An older IDQA trust bundle cannot replace a newer trusted release."};val clear=bytes.copyOf();try{vault.put(BUNDLE,clear)}finally{clear.fill(0)};saveState(current.copy(highestBundleSequence=bundle.sequence));return bundle.sequence}
    @Synchronized fun importAttestation(bytes:ByteArray,persistent:PersistentState):IdqaValidationResult{require(bytes.size in 1..2*1024*1024);val bundle=bundle();val att=IdqaAttestation.fromJson(JSONObject(bytes.decodeToString()));val profile=requireNotNull(persistent.profileId);val cert=DigitalSpaceCrypto.certificate(requireNotNull(persistent.foundationalCertificate));val result=trust.validateAttestation(att,profile,cert,bundle);val current=state();require(result.trustBundleSequence>=current.highestBundleSequence);require(att.attestationId !in current.processedIds){"This IDQA attestation was already processed."};val old=current.attestation;require(old==null||!att.issuedAt.isBefore(old.issuedAt)){"An older IDQA attestation cannot replace a newer assessment."};val processed=(current.processedIds+att.attestationId).takeLast(1024);saveState(IdqaStoredState(att,result,maxOf(current.highestBundleSequence,result.trustBundleSequence),processed));return result}
    @Synchronized fun current(persistent:PersistentState):IdqaStoredState{val current=state();val att=current.attestation?:return current;return runCatching{val result=trust.validateAttestation(att,requireNotNull(persistent.profileId),DigitalSpaceCrypto.certificate(requireNotNull(persistent.foundationalCertificate)),bundle());current.copy(validation=result)}.getOrElse{current.copy(validation=IdqaValidationResult(false,it.message?:"Invalid",current.highestBundleSequence,"","","","",""))}}
    @Synchronized fun remove(){val current=state();saveState(current.copy(attestation=null,validation=null))}
    fun level(score:Int):Pair<Int,Int>{val s=score.coerceIn(0,72);val level=if(s<=0)0 else minOf(6,(s+11)/12);val progress=if(level==0)0 else if(level==6&&s==72)12 else s-((level-1)*12);return level to progress}
    private fun bundle():IdqaTrustBundle{val b=vault.get(BUNDLE)?:throw IllegalStateException("Import the signed IDQA trust bundle first.");return try{IdqaTrustBundle.fromJson(JSONObject(b.decodeToString())).also{trust.validateBundle(it)}}finally{b.fill(0)}}
    private fun state():IdqaStoredState{val b=vault.get(STATE)?:return IdqaStoredState(null,null,0,emptyList());return try{val o=JSONObject(b.decodeToString());val a=o.optJSONObject("attestation")?.let(IdqaAttestation::fromJson);val p=o.optJSONArray("processed_ids")?:JSONArray();IdqaStoredState(a,null,o.optLong("highest_bundle_sequence",0),(0 until p.length()).map{p.getString(it)})}finally{b.fill(0)}}
    private fun saveState(s:IdqaStoredState){val c=JSONObject().putOpt("attestation",s.attestation?.toJson()).put("highest_bundle_sequence",s.highestBundleSequence).put("processed_ids",JSONArray(s.processedIds)).toString().encodeToByteArray();try{vault.put(STATE,c)}finally{c.fill(0)}}
}
