/* SPDX-License-Identifier: MIT */
package pro.digitalspace.android.passwords

import java.net.URI
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.time.Instant
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

object CredentialOrigin {
    fun normalize(value: String): String {
        var input = value.trim(); require(input.isNotBlank()) { "A credential URL is required for autofill." }
        if (!input.contains("://")) input = "https://$input"
        val uri = URI(input); var scheme = uri.scheme?.lowercase() ?: throw IllegalArgumentException("The credential URL is invalid.")
        if (scheme == "httpsa" || scheme == "indoor") scheme = "https"
        require(scheme == "https") { "Password autofill supports HTTPS/httpsa origins only." }
        require(uri.userInfo.isNullOrEmpty()) { "Credential URLs may not contain embedded usernames or passwords." }
        val host = uri.host?.trimEnd('.')?.lowercase().orEmpty(); require(host.isNotBlank()) { "The credential URL host is missing." }
        val port = if (uri.port < 0) 443 else uri.port
        return "https://$host" + if (port == 443) "" else ":$port"
    }
    fun exactMatch(record: PasswordCredentialRecord, origin: String): Boolean = runCatching {
        val normalized = normalize(origin); record.allowedOrigins.any { normalize(it).equals(normalized, true) }
    }.getOrDefault(false)
}

object PasswordGenerator {
    private const val LOWER="abcdefghijkmnopqrstuvwxyz"; private const val UPPER="ABCDEFGHJKLMNPQRSTUVWXYZ"
    private const val DIGITS="23456789"; private const val SYMBOLS="!@#$%^&*()-_=+[]{}:,.?"
    private val random=SecureRandom()
    fun generate(length:Int=24, symbols:Boolean=true):String { require(length in 12..128); val sets=mutableListOf(LOWER,UPPER,DIGITS); if(symbols)sets+=SYMBOLS
        val all=sets.joinToString(""); val chars=CharArray(length); sets.forEachIndexed{i,set->chars[i]=set[random.nextInt(set.length)]}
        for(i in sets.size until length) chars[i]=all[random.nextInt(all.length)]; for(i in chars.lastIndex downTo 1){val j=random.nextInt(i+1); val x=chars[i];chars[i]=chars[j];chars[j]=x}; return String(chars)}
}

object TotpService {
    private const val ALPHABET="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    fun parseBase32(value:String):ByteArray { val clean=value.uppercase().filter{!it.isWhitespace()&&it!='-'&&it!='='}; if(clean.isBlank())return ByteArray(0);require(clean.length in 16..256)
        val out=ArrayList<Byte>(); var buffer=0;var bits=0; for(ch in clean){val index=ALPHABET.indexOf(ch);require(index>=0){"The TOTP secret is not valid Base32."};buffer=(buffer shl 5) or index;bits+=5;if(bits>=8){bits-=8;out.add(((buffer shr bits) and 0xff).toByte())}};return out.toByteArray()}
    fun currentCode(secret:ByteArray, now:Instant=Instant.now()):Pair<String,Int>{require(secret.isNotEmpty());val unix=now.epochSecond;val counter=unix/30;val bytes=ByteBuffer.allocate(8).putLong(counter).array();val hash=Mac.getInstance("HmacSHA1").apply{init(SecretKeySpec(secret,"HmacSHA1"))}.doFinal(bytes)
        return try{val off=hash.last().toInt() and 0xf;val binary=((hash[off].toInt() and 0x7f) shl 24) or ((hash[off+1].toInt() and 0xff) shl 16) or ((hash[off+2].toInt() and 0xff) shl 8) or (hash[off+3].toInt() and 0xff); "%06d".format(binary%1_000_000) to (30-(unix%30).toInt())}finally{hash.fill(0);bytes.fill(0)}}
}
