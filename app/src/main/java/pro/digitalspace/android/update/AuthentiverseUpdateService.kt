/* SPDX-License-Identifier: MIT */
package pro.digitalspace.android.update

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.content.FileProvider
import org.json.JSONObject
import pro.digitalspace.android.BuildConfig
import pro.digitalspace.android.security.DigitalSpaceCrypto
import java.io.File
import java.net.URL
import java.security.MessageDigest
import javax.net.ssl.HttpsURLConnection

data class UpdateManifest(val versionCode:Int,val versionName:String,val apkUrl:String,val sha256:String,val size:Long)

/** Fail-closed signed-APK updater. Distribution is enabled only when build-time pins are configured. */
class AuthentiverseUpdateService(private val context: Context) {
    val configured: Boolean get() = BuildConfig.AUTHENTIVERSE_UPDATE_MANIFEST_URL.startsWith("https://") && signerPins().isNotEmpty()

    fun check(): UpdateManifest? {
        require(configured) { "Automatic updates are not configured in this build." }
        val bytes = get(BuildConfig.AUTHENTIVERSE_UPDATE_MANIFEST_URL, 256 * 1024)
        val root = JSONObject(bytes.decodeToString())
        val manifest = UpdateManifest(root.getInt("version_code"), root.getString("version_name"), root.getString("apk_url"),
            root.getString("sha256").replace(":", "").uppercase(), root.getLong("size"))
        require(manifest.apkUrl.startsWith("https://"))
        require(manifest.sha256.matches(Regex("[0-9A-F]{64}")))
        require(manifest.size in 1..(1024L*1024L*1024L))
        return manifest.takeIf { it.versionCode > BuildConfig.VERSION_CODE }
    }

    fun downloadAndVerify(manifest: UpdateManifest): File {
        val target = File(context.cacheDir, "updates/authentiverse-${manifest.versionCode}.apk").apply { parentFile?.mkdirs(); delete() }
        val c = URL(manifest.apkUrl).openConnection() as HttpsURLConnection
        c.connectTimeout=20_000;c.readTimeout=120_000;c.instanceFollowRedirects=false;c.setRequestProperty("User-Agent","Authentiverse-Android/${BuildConfig.VERSION_NAME}")
        require(c.responseCode in 200..299) { "Update download failed with HTTP ${c.responseCode}." }
        val digest=MessageDigest.getInstance("SHA-256");var total=0L
        c.inputStream.use { input -> target.outputStream().use { output -> val b=ByteArray(64*1024);while(true){val n=input.read(b);if(n<0)break;total+=n;require(total<=manifest.size&&total<=1024L*1024L*1024L){"Update is larger than declared."};digest.update(b,0,n);output.write(b,0,n)};b.fill(0) } }
        require(total==manifest.size) { "Update size does not match its signed manifest." }
        require(DigitalSpaceCrypto.hex(digest.digest()).equals(manifest.sha256,true)) { "Update SHA-256 does not match." }
        verifySigner(target)
        return target
    }

    fun installIntent(apk: File): Intent {
        val uri=FileProvider.getUriForFile(context,"${context.packageName}.files",apk)
        return Intent(Intent.ACTION_VIEW).setDataAndType(uri,"application/vnd.android.package-archive")
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
    }

    private fun verifySigner(apk: File) {
        val pm=context.packageManager
        val info=if(Build.VERSION.SDK_INT>=28) pm.getPackageArchiveInfo(apk.absolutePath,PackageManager.GET_SIGNING_CERTIFICATES)
            else @Suppress("DEPRECATION") pm.getPackageArchiveInfo(apk.absolutePath,PackageManager.GET_SIGNATURES)
        requireNotNull(info) { "Downloaded update is not a valid Android package." }
        require(info.packageName==context.packageName) { "Update package identity does not match Authentiverse." }
        val signatures=if(Build.VERSION.SDK_INT>=28) info.signingInfo?.apkContentsSigners.orEmpty() else @Suppress("DEPRECATION") info.signatures.orEmpty()
        val actual=signatures.map{DigitalSpaceCrypto.hex(MessageDigest.getInstance("SHA-256").digest(it.toByteArray()))}.toSet()
        require(actual.any{it in signerPins()}) { "Update signer is not trusted by this Authentiverse build." }
    }
    private fun signerPins()=BuildConfig.AUTHENTIVERSE_UPDATE_SIGNER_SHA256.split(';').map{it.replace(":","").trim().uppercase()}.filter{it.matches(Regex("[0-9A-F]{64}"))}.toSet()
    private fun get(url:String,max:Int):ByteArray { val c=URL(url).openConnection() as HttpsURLConnection;c.connectTimeout=15_000;c.readTimeout=20_000;c.instanceFollowRedirects=false;c.setRequestProperty("Accept","application/json");require(c.responseCode in 200..299);return c.inputStream.use{val out=java.io.ByteArrayOutputStream();val b=ByteArray(8192);while(true){val n=it.read(b);if(n<0)break;require(out.size()+n<=max);out.write(b,0,n)};out.toByteArray()} }
}
