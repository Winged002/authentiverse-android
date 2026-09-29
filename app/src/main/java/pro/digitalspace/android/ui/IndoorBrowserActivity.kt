/* SPDX-License-Identifier: MIT */
package pro.digitalspace.android.ui

import android.annotation.SuppressLint
import android.graphics.Bitmap
import android.graphics.Color
import android.content.res.ColorStateList
import android.net.Uri
import android.net.http.SslCertificate
import android.net.http.SslError
import android.os.Bundle
import android.view.View
import android.view.Gravity
import android.webkit.ClientCertRequest
import android.webkit.CookieManager
import android.webkit.HttpAuthHandler
import android.webkit.RenderProcessGoneDetail
import android.webkit.SslErrorHandler
import android.webkit.WebChromeClient
import android.webkit.PermissionRequest
import android.Manifest
import android.content.pm.PackageManager
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import pro.digitalspace.android.BuildConfig
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView
import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.setPadding
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.google.android.material.appbar.MaterialToolbar
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.google.android.material.snackbar.Snackbar
import kotlinx.coroutines.launch
import pro.digitalspace.android.DigitalSpaceApplication
import pro.digitalspace.android.model.SpaceState
import pro.digitalspace.android.network.ControlPlaneClient
import pro.digitalspace.android.repository.DigitalSpaceRepository
import pro.digitalspace.android.repository.IndoorBrowserCredentials
import pro.digitalspace.android.security.DigitalSpaceCrypto
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

class IndoorBrowserActivity : AppCompatActivity() {
    companion object {
        private const val HOME_URL = "https://home.digitalspace.home.arpa/"
        private const val HOME_HOST = "home.digitalspace.home.arpa"
        private const val API_HOST = "api.digitalspace.home.arpa"
        private const val HTTPS_PORT = 443
        private const val SERVER_AUTH_OID = "1.3.6.1.5.5.7.3.1"
    }

    private lateinit var repository: DigitalSpaceRepository
    private lateinit var credentials: IndoorBrowserCredentials
    private lateinit var webView: WebView
    private lateinit var progress: ProgressBar
    private lateinit var root: LinearLayout
    private lateinit var addressText: TextView
    private lateinit var app: DigitalSpaceApplication
    private var callMode = false
    private var initialUrl = HOME_URL

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        app = application as DigitalSpaceApplication
        repository = app.repository
        callMode = intent.getBooleanExtra("call_mode", false)
        initialUrl = normalizeInitialUrl(intent.getStringExtra("initial_uri"))
        credentials = runCatching { repository.indoorBrowserCredentials() }.getOrElse {
            finishWithError(it.message ?: "Indoor Home credentials are unavailable.")
            return
        }
        buildBrowser()
        observeTunnel()
        if (savedInstanceState == null) webView.loadUrl(initialUrl)

        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                if (webView.canGoBack()) webView.goBack() else finish()
            }
        })
    }

    @SuppressLint("SetJavaScriptEnabled")
    private fun buildBrowser() {
        root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setBackgroundColor(Color.parseColor("#F7F8FB")) }
        val toolbar = MaterialToolbar(this).apply {
            title = if (callMode) "Private call" else "Browser"
            setTitleTextColor(Color.parseColor("#111827"))
            setBackgroundColor(Color.parseColor("#F7F8FB"))
            setNavigationIcon(android.R.drawable.ic_menu_close_clear_cancel)
            setNavigationOnClickListener { finish() }
            if (!callMode) {
                menu.add("Passwords").apply { setShowAsAction(android.view.MenuItem.SHOW_AS_ACTION_ALWAYS) }
                setOnMenuItemClickListener { if (it.title == "Passwords") { showAutofill(); true } else false }
            }
        }

        val browserBar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(12), dp(5), dp(12), dp(9))
        }
        val back = MaterialButton(this, null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
            text = "‹"
            textSize = 25f
            minWidth = 0
            minimumWidth = 0
            setPadding(0, 0, 0, 0)
            cornerRadius = dp(16)
            strokeColor = ColorStateList.valueOf(Color.parseColor("#E4E7EC"))
            setTextColor(Color.parseColor("#475467"))
            setOnClickListener { if (::webView.isInitialized && webView.canGoBack()) webView.goBack() else finish() }
            contentDescription = "Back"
        }
        browserBar.addView(back, LinearLayout.LayoutParams(dp(46), dp(46)).apply { marginEnd = dp(8) })

        val address = MaterialCardView(this).apply {
            radius = dp(16).toFloat(); strokeWidth = dp(1); strokeColor = Color.parseColor("#E4E7EC")
            setCardBackgroundColor(Color.WHITE); cardElevation = 0f
            isClickable = true; setOnClickListener { showConnectionDetails() }
        }
        val addressRow = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL; setPadding(dp(12), 0, dp(12), 0) }
        addressRow.addView(ImageView(this).apply {
            setImageResource(pro.digitalspace.android.R.drawable.ic_av_shield)
            imageTintList = ColorStateList.valueOf(Color.parseColor("#08735E"))
            contentDescription = "Authenticated"
        }, LinearLayout.LayoutParams(dp(18), dp(18)).apply { marginEnd = dp(8) })
        addressText = TextView(this).apply {
            text = if (callMode) "httpsa://$API_HOST/rtc" else "httpsa://$HOME_HOST"
            textSize = 13f
            setTextColor(Color.parseColor("#344054"))
            maxLines = 1
            ellipsize = android.text.TextUtils.TruncateAt.MIDDLE
        }
        addressRow.addView(addressText, LinearLayout.LayoutParams(0, -2, 1f))
        address.addView(addressRow)
        browserBar.addView(address, LinearLayout.LayoutParams(0, dp(46), 1f))

        progress = ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal).apply {
            max = 100
            visibility = View.GONE
        }
        val frame = FrameLayout(this)
        webView = WebView(this).apply {
            setBackgroundColor(Color.WHITE)
            settings.apply {
                javaScriptEnabled = true
                domStorageEnabled = true
                allowFileAccess = false
                allowContentAccess = false
                javaScriptCanOpenWindowsAutomatically = false
                setSupportMultipleWindows(false)
                mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
                cacheMode = WebSettings.LOAD_DEFAULT
                userAgentString = "$userAgentString Authentiverse-Android/${BuildConfig.VERSION_NAME}"
                if (android.os.Build.VERSION.SDK_INT >= 26) safeBrowsingEnabled = true
            }
            CookieManager.getInstance().setAcceptThirdPartyCookies(this, false)
            webChromeClient = object : WebChromeClient() {
                override fun onProgressChanged(view: WebView?, newProgress: Int) {
                    this@IndoorBrowserActivity.progress.progress = newProgress
                    this@IndoorBrowserActivity.progress.visibility = if (newProgress in 1..99) View.VISIBLE else View.GONE
                }
                override fun onPermissionRequest(request: PermissionRequest) {
                    val origin = request.origin
                    val audioOnly = request.resources.all { it == PermissionRequest.RESOURCE_AUDIO_CAPTURE }
                    if (callMode && audioOnly && origin.scheme.equals("https", true) && origin.host.equals(API_HOST, true)) {
                        if (ContextCompat.checkSelfPermission(this@IndoorBrowserActivity, Manifest.permission.RECORD_AUDIO) == PackageManager.PERMISSION_GRANTED)
                            request.grant(arrayOf(PermissionRequest.RESOURCE_AUDIO_CAPTURE))
                        else { request.deny(); ActivityCompat.requestPermissions(this@IndoorBrowserActivity, arrayOf(Manifest.permission.RECORD_AUDIO), 44) }
                    } else request.deny()
                }
            }
            webViewClient = IndoorWebViewClient()
        }
        frame.addView(webView, FrameLayout.LayoutParams(-1, -1))
        root.addView(toolbar, LinearLayout.LayoutParams(-1, dp(58)))
        root.addView(browserBar, LinearLayout.LayoutParams(-1, dp(60)))
        root.addView(progress, LinearLayout.LayoutParams(-1, dp(3)))
        root.addView(frame, LinearLayout.LayoutParams(-1, 0, 1f))
        setContentView(root)
    }

    private fun observeTunnel() {
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                repository.snapshot.collect { snapshot ->
                    if (snapshot.state != SpaceState.INDOORS && snapshot.state != SpaceState.ENTERING) {
                        finishWithError("Browser closed because the Private Network connection ended.")
                    }
                }
            }
        }
    }

    private inner class IndoorWebViewClient : WebViewClient() {
        override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest): Boolean =
            if (isAllowedPage(request.url)) false else blockNavigation()

        @Deprecated("Deprecated by Android")
        override fun shouldOverrideUrlLoading(view: WebView?, url: String?): Boolean =
            if (url != null && isAllowedPage(Uri.parse(url))) false else blockNavigation()

        override fun shouldInterceptRequest(view: WebView?, request: WebResourceRequest): WebResourceResponse? =
            if (isAllowedResource(request.url)) null else blockedResource()

        override fun onPageStarted(view: WebView?, url: String?, favicon: Bitmap?) {
            if (url == null || !isAllowedPage(Uri.parse(url))) {
                view?.stopLoading()
                blockNavigation()
                return
            }
            if (::addressText.isInitialized) addressText.text = displayUrl(url)
            super.onPageStarted(view, url, favicon)
        }

        override fun onReceivedClientCertRequest(view: WebView?, request: ClientCertRequest) {
            val keyTypes = request.keyTypes.orEmpty()
            val supportsEc = keyTypes.isEmpty() || keyTypes.any { it.equals("EC", true) }
            when {
                !supportsEc || request.port != HTTPS_PORT -> request.cancel()
                request.host.equals(HOME_HOST, true) -> request.proceed(
                    credentials.profilePrivateKey, credentials.profileCertificateChain)
                request.host.equals(API_HOST, true) -> request.proceed(
                    credentials.devicePrivateKey, credentials.deviceCertificateChain)
                else -> request.cancel()
            }
        }

        @SuppressLint("WebViewClientOnReceivedSslError")
        override fun onReceivedSslError(view: WebView?, handler: SslErrorHandler, error: SslError) {
            // WebView cannot consume the app-private CA dynamically. Proceed only
            // after replacing its generic untrusted-root result with our exact,
            // pinned X.509 validation. Every other TLS error remains fatal.
            if (error.primaryError == SslError.SSL_UNTRUSTED && validatePinnedServer(error)) {
                handler.proceed()
            } else {
                handler.cancel()
                showBlocked("Authenticated service failed secure verification.")
            }
        }

        override fun onReceivedHttpAuthRequest(view: WebView?, handler: HttpAuthHandler, host: String?, realm: String?) {
            handler.cancel()
        }

        override fun onReceivedHttpError(view: WebView?, request: WebResourceRequest, errorResponse: WebResourceResponse) {
            if (request.isForMainFrame) showBlocked("Authenticated service returned HTTP ${errorResponse.statusCode}.")
        }

        override fun onRenderProcessGone(view: WebView?, detail: RenderProcessGoneDetail?): Boolean {
            finishWithError("The Authentiverse browser stopped unexpectedly.")
            return true
        }
    }

    private fun validatePinnedServer(error: SslError): Boolean = runCatching {
        val uri = Uri.parse(error.url)
        require(isAllowedResource(uri))
        val authority = credentials.serverAuthority
        require(DigitalSpaceCrypto.hex(DigitalSpaceCrypto.sha256(authority.encoded))
            .equals(ControlPlaneClient.PINNED_CA_SHA256, true))
        authority.checkValidity()
        val state = requireNotNull(SslCertificate.saveState(error.certificate))
        val encoded = requireNotNull(state.getByteArray("x509-certificate"))
        val leaf = CertificateFactory.getInstance("X.509")
            .generateCertificate(encoded.inputStream()) as X509Certificate
        leaf.checkValidity()
        leaf.verify(authority.publicKey)
        require(matchesExactDnsName(leaf, requireNotNull(uri.host)))
        val extendedUsage = leaf.extendedKeyUsage
        require(extendedUsage == null || SERVER_AUTH_OID in extendedUsage)
        true
    }.getOrDefault(false)

    private fun matchesExactDnsName(certificate: X509Certificate, host: String): Boolean =
        certificate.subjectAlternativeNames.orEmpty().any { name ->
            name.size >= 2 && name[0] == 2 && (name[1] as? String)?.equals(host, true) == true
        }

    private fun isAllowedPage(uri: Uri): Boolean = isSecureHost(uri, HOME_HOST) || (callMode && isSecureHost(uri, API_HOST) && uri.path.orEmpty().startsWith("/rtc"))

    private fun isAllowedResource(uri: Uri): Boolean = isSecureHost(uri, HOME_HOST) || isSecureHost(uri, API_HOST)

    private fun isSecureHost(uri: Uri, host: String): Boolean {
        val port = if (uri.port == -1) HTTPS_PORT else uri.port
        return uri.scheme.equals("https", true) && uri.host.equals(host, true) && port == HTTPS_PORT &&
            uri.userInfo == null
    }


    private fun normalizeInitialUrl(value:String?):String {
        if(value.isNullOrBlank()) return HOME_URL
        val uri=runCatching{Uri.parse(value)}.getOrNull()?:return HOME_URL
        val normalized=if(uri.scheme.equals("httpsa",true)||uri.scheme.equals("indoor",true)) uri.buildUpon().scheme("https").build() else uri
        return if(isSecureHost(normalized,HOME_HOST)||(callMode&&isSecureHost(normalized,API_HOST)&&normalized.path.orEmpty().startsWith("/rtc"))) normalized.toString() else HOME_URL
    }

    private fun displayUrl(value: String): String = value.replaceFirst("https://", "httpsa://")

    private fun showConnectionDetails() {
        val host = webView.url?.let { runCatching { Uri.parse(it).host }.getOrNull() } ?: if (callMode) API_HOST else HOME_HOST
        MaterialAlertDialogBuilder(this)
            .setTitle("Authenticated connection")
            .setMessage("✓ Service identity verified\n✓ Your Authentiverse identity is presented only when required\n✓ Connection is private\n\n$host\n\nHTTPSA means the connection is encrypted and identity-authenticated.")
            .setPositiveButton("Close", null)
            .show()
    }

    private fun dp(value: Int) = (value * resources.displayMetrics.density).toInt()

    private fun showAutofill(){
        val current=webView.url?.let{Uri.parse(it)}?:return
        if(!current.scheme.equals("https",true)||current.host.isNullOrBlank()) return
        val origin="https://${current.host!!.lowercase()}" + if(current.port==-1||current.port==443)"" else ":${current.port}"
        val matches=runCatching{app.passwords.findForOrigin(origin)}.getOrElse{showBlocked(it.message?:"Password Vault unavailable.");return}
        if(matches.isEmpty()){showBlocked("No Password Vault credential is approved for this exact origin.");return}
        MaterialAlertDialogBuilder(this).setTitle("Fill from Password Vault").setItems(matches.map{it.title+if(it.username.isBlank())"" else " · "+it.username}.toTypedArray()){_,i->
            val pair=runCatching{app.passwords.autofillSecret(matches[i].credentialId,origin)}.getOrElse{showBlocked(it.message?:"Autofill denied.");return@setItems}
            val password=pair.second.decodeToString();pair.second.fill(0)
            val js="""(function(){const u=${org.json.JSONObject.quote(pair.first)},p=${org.json.JSONObject.quote(password)};const es=[...document.querySelectorAll('input')];const pass=es.find(e=>e.type==='password');const user=es.find(e=>e!==pass&&(['text','email',''].includes(e.type)));if(user){user.focus();user.value=u;user.dispatchEvent(new Event('input',{bubbles:true}));}if(pass){pass.focus();pass.value=p;pass.dispatchEvent(new Event('input',{bubbles:true}));}return !!pass;})()"""
            webView.evaluateJavascript(js,null)
        }.show()
    }

    private fun blockedResource() = WebResourceResponse(
        "text/plain",
        "UTF-8",
        403,
        "Blocked by Authentiverse",
        mapOf("Cache-Control" to "no-store"),
        ByteArrayInputStream(ByteArray(0))
    )

    private fun blockNavigation(): Boolean {
        showBlocked("Authentiverse blocked navigation outside this authenticated Private Network.")
        return true
    }

    private fun showBlocked(message: String) {
        if (::root.isInitialized) Snackbar.make(root, message, Snackbar.LENGTH_LONG).show()
    }

    private fun finishWithError(message: String) {
        if (::root.isInitialized) {
            Snackbar.make(root, message, Snackbar.LENGTH_LONG).show()
            root.postDelayed({ finish() }, 1_800)
        } else {
            setContentView(TextView(this).apply { text = message; setPadding(48); textSize = 16f })
            window.decorView.postDelayed({ finish() }, 1_800)
        }
    }

    override fun onDestroy() {
        if (::webView.isInitialized) {
            webView.stopLoading()
            webView.loadUrl("about:blank")
            webView.clearHistory()
            webView.removeAllViews()
            webView.destroy()
        }
        super.onDestroy()
    }
}
