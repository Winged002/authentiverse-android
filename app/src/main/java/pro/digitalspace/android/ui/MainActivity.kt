/* SPDX-License-Identifier: MIT */
package pro.digitalspace.android.ui

import android.app.Activity
import android.content.Intent
import android.content.res.ColorStateList
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.pdf.PdfRenderer
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.os.ProxyFileDescriptorCallback
import android.os.storage.StorageManager
import android.os.ParcelFileDescriptor
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.net.VpnService
import android.os.Bundle
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.widget.*
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.FileProvider
import androidx.core.view.WindowCompat
import androidx.core.view.setPadding
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.google.android.material.appbar.MaterialToolbar
import com.google.android.material.bottomnavigation.BottomNavigationView
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.google.android.material.checkbox.MaterialCheckBox
import com.google.android.material.chip.Chip
import com.google.android.material.chip.ChipGroup
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.progressindicator.LinearProgressIndicator
import com.google.android.material.snackbar.Snackbar
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import pro.digitalspace.android.DigitalSpaceApplication
import pro.digitalspace.android.BuildConfig
import pro.digitalspace.android.chat.ChatMessagePolicy
import pro.digitalspace.android.chat.ChatStoredMessage
import pro.digitalspace.android.passwords.PasswordCredentialSummary
import pro.digitalspace.android.protocol.ProtocolRouter
import pro.digitalspace.android.protocol.AuthentiverseRouteKind
import pro.digitalspace.android.update.AuthentiverseUpdateService
import pro.digitalspace.android.model.*
import pro.digitalspace.android.privacy.PrivacyRequestParser
import pro.digitalspace.android.repository.AppSnapshot
import pro.digitalspace.android.repository.DigitalSpaceRepository
import pro.digitalspace.android.security.DigitalSpaceCrypto
import java.io.File
import java.time.Instant
import java.time.LocalTime
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.temporal.ChronoUnit
import java.util.Locale

class MainActivity : AppCompatActivity() {
    companion object {
        private const val BG = "#F7F8FB"
        private const val INK = "#111827"
        private const val MUTED = "#667085"
        private const val PRIMARY = "#5755D9"
        private const val PRIMARY_DARK = "#3730A3"
        private const val DANGER = "#D14343"
        private const val BORDER = "#E4E7EC"
    }

    private lateinit var app: DigitalSpaceApplication
    private lateinit var repository: DigitalSpaceRepository
    private lateinit var root: LinearLayout
    private lateinit var toolbar: MaterialToolbar
    private lateinit var content: LinearLayout
    private lateinit var progress: LinearProgressIndicator
    private lateinit var navigation: BottomNavigationView
    private var section = Section.HOME
    private var vaultMode = VaultMode.FILES
    private var ndaFilter = NdaFilter.ALL
    private var latest: AppSnapshot? = null
    private var pendingArea: String? = null
    private var pendingExport: ((Uri) -> Unit)? = null
    private var secureViewer: androidx.appcompat.app.AlertDialog? = null

    private enum class Section { HOME, MESSAGES, VAULT, BROWSER, YOU }
    private enum class VaultMode { FILES, NDAS, PASSWORDS }
    private enum class NdaFilter { ALL, NEEDS_ACTION, SENT, COMPLETED }

    private val vpnPermission = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        val area = pendingArea.also { pendingArea = null }
        if (result.resultCode == Activity.RESULT_OK && area != null) launch { repository.enterArea(area) }
    }
    private val importPackage = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) launch { repository.importPackage(uri) }
    }
    private val addFile = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) launch { repository.addProtectedFile(uri) }
    }
    private val importIdqaBundle = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) launch { val bytes=contentResolver.openInputStream(uri)!!.use{it.readBytes()}; try { val seq=app.idqa.importTrustBundle(bytes); repository.refreshLocal("IDQA trust bundle $seq imported.") } finally { bytes.fill(0) } }
    }
    private val importIdqaAttestation = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) launch { val bytes=contentResolver.openInputStream(uri)!!.use{it.readBytes()}; try { val result=app.idqa.importAttestation(bytes, repository.snapshot.value.persistent); repository.refreshLocal("IDQA attestation ${if(result.isValid) "verified" else "rejected"}.") } finally { bytes.fill(0) } }
    }
    private val createDocument = registerForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        val action = pendingExport.also { pendingExport = null }
        if (uri != null) runCatching { action?.invoke(uri) }.onFailure(::showError)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.statusBarColor = color(BG)
        window.navigationBarColor = Color.WHITE
        WindowCompat.getInsetsController(window, window.decorView).apply {
            isAppearanceLightStatusBars = true
            isAppearanceLightNavigationBars = true
        }
        File(cacheDir, "managed-previews").listFiles()?.forEach(File::delete)
        app = application as DigitalSpaceApplication
        repository = app.repository
        buildShell()
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                repository.snapshot.collect { snapshot ->
                    latest = snapshot
                    render(snapshot)
                    snapshot.message?.let {
                        Snackbar.make(root, it, Snackbar.LENGTH_LONG).show()
                        repository.clearMessage()
                    }
                }
            }
        }
        (intent?.dataString ?: intent?.getStringExtra("route_uri"))?.let { runCatching { Uri.parse(it) }.getOrNull()?.let(::handleDeepLink) }
    }


    override fun onStop(){ secureViewer?.dismiss(); super.onStop() }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        (intent.dataString ?: intent.getStringExtra("route_uri"))?.let { runCatching { Uri.parse(it) }.getOrNull()?.let(::handleDeepLink) }
    }

    private fun buildShell() {
        root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setBackgroundColor(color(BG)) }
        toolbar = MaterialToolbar(this).apply {
            title = "Authentiverse"
            subtitle = null
            inflateMenu(pro.digitalspace.android.R.menu.authentiverse_toolbar)
            menu.add(0, 901, 0, "Protection").apply {
                setIcon(pro.digitalspace.android.R.drawable.ic_av_shield)
                setShowAsAction(android.view.MenuItem.SHOW_AS_ACTION_ALWAYS)
            }
            setOnMenuItemClickListener { item ->
                when (item.itemId) {
                    pro.digitalspace.android.R.id.action_switch_account -> { switchAccount(); true }
                    901 -> { latest?.let(::securityCenterDialog); true }
                    else -> false
                }
            }
            setTitleTextColor(color(INK))
            setPadding(dp(14), dp(5), dp(10), 0)
            setBackgroundColor(color(BG))
        }
        progress = LinearProgressIndicator(this).apply {
            visibility = View.GONE
            isIndeterminate = true
            trackColor = color("#E8E7FF")
            setIndicatorColor(color(PRIMARY))
        }
        val scroll = ScrollView(this).apply { isFillViewport = true; overScrollMode = View.OVER_SCROLL_NEVER }
        content = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(18), dp(10), dp(18), dp(32)) }
        scroll.addView(content, ViewGroup.LayoutParams(-1, -2))
        val states = arrayOf(intArrayOf(android.R.attr.state_checked), intArrayOf())
        navigation = BottomNavigationView(this).apply {
            setBackgroundColor(Color.WHITE)
            itemIconTintList = ColorStateList(states, intArrayOf(color(PRIMARY), color("#98A2B3")))
            itemTextColor = ColorStateList(states, intArrayOf(color(PRIMARY_DARK), color("#667085")))
            itemActiveIndicatorColor = ColorStateList.valueOf(color("#ECEBFF"))
            labelVisibilityMode = BottomNavigationView.LABEL_VISIBILITY_LABELED
            menu.add(0, 1, 0, "Home").setIcon(pro.digitalspace.android.R.drawable.ic_av_home)
            menu.add(0, 2, 1, "Messages").setIcon(pro.digitalspace.android.R.drawable.ic_av_messages)
            menu.add(0, 3, 2, "Vault").setIcon(pro.digitalspace.android.R.drawable.ic_av_vault)
            menu.add(0, 4, 3, "Browser").setIcon(pro.digitalspace.android.R.drawable.ic_av_browser)
            menu.add(0, 5, 4, "You").setIcon(pro.digitalspace.android.R.drawable.ic_av_you)
            selectedItemId = 1
            setOnItemSelectedListener {
                section = when (it.itemId) {
                    1 -> Section.HOME
                    2 -> Section.MESSAGES
                    3 -> Section.VAULT
                    4 -> Section.BROWSER
                    else -> Section.YOU
                }
                latest?.let(::render)
                true
            }
        }
        root.addView(toolbar, lp(-1, dp(64)))
        root.addView(progress, lp(-1, dp(3)))
        root.addView(scroll, LinearLayout.LayoutParams(-1, 0, 1f))
        root.addView(navigation, lp(-1, -2))
        setContentView(root)
    }

    private fun render(s: AppSnapshot) {
        progress.visibility = if (s.busy) View.VISIBLE else View.GONE
        toolbar.title = when (section) {
            Section.HOME -> "Authentiverse"
            Section.MESSAGES -> "Messages"
            Section.VAULT -> "Vault"
            Section.BROWSER -> "Browser"
            Section.YOU -> "You"
        }
        content.removeAllViews()
        when (section) {
            Section.HOME -> renderHome(s)
            Section.MESSAGES -> renderMessages(s)
            Section.VAULT -> renderVault(s)
            Section.BROWSER -> renderBrowser(s)
            Section.YOU -> renderYou(s)
        }
    }

    private fun renderHome(s: AppSnapshot) {
        val indoors = s.state == SpaceState.INDOORS
        val accountName = app.active?.account?.displayName ?: "Authentiverse"
        content.addView(TextView(this).apply {
            text = "${greeting()}, $accountName"
            textSize = 27f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(color(INK))
        }, marginLp(-1, -2, 0, 4, 0, 3))
        content.addView(TextView(this).apply {
            text = if (s.persistent.enrolled) "Your identity, private network and Vault in one place." else "Set up your private identity to get started."
            textSize = 14f
            setTextColor(color(MUTED))
        }, marginLp(-1, -2, 0, 0, 0, 18))

        if (!s.persistent.enrolled) {
            identitySetupCard()
            primaryButton("Create my identity") { enrollmentDialog() }
            trustNote("Your private identity keys are created on this phone and are never uploaded as private material.")
            return
        }

        val idqa = runCatching { app.idqa.current(s.persistent) }.getOrNull()
        val score = idqa?.attestation?.scores?.total ?: 0
        val verified = idqa?.validation?.isValid == true
        identityCard(s, score, verified)
        quickActions(s)
        protectionCard(s, score, verified)

        sectionTitle("Recent")
        val latestMessage = runCatching { app.chat.messages().maxByOrNull { it.createdAt } }.getOrNull()
        val latestFile = (s.information.ownedFiles.map { it.descriptor.fileName to it.descriptor.addedAt } +
            s.information.sharedFiles.map { it.descriptor.fileName to it.receivedAt }).maxByOrNull { it.second }
        if (latestMessage == null && latestFile == null) {
            emptyState("Nothing recent yet", "Messages and protected files you use will appear here.")
        } else {
            latestMessage?.let { message ->
                listCard("M", message.contactDisplayName, messagePreview(message), friendlyDateTime(message.createdAt)) {
                    conversationDialog(message.contactId, message.contactDisplayName.removePrefix("@"), s)
                }
            }
            latestFile?.let { file ->
                listCard("F", file.first, "Protected in your Vault", friendlyDate(file.second)) {
                    section = Section.VAULT; navigation.selectedItemId = 3; render(s)
                }
            }
        }

        sectionTitle("Private Network")
        if (indoors) {
            val networkText = if (s.persistent.isolatedIndoor) "Connected · public internet paused" else "Connected · authenticated private session"
            listCard("✓", s.persistent.currentAreaName ?: "Private Area", networkText, "Connected") {
                section = Section.BROWSER; navigation.selectedItemId = 4
            }
            textButton("Disconnect", danger = true) { launch { repository.goOutdoors() } }
        } else {
            if (s.areas.isEmpty()) {
                emptyState("No private networks available", "Refresh after an administrator authorizes this identity for an Area.")
            } else {
                s.areas.take(3).forEach { area ->
                    listCard("A", area.name.ifBlank { area.id }, area.description.ifBlank { "Authenticated private network" }, "Connect") {
                        connectArea(area.id)
                    }
                }
            }
            secondaryButton("Refresh networks") { launch { repository.refreshAreas() } }
        }
    }

    private fun certificateDialog(s:AppSnapshot){MaterialAlertDialogBuilder(this).setTitle("Authentiverse certificates").setMessage("Foundational: ${if(s.persistent.foundationalCertificate.isNullOrBlank()) "Not enrolled" else "Installed"}\nDevice: ${if(s.persistent.deviceCertificate.isNullOrBlank()) "Not enrolled" else "Installed"}\nProfile: ${if(s.persistent.profileCertificate.isNullOrBlank()) "Outdoors" else "Active for this Area"}\n\nClassical identity keys are non-exportable when Android Keystore supports the required operation. Post-quantum chat keys are PIN-Vault protected because Android Keystore does not expose ML-KEM/ML-DSA key generation." ).setPositiveButton("Close",null).show()}
    private fun checkUpdates() {
        lifecycleScope.launch(Dispatchers.IO) {
            runCatching {
                val service = AuthentiverseUpdateService(this@MainActivity)
                val update = service.check()
                withContext(Dispatchers.Main) {
                    if (update == null) {
                        MaterialAlertDialogBuilder(this@MainActivity)
                            .setTitle("Authentiverse is up to date")
                            .setMessage("Version ${BuildConfig.VERSION_NAME}")
                            .setPositiveButton("Close", null).show()
                    } else {
                        MaterialAlertDialogBuilder(this@MainActivity)
                            .setTitle("Authentiverse ${update.versionName} is available")
                            .setMessage("The APK will be accepted only if its hash and Android signing certificate match this build's configured trust pins.")
                            .setNegativeButton("Later", null)
                            .setPositiveButton("Download and verify") { _, _ ->
                                lifecycleScope.launch(Dispatchers.IO) {
                                    runCatching { service.downloadAndVerify(update) }
                                        .onSuccess { apk -> runOnUiThread { startActivity(service.installIntent(apk)) } }
                                        .onFailure { error -> runOnUiThread { showError(error) } }
                                }
                            }.show()
                    }
                }
            }.onFailure { error -> runOnUiThread { showError(error) } }
        }
    }

    private fun renderFiles(s: AppSnapshot) {
        content.addView(TextView(this).apply { text = "Protected files"; textSize = 19f; typeface = Typeface.DEFAULT_BOLD; setTextColor(color(INK)) }, marginLp(-1,-2,0,2,0,8))
        rowButtons("Add a file" to { addFile.launch(arrayOf("*/*")) }, "Import" to { importPackage.launch(arrayOf("*/*")) })
        metricStrip(listOf("My files" to s.information.ownedFiles.size.toString(), "Shared with me" to s.information.sharedFiles.size.toString(),
            "Waiting" to pendingForMe(s).toString()))
        sectionTitle("My files")
        if (s.information.ownedFiles.isEmpty()) emptyState("Nothing here yet", "Add any document, image or file. It will be encrypted immediately.")
        s.information.ownedFiles.sortedByDescending { it.descriptor.addedAt }.forEach { record ->
            listCard("F", record.descriptor.fileName, "${bytes(record.descriptor.size)} · Added ${friendlyDate(record.descriptor.addedAt)}", "Open") { openOwned(record) }
        }
        sectionTitle("Shared with me")
        if (s.information.sharedFiles.isEmpty()) emptyState("No shared files", "Files covered by an NDA appear here as soon as the package arrives.")
        s.information.sharedFiles.sortedByDescending { it.receivedAt }.forEach { record ->
            val nda = record.ndaId?.let { id -> s.information.agreements.firstOrNull { it.ndaId == id } }
            val participant = nda?.participants?.firstOrNull { it.contactId == record.recipientContactId }
            val expired = nda != null && Instant.now().isAfter(nda.validUntil) && nda.postExpiryPolicy == PostExpiryAccessPolicy.RevokeManagedAccess
            val available = if (nda == null) true else participant?.let {
                it.state == AgreementState.Accepted && DigitalSpaceCrypto.verifyAgreementDecision(nda, it)
            } == true
            val state = when { expired -> "Expired"; available -> "Protected"; else -> "Needs your signature" }
            listCard(if (available && !expired) "✓" else "L", record.descriptor.fileName,
                "${bytes(record.descriptor.size)} · $state", if (available && !expired) "View" else "Review") {
                if (available && !expired) openShared(record) else nda?.let(::ndaReview)
            }
        }
        trustNote("NDA-controlled files never offer Save a copy. Supported files open only in the protected viewer.")
    }

    private fun renderNdas(s: AppSnapshot) {
        content.addView(TextView(this).apply { text = "Protected agreements"; textSize = 19f; typeface = Typeface.DEFAULT_BOLD; setTextColor(color(INK)) }, marginLp(-1,-2,0,2,0,8))
        content.addView(TextView(this).apply { text = "Sign clear terms and keep covered files managed inside Authentiverse."; textSize = 13f; setTextColor(color(MUTED)) }, marginLp(-1,-2,0,0,0,12))
        val canCreate = s.information.contacts.isNotEmpty() && s.information.ownedFiles.isNotEmpty()
        primaryButton("Create protected agreement", enabled = canCreate) { createNdaDialog(s) }
        if (!canCreate) trustNote("Add at least one protected file and one trusted person before creating an agreement.")
        val ownId = ownContactId(s)
        metricStrip(listOf(
            "Needs you" to s.information.agreements.count { it.issuerCertificate != s.persistent.foundationalCertificate && it.participants.any { p -> p.contactId == ownId && p.state == AgreementState.Pending } }.toString(),
            "Sent" to s.information.agreements.count { it.issuerCertificate == s.persistent.foundationalCertificate }.toString(),
            "Signed" to s.information.agreements.count { it.participants.any { p -> p.state == AgreementState.Accepted } }.toString()))
        ndaFilterChips()
        val filtered = s.information.agreements.sortedByDescending { it.createdAt }.filter { nda ->
            val sent = nda.issuerCertificate == s.persistent.foundationalCertificate
            val own = nda.participants.firstOrNull { it.contactId == ownId }
            when (ndaFilter) {
                NdaFilter.ALL -> true; NdaFilter.NEEDS_ACTION -> !sent && own?.state == AgreementState.Pending; NdaFilter.SENT -> sent
                NdaFilter.COMPLETED -> if (sent) nda.participants.none { it.state == AgreementState.Pending } else own?.state != AgreementState.Pending
            }
        }
        if (filtered.isEmpty()) emptyState("No agreements here", when (ndaFilter) {
            NdaFilter.ALL -> "Create an NDA or import one sent to you."; NdaFilter.NEEDS_ACTION -> "You’re all caught up."
            NdaFilter.SENT -> "Agreements you create will appear here."; NdaFilter.COMPLETED -> "Signed or declined agreements will appear here."
        })
        filtered.forEach { agreementCard(it, s, ownId) }
    }

    private fun renderPeople(s: AppSnapshot) {
        hero("TRUSTED PEOPLE", "Share with the right person", "Contact cards contain public identity and encryption details—never private personal data.", false)
        if (s.persistent.enrolled) rowButtons("Share my contact" to {
            pendingExport = { repository.exchange.exportContact(it, s.persistent) }; createDocument.launch("${s.persistent.profileHandle}.dscontact")
        }, "Add a person" to { importPackage.launch(arrayOf("application/json", "*/*")) })
        sectionTitle("People you know")
        if (s.information.contacts.isEmpty()) emptyState("No people added", "Import someone’s .dscontact card before sharing files or creating an NDA.")
        s.information.contacts.sortedBy { it.card.handle }.forEach { record ->
            listCard(record.card.handle.take(1).uppercase(), "@${record.card.handle}", "Verified until ${friendlyDate(record.card.expiresAt)}", "Verified", null)
        }
    }

    private fun renderPrivacy(s: AppSnapshot) {
        hero("PRIVATE BY DEFAULT", "Prove the answer—not the data", "Approve a simple answer while the personal source value stays encrypted on this phone.", true)
        val wallet = repository.privacy.load(); primaryButton("Review private details") { privacyWalletDialog() }
        sectionTitle("Stored privately")
        simpleCard("Date of birth", wallet.dateOfBirth ?: "Not added", "Encrypted on this phone", wallet.dateOfBirth != null)
        simpleCard("Gender", wallet.gender?.replaceFirstChar(Char::titlecase) ?: "Not added", "Optional", wallet.gender != null)
        sectionTitle("How requests work")
        simpleCard("You approve every request", "The person asking and the exact proof are shown first.", "Always", true)
        simpleCard("Your source value stays hidden", "Only the approved answer can be presented.", "Private", true)
        trustNote(if (s.state == SpaceState.INDOORS) "Privacy requests can be reviewed while you are Indoors."
            else "Enter an Area before responding to an Indoor privacy request.")
    }


    private fun renderVault(s: AppSnapshot) {
        content.addView(TextView(this).apply {
            text = "Everything important, protected"
            textSize = 24f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(color(INK))
        }, marginLp(-1, -2, 0, 3, 0, 4))
        content.addView(TextView(this).apply {
            text = "Passwords, files and signed agreements stay encrypted inside this account."
            textSize = 14f
            setTextColor(color(MUTED))
        }, marginLp(-1, -2, 0, 0, 0, 16))
        val group = ChipGroup(this).apply { isSingleSelection = true; isSelectionRequired = true; chipSpacingHorizontal = dp(8) }
        listOf(VaultMode.FILES to "Files", VaultMode.PASSWORDS to "Passwords", VaultMode.NDAS to "Agreements").forEach { (mode, label) ->
            group.addView(Chip(this).apply {
                text = label; isCheckable = true; isChecked = vaultMode == mode
                setOnClickListener { vaultMode = mode; render(s) }
            })
        }
        content.addView(group, marginLp(-1, -2, 0, 0, 0, 12))
        when (vaultMode) { VaultMode.FILES -> renderFiles(s); VaultMode.NDAS -> renderNdas(s); VaultMode.PASSWORDS -> renderPasswords() }
    }

    private fun renderPasswords() {
        val health = runCatching { app.passwords.health() }.getOrNull()
        if (health != null) metricStrip(listOf("Passwords" to health.total.toString(), "Needs attention" to health.weak.toString(), "Without 2FA" to health.withoutTotp.toString()))
        rowButtons("New password" to { passwordCreateDialog() }, "Security history" to { passwordAuditDialog() })
        val items = runCatching { app.passwords.list() }.getOrElse { showError(it); emptyList() }
        sectionTitle("Passwords")
        if (items.isEmpty()) emptyState("No saved passwords", "Save a login here and Authentiverse can offer it only to the exact matching site.")
        items.forEach { item ->
            val subtitle = listOf(item.username, item.url).filter { it.isNotBlank() }.joinToString(" · ")
            listCard("P", item.title, subtitle.ifBlank { "Protected login" }, if (item.hasTotp) "2FA" else "Open") { passwordDetailDialog(item) }
        }
        trustNote("Website filling uses exact-origin matching. Shared passwords keep separate reveal, copy and autofill permissions.")
    }

    private fun renderMessages(s: AppSnapshot) {
        val connected = s.state == SpaceState.INDOORS
        content.addView(TextView(this).apply {
            text = "Private conversations"
            textSize = 24f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(color(INK))
        }, marginLp(-1, -2, 0, 3, 0, 4))
        content.addView(TextView(this).apply {
            text = if (connected) "Verified contacts · Private Network connected" else "Connect to a Private Network to send or receive messages."
            textSize = 14f
            setTextColor(color(if (connected) "#08735E" else MUTED))
        }, marginLp(-1, -2, 0, 0, 0, 16))
        rowButtons("New message" to { if (connected) chooseChatContact(s) else showError(IllegalStateException("Connect to a Private Network before messaging.")) },
            "Check messages" to { if (connected) launch { repository.syncInbox() } else showError(IllegalStateException("Connect to a Private Network before checking messages.")) })

        val messages = runCatching { app.chat.messages() }.getOrElse { emptyList() }
        val conversations = messages.groupBy { it.contactId }.mapNotNull { (_, list) -> list.maxByOrNull { it.createdAt } }.sortedByDescending { it.createdAt }
        sectionTitle("Conversations")
        if (conversations.isEmpty()) emptyState("No conversations yet", "Start a message with a verified person you have added to Authentiverse.")
        conversations.forEach { message ->
            listCard(initials(message.contactDisplayName), message.contactDisplayName, messagePreview(message), shortTime(message.createdAt)) {
                conversationDialog(message.contactId, message.contactDisplayName.removePrefix("@"), s)
            }
        }
        trustNote("Messages are authenticated to verified identities. Advanced cryptographic details are available in Protection.")
    }

    private fun renderBrowser(s: AppSnapshot) {
        val connected = s.state == SpaceState.INDOORS
        content.addView(TextView(this).apply {
            text = "Authenticated browsing"
            textSize = 24f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(color(INK))
        }, marginLp(-1, -2, 0, 3, 0, 4))
        content.addView(TextView(this).apply {
            text = "The browser looks familiar, but Authentiverse verifies both the service and the identity used to reach it."
            textSize = 14f
            setTextColor(color(MUTED))
            setLineSpacing(0f, 1.12f)
        }, marginLp(-1, -2, 0, 0, 0, 18))

        val browserCard = card()
        val box = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(18)) }
        box.addView(TextView(this).apply {
            text = if (connected) "✓  Authenticated" else "Private Network required"
            textSize = 12f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(color(if (connected) "#08735E" else "#B54708"))
        })
        box.addView(TextView(this).apply {
            text = "httpsa://home.digitalspace.home.arpa"
            textSize = 15f
            typeface = Typeface.MONOSPACE
            setTextColor(color(INK))
            background = rounded("#F8F9FC", 14)
            setPadding(dp(14), dp(12), dp(14), dp(12))
        }, marginLp(-1, -2, 0, 12, 0, 12))
        box.addView(TextView(this).apply {
            text = if (connected) "Website identity verified · Your authenticated profile is available when the service requests it." else "Connect to one of your authorized Areas before opening authenticated services."
            textSize = 13f
            setTextColor(color(MUTED))
            setLineSpacing(0f, 1.12f)
        })
        browserCard.addView(box)
        content.addView(browserCard, marginLp(-1, -2, 0, 0, 0, 14))
        primaryButton(if (connected) "Open Browser" else "Choose a Private Network") {
            if (connected) runCatching { repository.indoorBrowserCredentials() }
                .onSuccess { startActivity(Intent(this, IndoorBrowserActivity::class.java)) }.onFailure(::showError)
            else { section = Section.HOME; navigation.selectedItemId = 1; render(s) }
        }
        sectionTitle("What Authentiverse adds")
        simpleCard("Authenticated connection", "The service certificate and your permitted identity are verified before access.", "Verified", connected)
        simpleCard("Private information requests", "When a service asks for personal information, you see exactly what will be shared before approving it.", "You decide", true)
        simpleCard("Password Vault", "Saved credentials are offered only to their exact matching origin.", "Protected", true)
    }

    private fun renderYou(s: AppSnapshot) {
        val account = app.active?.account
        val handle = s.persistent.profileHandle?.takeIf { it.isNotBlank() }
        val idqa = runCatching { app.idqa.current(s.persistent) }.getOrNull()
        val score = idqa?.attestation?.scores?.total ?: 0
        val verified = idqa?.validation?.isValid == true
        val level = app.idqa.level(score).first

        val profile = card()
        val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL; setPadding(dp(18)) }
        row.addView(TextView(this).apply {
            text = initials(account?.displayName ?: handle ?: "A")
            gravity = Gravity.CENTER
            textSize = 19f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(Color.WHITE)
            background = GradientDrawable().apply { shape = GradientDrawable.OVAL; setColor(color(PRIMARY)) }
        }, LinearLayout.LayoutParams(dp(58), dp(58)))
        row.addView(LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; setPadding(dp(14), 0, 0, 0)
            addView(TextView(this@MainActivity).apply { text = account?.displayName ?: "Authentiverse account"; textSize = 18f; typeface = Typeface.DEFAULT_BOLD; setTextColor(color(INK)) })
            addView(TextView(this@MainActivity).apply { text = handle?.let { "@$it" } ?: "Identity not enrolled"; textSize = 13f; setTextColor(color(MUTED)); setPadding(0, dp(3), 0, 0) })
            if (s.persistent.enrolled) addView(TextView(this@MainActivity).apply { text = "✓ Verified on this device"; textSize = 12f; setTextColor(color("#08735E")); setPadding(0, dp(4), 0, 0) })
        }, LinearLayout.LayoutParams(0, -2, 1f))
        profile.addView(row)
        content.addView(profile, marginLp(-1, -2, 0, 4, 0, 18))

        sectionTitle("Identity & privacy")
        listCard("ID", "Identity Level", if (verified) "Level $level · $score trust points" else "No verified assessment yet", if (verified) "Verified" else "Open") { identityLevelDialog(s) }
        val wallet = repository.privacy.load()
        listCard("PI", "Personal information", if (wallet.dateOfBirth != null || wallet.gender != null) "Private details stored on this device" else "Add private details for proof requests", "Private") { privacyWalletDialog() }
        listCard("P", "Trusted people", "${s.information.contacts.size} verified contact${if (s.information.contacts.size == 1) "" else "s"}", "Manage") { trustedPeopleDialog(s) }

        sectionTitle("Security")
        listCard("✓", "Protection", protectionSummary(s), "Protected") { securityCenterDialog(s) }
        listCard("C", "Identity certificates", "Foundational, device and active profile certificates", "Advanced") { certificateDialog(s) }
        listCard("U", "App updates", "Version ${BuildConfig.VERSION_NAME}", "Check") { checkUpdates() }

        sectionTitle("Account")
        secondaryButton("Switch account") { switchAccount() }
    }

    private fun passwordCreateDialog(){
        val fields=form("Title","Username","Password","URL (https://…)","Notes","TOTP secret (optional)");fields.second[2].inputType=InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        MaterialAlertDialogBuilder(this).setTitle("New credential").setView(fields.first).setNegativeButton("Cancel",null).setPositiveButton("Save"){_,_->runCatching{app.passwords.create(fields.second[0].text.toString(),fields.second[1].text.toString(),fields.second[2].text.toString(),fields.second[3].text.toString(),fields.second[4].text.toString(),fields.second[5].text.toString())}.onSuccess{repository.refreshLocal("Credential protected in Password Vault.");latest?.let(::render)}.onFailure(::showError)}.show()
    }
    private fun passwordDetailDialog(item:PasswordCredentialSummary){
        val actions=mutableListOf("Reveal for 10 seconds","Edit","Delete");if(item.hasTotp)actions.add(1,"Show TOTP")
        MaterialAlertDialogBuilder(this).setTitle(item.title)
            .setMessage(listOf(item.username,item.url,item.notes).filter{it.isNotBlank()}.joinToString("\n\n"))
            .setItems(actions.toTypedArray()){_,which->when(actions[which]){
                "Reveal for 10 seconds"->{
                    val raw=runCatching{app.passwords.reveal(item.credentialId)}.getOrElse{showError(it);return@setItems}
                    val value=raw.decodeToString();raw.fill(0)
                    val d=MaterialAlertDialogBuilder(this).setTitle(item.title).setMessage(value).setPositiveButton("Hide",null).create()
                    d.setOnShowListener{d.window?.addFlags(WindowManager.LayoutParams.FLAG_SECURE);lifecycleScope.launch{delay(10_000);if(d.isShowing){d.setMessage("Hidden");d.getButton(android.app.AlertDialog.BUTTON_POSITIVE).text="Close"}}};d.show()
                }
                "Show TOTP"->{runCatching{app.passwords.totp(item.credentialId)}.onSuccess{(code,seconds)->MaterialAlertDialogBuilder(this).setTitle("Authenticator code").setMessage("$code\n\nExpires in $seconds seconds.").setPositiveButton("Close",null).show()}.onFailure(::showError)}
                "Edit"->passwordEditDialog(item)
                "Delete"->MaterialAlertDialogBuilder(this).setTitle("Delete credential?").setMessage("This removes the local encrypted record.").setNegativeButton("Cancel",null).setPositiveButton("Delete"){_,_->runCatching{app.passwords.delete(item.credentialId)}.onSuccess{latest?.let(::render)}.onFailure(::showError)}.show()
            }}.show()
    }
    private fun passwordEditDialog(item:PasswordCredentialSummary){val fields=form("Title","Username","New password (blank keeps current)","URL","Notes","TOTP secret (blank removes)");fields.second[0].setText(item.title);fields.second[1].setText(item.username);fields.second[3].setText(item.url);fields.second[4].setText(item.notes);fields.second[2].inputType=InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD;MaterialAlertDialogBuilder(this).setTitle("Edit credential").setView(fields.first).setNegativeButton("Cancel",null).setPositiveButton("Save"){_,_->val pass=fields.second[2].text.toString().takeIf{it.isNotEmpty()};runCatching{app.passwords.update(item.credentialId,fields.second[0].text.toString(),fields.second[1].text.toString(),pass,fields.second[3].text.toString(),fields.second[4].text.toString(),fields.second[5].text.toString())}.onSuccess{latest?.let(::render)}.onFailure(::showError)}.show()}
    private fun passwordAuditDialog(){val entries=runCatching{app.passwords.audits().take(50)}.getOrElse{showError(it);emptyList()};MaterialAlertDialogBuilder(this).setTitle("Password Vault audit").setMessage(if(entries.isEmpty())"No audit entries." else entries.joinToString("\n"){"${friendlyDateTime(it.at)} · ${it.action}${it.detail?.let{d->" · $d"}.orEmpty()}"}).setPositiveButton("Close",null).show()}

    private fun chooseChatContact(s:AppSnapshot){val contacts=s.information.contacts.filter{it.card.format=="digitalspace-contact-v2"};if(contacts.isEmpty()){showError(IllegalStateException("Import a v2 Authentiverse contact card before using high-assurance chat."));return};MaterialAlertDialogBuilder(this).setTitle("Message someone").setItems(contacts.map{"@${it.card.handle}"}.toTypedArray()){_,i->conversationDialog(contacts[i].card.contactId,contacts[i].card.handle,s)}.show()}
    private fun conversationDialog(contactId: String, handle: String, s: AppSnapshot) {
        val body = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(18), dp(4), dp(18), dp(6)) }
        val history = runCatching { app.chat.messages(contactId) }.getOrElse { emptyList() }.takeLast(40)
        if (history.isEmpty()) {
            body.addView(TextView(this).apply {
                text = "Start a private conversation with @$handle."
                textSize = 13f; setTextColor(color(MUTED)); gravity = Gravity.CENTER
                setPadding(dp(12), dp(18), dp(12), dp(18))
            })
        } else history.forEach { body.addView(chatBubble(it, s), marginLp(-1, -2, 0, 3, 0, 3)) }
        val field = field("Message", true)
        body.addView(field.first, marginLp(-1, -2, 0, 14, 0, 0))
        val scroll = ScrollView(this).apply { addView(body) }
        MaterialAlertDialogBuilder(this)
            .setTitle("@$handle")
            .setView(scroll)
            .setNegativeButton("Close", null)
            .setNeutralButton("Private call") { _, _ ->
                if (s.state != SpaceState.INDOORS) showError(IllegalStateException("Connect to a Private Network before calling."))
                else launch {
                    val message = app.chat.inviteCall(contactId, s.persistent)
                    repository.refreshLocal("Private call invitation sent.")
                    openCall(requireNotNull(message.callRoomId), requireNotNull(message.callSecret), "@$handle")
                }
            }
            .setPositiveButton("Send") { _, _ ->
                val text = field.second.text?.toString().orEmpty().trim()
                if (text.isNotEmpty()) launch {
                    app.chat.sendText(contactId, text, ChatMessagePolicy.Keep, null, s.persistent)
                    repository.refreshLocal("Message sent.")
                }
            }.show()
    }
    private fun openCall(room:String,secret:String,name:String){val url="https://api.digitalspace.home.arpa/rtc#room=${Uri.encode(room)}&secret=${Uri.encode(secret)}&name=${Uri.encode(name)}";startActivity(Intent(this,IndoorBrowserActivity::class.java).putExtra("initial_uri",url).putExtra("call_mode",true))}

    private fun switchAccount(){
        val doSwitch={app.deactivate();startActivity(Intent(this,LauncherActivity::class.java));finish()}
        if(latest?.state==SpaceState.INDOORS) launch{runCatching{repository.goOutdoors()};doSwitch()} else doSwitch()
    }

    private fun agreementCard(nda: NdaAgreement, s: AppSnapshot, ownId: String?) {
        val sent = nda.issuerCertificate == s.persistent.foundationalCertificate
        val own = nda.participants.firstOrNull { it.contactId == ownId }; val expired = Instant.now().isAfter(nda.validUntil)
        val accepted = nda.participants.count { it.state == AgreementState.Accepted }; val declined = nda.participants.count { it.state == AgreementState.Declined }
        val status = when {
            expired -> "Expired"; sent && nda.participants.any { it.state == AgreementState.Pending } -> "$accepted/${nda.participants.size} signed"
            sent && declined > 0 -> "$declined declined"; sent -> "Complete"; own?.state == AgreementState.Accepted -> "Signed"
            own?.state == AgreementState.Declined -> "Declined"; else -> "Needs you"
        }
        listCard(if (sent) "↗" else "↙", nda.title,
            "${if (sent) "Sent to ${nda.participants.size}" else "From @${nda.issuerHandle}"} · ${nda.fileIds.size} file${if (nda.fileIds.size == 1) "" else "s"} · Ends ${friendlyDate(nda.validUntil)}",
            status) { ndaReview(nda) }
    }

    private fun ndaFilterChips() {
        val group = ChipGroup(this).apply { isSingleSelection = true; isSelectionRequired = true; chipSpacingHorizontal = dp(8) }
        listOf(NdaFilter.ALL to "All", NdaFilter.NEEDS_ACTION to "Needs you", NdaFilter.SENT to "Sent", NdaFilter.COMPLETED to "Completed").forEach { (filter, title) ->
            group.addView(Chip(this).apply {
                text = title; isCheckable = true; isChecked = ndaFilter == filter
                chipBackgroundColor = ColorStateList(arrayOf(intArrayOf(android.R.attr.state_checked), intArrayOf()), intArrayOf(color("#E8E7FF"), Color.WHITE))
                setTextColor(ColorStateList(arrayOf(intArrayOf(android.R.attr.state_checked), intArrayOf()), intArrayOf(color(PRIMARY_DARK), color(MUTED))))
                setOnClickListener { ndaFilter = filter; latest?.let(::render) }
            })
        }
        content.addView(HorizontalScrollView(this).apply { isHorizontalScrollBarEnabled = false; addView(group) }, marginLp(-1, -2, 0, 4, 0, 18))
    }

    private fun createNdaDialog(s: AppSnapshot) {
        val box = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(22), dp(8), dp(22), dp(18)) }
        box.addView(dialogIntro("Create one signed agreement and deliver it with every file selected below. One delivery can include up to 100 files."))
        val title = field("Agreement title"); val purpose = field("What is being shared and why?"); val terms = field("Agreement terms", multiline = true)
        box.addView(title.first); box.addView(purpose.first); box.addView(terms.first); box.addView(dialogSection("Expires after"))
        val expiry = RadioGroup(this).apply { orientation = RadioGroup.HORIZONTAL }
        listOf(7 to "7 days", 30 to "30 days", 90 to "90 days", 365 to "1 year").forEach { (days, label) ->
            expiry.addView(RadioButton(this).apply { text = label; tag = days; id = View.generateViewId(); isChecked = days == 30 }, RadioGroup.LayoutParams(0, -2, 1f))
        }
        box.addView(expiry); box.addView(dialogSection("After expiry"))
        val policy = RadioGroup(this).apply { orientation = RadioGroup.VERTICAL }
        policy.addView(RadioButton(this).apply { id = View.generateViewId(); tag = PostExpiryAccessPolicy.RevokeManagedAccess; text = "Lock managed files"; isChecked = true })
        policy.addView(RadioButton(this).apply { id = View.generateViewId(); tag = PostExpiryAccessPolicy.RetainAccess; text = "Keep access for people who signed" })
        box.addView(policy); box.addView(dialogSection("People"))
        val contacts = s.information.contacts.map { item -> MaterialCheckBox(this).apply { text = "@${item.card.handle}"; tag = item.card.contactId; box.addView(this) } }
        box.addView(dialogSection("Protected files"))
        val files = s.information.ownedFiles.map { item -> MaterialCheckBox(this).apply { text = "${item.descriptor.fileName} · ${bytes(item.descriptor.size)}"; tag = item.descriptor.fileId; box.addView(this) } }
        box.addView(dialogIntro("Creating this NDA signs its terms, file list and participants with your verified identity."))
        val dialog = MaterialAlertDialogBuilder(this).setTitle("New NDA").setView(ScrollView(this).apply { addView(box); layoutParams = lp(-1, dp(620)) })
            .setNegativeButton("Cancel", null).setPositiveButton("Create and sign", null).create()
        dialog.setOnShowListener {
            dialog.getButton(android.app.AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val days = expiry.findViewById<RadioButton>(expiry.checkedRadioButtonId)?.tag as? Int ?: 30
                val chosenPolicy = policy.findViewById<RadioButton>(policy.checkedRadioButtonId)?.tag as? PostExpiryAccessPolicy ?: PostExpiryAccessPolicy.RevokeManagedAccess
                launch {
                    val selectedFiles = files.filter { it.isChecked }.map { it.tag.toString() }
                    require(selectedFiles.size <= 100) { "Choose up to 100 files for one NDA delivery." }
                    repository.exchange.createAgreement(title.second.text.toString(), purpose.second.text.toString(), terms.second.text.toString(),
                        Instant.now().plus(days.toLong(), ChronoUnit.DAYS), chosenPolicy, contacts.filter { it.isChecked }.map { it.tag.toString() },
                        selectedFiles, s.persistent)
                    repository.refreshLocal("NDA created and signed. Open it to deliver the package."); dialog.dismiss()
                }
            }
        }
        dialog.show()
    }

    private fun ndaReview(nda: NdaAgreement) {
        val s = latest ?: return; val ownId = ownContactId(s); val sent = nda.issuerCertificate == s.persistent.foundationalCertificate
        val own = nda.participants.firstOrNull { it.contactId == ownId }; val pending = !sent && own?.state == AgreementState.Pending
        val body = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(22), dp(4), dp(22), dp(20)) }
        body.addView(dialogIntro(if (sent) "Signed by you and addressed separately to every person below." else "Review every term and covered file before signing your decision."))
        body.addView(detailRow("From", "@${nda.issuerHandle}")); body.addView(detailRow("Purpose", nda.purpose))
        body.addView(detailRow("Valid until", friendlyDateTime(nda.validUntil)))
        body.addView(detailRow("After expiry", if (nda.postExpiryPolicy == PostExpiryAccessPolicy.RevokeManagedAccess) "Managed files lock" else "Signed access remains"))
        body.addView(dialogSection("Terms")); body.addView(termsCard(nda.terms)); body.addView(dialogSection("Protected files"))
        nda.fileIds.forEach { body.addView(compactLine("F", fileNameFor(it, s))) }
        body.addView(dialogSection(if (sent) "People and signatures" else "Your decision"))
        nda.participants.forEach { body.addView(participantRow(it, nda, s, sent)) }
        if (!sent && own?.state != AgreementState.Pending) {
            val issuer = s.information.contacts.firstOrNull { it.card.signingCertificate == nda.issuerCertificate }
            if (issuer != null) body.addView(MaterialButton(this, null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
                text = if (s.state == SpaceState.INDOORS) "Send signed response again" else "Export signed response"
                setOnClickListener {
                    if (s.state == SpaceState.INDOORS) launch { repository.sendNdaIndoors(nda.ndaId, issuer.card.contactId) }
                    else exportNda(nda, issuer.card.contactId, "${nda.title}-response.dsnda")
                }
            }, marginLp(-1, dp(50), 0, 14, 0, 0))
        }
        val builder = MaterialAlertDialogBuilder(this).setTitle(nda.title).setView(ScrollView(this).apply { addView(body) }).setNegativeButton("Close", null)
        if (pending) builder.setNeutralButton("Decline and sign") { _, _ -> confirmDecision(nda, false) }
            .setPositiveButton("Accept and sign") { _, _ -> confirmDecision(nda, true) }
        builder.show()
    }

    private fun participantRow(participant: NdaParticipant, nda: NdaAgreement, s: AppSnapshot, sent: Boolean): View {
        val box = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(14)); background = rounded("#F8F9FC", 14) }
        val top = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL }
        top.addView(bodyStrong("@${participant.handle}"), LinearLayout.LayoutParams(0, -2, 1f))
        top.addView(badge(when (participant.state) { AgreementState.Accepted -> "Signed"; AgreementState.Declined -> "Declined"; AgreementState.Pending -> "Waiting" }, participant.state == AgreementState.Accepted))
        box.addView(top); participant.respondedAt?.let { box.addView(caption("Responded ${friendlyDateTime(it)}")) }
        if (sent) {
            val buttons = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.END }
            buttons.addView(smallButton("Export") { exportNda(nda, participant.contactId, "${nda.title}-${participant.handle}.dsnda") })
            if (s.state == SpaceState.INDOORS) buttons.addView(smallButton("Send securely") { launch { repository.sendNdaIndoors(nda.ndaId, participant.contactId) } })
            box.addView(buttons, marginLp(-1, -2, 0, 8, 0, 0))
        }
        return box.apply { layoutParams = marginLp(-1, -2, 0, 0, 0, 8) }
    }

    private fun confirmDecision(nda: NdaAgreement, accepted: Boolean) {
        MaterialAlertDialogBuilder(this).setTitle(if (accepted) "Accept and sign?" else "Decline and sign?")
            .setMessage(if (accepted) "Your verified identity will countersign this NDA. Its protected files will unlock inside Authentiverse."
            else "Your verified identity will sign a declined decision. The protected files will stay locked.")
            .setNegativeButton("Cancel", null).setPositiveButton(if (accepted) "Accept and sign" else "Decline and sign") { _, _ ->
                launch { repository.decideNda(nda.ndaId, accepted) }
            }.show()
    }

    private fun exportNda(nda: NdaAgreement, recipientId: String, suggestedName: String) {
        val s = latest ?: return; pendingExport = { repository.exchange.exportNda(nda.ndaId, recipientId, it, s.persistent) }
        createDocument.launch(safeName(suggestedName))
    }

    private fun enrollmentDialog() {
        val fields = form("Invitation code", "Full name", "Email", "Phone", "Username")
        MaterialAlertDialogBuilder(this).setTitle("Create your identity").setMessage("We’ll verify your email and phone, then create the private keys on this device.")
            .setView(fields.first).setNegativeButton("Cancel", null).setPositiveButton("Continue") { _, _ ->
                val values = fields.second.map { it.text?.toString().orEmpty() }
                launch { val started = repository.startEnrollment(values[0], values[1], values[2], values[3]); verificationDialog(started.id, started.emailCode, started.phoneCode, values[1], values[4]) }
            }.show()
    }

    private fun verificationDialog(id: String, developmentEmail: String?, developmentPhone: String?, name: String, handle: String) {
        val fields = form("Email code", "Phone code"); fields.second[0].setText(developmentEmail ?: ""); fields.second[1].setText(developmentPhone ?: "")
        MaterialAlertDialogBuilder(this).setTitle("Confirm it’s you").setView(fields.first).setNegativeButton("Later", null)
            .setPositiveButton("Finish") { _, _ -> launch { repository.finishEnrollment(id, fields.second[0].text.toString(), fields.second[1].text.toString(), name, handle) } }.show()
    }

    private fun openOwned(record: OwnedFileRecord) {
        launch {
            val bytes = withContext(Dispatchers.IO) { repository.information.readOwnedBytes(record.descriptor.fileId) }
            showProtectedViewer(bytes, record.displayName.ifBlank { record.descriptor.fileName }, record.descriptor.contentType, null)
        }
    }

    private fun openShared(record: SharedFileRecord) {
        launch {
            val bytes = withContext(Dispatchers.IO) { repository.information.readSharedBytes(record.shareId) }
            val nda=record.ndaId?.let{id->latest?.information?.agreements?.firstOrNull{it.ndaId==id}}
            val revokeAt=nda?.takeIf{it.postExpiryPolicy==PostExpiryAccessPolicy.RevokeManagedAccess}?.validUntil
            showProtectedViewer(bytes, record.descriptor.fileName, record.descriptor.contentType, revokeAt)
        }
    }

    private fun showProtectedViewer(data: ByteArray, name: String, type: String, revokeAt: Instant?) {
        require(data.size <= 64 * 1024 * 1024) { "This file is too large for the memory-only Secure Viewer." }
        secureViewer?.dismiss()
        val body = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(18)) }
        body.addView(LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = rounded("#F0F8F5", 14)
            setPadding(dp(14), dp(11), dp(14), dp(11))
            addView(TextView(this@MainActivity).apply { text = "✓  Protected view"; textSize = 13f; typeface = Typeface.DEFAULT_BOLD; setTextColor(color("#08735E")) })
            addView(TextView(this@MainActivity).apply { text = "Copy and export are unavailable for this protected file."; textSize = 11f; setTextColor(color(MUTED)); setPadding(0, dp(3), 0, 0) })
        }, marginLp(-1, -2, 0, 0, 0, 14))
        val bitmaps=mutableListOf<Bitmap>();var renderer:PdfRenderer?=null;var descriptor:ParcelFileDescriptor?=null;var callbackThread:HandlerThread?=null
        try {
            when {
                type.startsWith("image/") -> { val bitmap=decodeManagedImage(data);bitmaps+=bitmap;body.addView(ImageView(this).apply{setImageBitmap(bitmap);adjustViewBounds=true;scaleType=ImageView.ScaleType.FIT_CENTER}) }
                isSafeTextType(type,name) -> { require(data.size<=2*1024*1024){"This text file is too large for Secure Viewer."};body.addView(TextView(this).apply{text=data.toString(Charsets.UTF_8);textSize=15f;setTextColor(color(INK));setTextIsSelectable(false);setLineSpacing(0f,1.18f);setPadding(dp(8));setOnLongClickListener{true}}) }
                type.equals("application/pdf",true)||name.endsWith(".pdf",true) -> {
                    require(Build.VERSION.SDK_INT>=26){"Memory-only PDF viewing requires Android 8.0 or newer."}
                    val source=data
                    val thread=HandlerThread("AuthentiverseSecurePdf").also{it.start()};callbackThread=thread
                    val manager=getSystemService(StorageManager::class.java)
                    val pfd=manager.openProxyFileDescriptor(ParcelFileDescriptor.MODE_READ_ONLY,object:ProxyFileDescriptorCallback(){
                        override fun onGetSize():Long=source.size.toLong()
                        override fun onRead(offset:Long,size:Int,out:ByteArray):Int{if(offset>=source.size)return 0;val count=minOf(size,source.size-offset.toInt());source.copyInto(out,0,offset.toInt(),offset.toInt()+count);return count}
                        override fun onRelease() = Unit
                    },Handler(thread.looper));descriptor=pfd
                    val pdf=PdfRenderer(pfd);renderer=pdf;require(pdf.pageCount in 1..100){"This PDF has an unsupported page count."}
                    for(i in 0 until pdf.pageCount){pdf.openPage(i).use{page->val width=1200;val height=(width.toDouble()*page.height/page.width).toInt().coerceAtLeast(1);val bitmap=Bitmap.createBitmap(width,height,Bitmap.Config.ARGB_8888);page.render(bitmap,null,null,PdfRenderer.Page.RENDER_MODE_FOR_DISPLAY);bitmaps+=bitmap;body.addView(ImageView(this).apply{setImageBitmap(bitmap);adjustViewBounds=true;scaleType=ImageView.ScaleType.FIT_CENTER},marginLp(-1,-2,0,0,0,10))}}
                }
                else -> throw IllegalStateException("This file type stays encrypted because Authentiverse has no memory-only viewer for it yet.")
            }
        } catch(t:Throwable){data.fill(0);bitmaps.forEach{it.recycle()};runCatching{renderer?.close()};runCatching{descriptor?.close()};callbackThread?.quitSafely();throw t}
        val dialog=MaterialAlertDialogBuilder(this).setTitle(name).setView(ScrollView(this).apply{addView(body)}).setPositiveButton("Close",null).create();secureViewer=dialog
        dialog.setOnShowListener{dialog.window?.addFlags(WindowManager.LayoutParams.FLAG_SECURE);lifecycleScope.launch{while(dialog.isShowing){delay(1000);if(!app.vaultSession.isUnlocked||(revokeAt!=null&&!Instant.now().isBefore(revokeAt)))dialog.dismiss()}}}
        dialog.setOnDismissListener{data.fill(0);bitmaps.forEach{runCatching{it.recycle()}};runCatching{renderer?.close()};runCatching{descriptor?.close()};callbackThread?.quitSafely();if(secureViewer===dialog)secureViewer=null}
        dialog.show()
    }

    private fun decodeManagedImage(data: ByteArray): Bitmap {
        val bounds=BitmapFactory.Options().apply{inJustDecodeBounds=true};BitmapFactory.decodeByteArray(data,0,data.size,bounds);require(bounds.outWidth>0&&bounds.outHeight>0){"The protected image is invalid."};var sample=1;while(bounds.outWidth/sample>2048||bounds.outHeight/sample>2048)sample*=2;return requireNotNull(BitmapFactory.decodeByteArray(data,0,data.size,BitmapFactory.Options().apply{inSampleSize=sample})){"The protected image could not be opened."}
    }

    private fun handleDeepLink(uri: Uri) {
        val route = ProtocolRouter.route(uri)
        when (route.kind) {
            AuthentiverseRouteKind.PRIVACY_PRESENT, AuthentiverseRouteKind.MOI_REQUEST -> Unit
            AuthentiverseRouteKind.MOI_ATTRIBUTES, AuthentiverseRouteKind.MOI_EVIDENCE, AuthentiverseRouteKind.MOI_FILES, AuthentiverseRouteKind.MOI_IMPORT -> { section=Section.YOU; navigation.selectedItemId=5; return }
            AuthentiverseRouteKind.HTTPSA, AuthentiverseRouteKind.INDOOR -> { if (latest?.state==SpaceState.INDOORS) startActivity(Intent(this, IndoorBrowserActivity::class.java).putExtra("initial_uri", uri.toString())); else showError(IllegalStateException("Connect to a Private Network before opening this authenticated address.")); return }
            else -> return
        }
        val request = runCatching { PrivacyRequestParser.parse(uri, repository.privacy, setOf("https://home.digitalspace.home.arpa")) }.getOrElse { showError(it); return }
        val policy = repository.privacy.requirePolicy(request.predicateId)
        MaterialAlertDialogBuilder(this).setTitle("${request.verifierName} is requesting information")
            .setMessage("${request.purpose}\n\n${policy.description}\n\nYour private source value will not be shared. Authentiverse will show you the proof before anything is approved.")
            .setPositiveButton("Review request") { _, _ -> section = Section.YOU; navigation.selectedItemId = 5 }
            .setNegativeButton("Don’t allow", null).show()
    }

    private fun privacyWalletDialog() {
        val current = repository.privacy.load(); val fields = form("Date of birth (YYYY-MM-DD, optional)", "Gender (optional)")
        fields.second[0].setText(current.dateOfBirth.orEmpty()); fields.second[1].setText(current.gender.orEmpty())
        MaterialAlertDialogBuilder(this).setTitle("Private details").setMessage("These values stay encrypted on this phone. Changing them removes derived credentials.")
            .setView(fields.first).setNeutralButton("Erase") { _, _ -> repository.privacy.clear(); repository.refreshLocal("Private details erased.") }
            .setNegativeButton("Cancel", null).setPositiveButton("Save privately") { _, _ ->
                runCatching { repository.privacy.save(fields.second[0].text?.toString(), fields.second[1].text?.toString()) }
                    .onSuccess { repository.refreshLocal("Private details updated.") }.onFailure(::showError)
            }.show()
    }

    private fun greeting(): String = when (LocalTime.now().hour) {
        in 5..11 -> "Good morning"
        in 12..17 -> "Good afternoon"
        else -> "Good evening"
    }

    private fun initials(value: String): String = value.trim().removePrefix("@").split(Regex("\\s+"))
        .filter(String::isNotBlank).take(2).joinToString("") { it.take(1).uppercase(Locale.getDefault()) }.ifBlank { "A" }

    private fun shortTime(value: Instant): String = DateTimeFormatter.ofPattern("HH:mm", Locale.getDefault())
        .withZone(ZoneId.systemDefault()).format(value)

    private fun messagePreview(message: ChatStoredMessage): String = when {
        message.kind == "call_invite" && message.outgoing -> "You started a private call"
        message.kind == "call_invite" -> "Private call invitation"
        message.policy == ChatMessagePolicy.ViewOnce && !message.outgoing -> if (message.viewConsumed) "View-once message opened" else "View-once message"
        message.text.isNullOrBlank() -> "Protected message"
        message.outgoing -> "You: ${message.text}"
        else -> message.text.orEmpty()
    }

    private fun connectArea(areaId: String) {
        val permission = VpnService.prepare(this)
        if (permission != null) { pendingArea = areaId; vpnPermission.launch(permission) }
        else launch { repository.enterArea(areaId) }
    }

    private fun identitySetupCard() {
        val c = card()
        val box = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(19)) }
        box.addView(TextView(this).apply { text = "Your identity is not set up yet"; textSize = 18f; typeface = Typeface.DEFAULT_BOLD; setTextColor(color(INK)) })
        box.addView(TextView(this).apply { text = "Verify your details once, then use the same Authentiverse identity for private networks, protected files and trusted services."; textSize = 13f; setTextColor(color(MUTED)); setPadding(0, dp(7), 0, 0) })
        c.addView(box)
        content.addView(c, marginLp(-1, -2, 0, 0, 0, 14))
    }

    private fun identityCard(s: AppSnapshot, score: Int, verified: Boolean) {
        val c = card()
        val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL; setPadding(dp(18)) }
        val accountName = app.active?.account?.displayName ?: "Authentiverse"
        row.addView(TextView(this).apply {
            text = initials(accountName)
            gravity = Gravity.CENTER
            textSize = 19f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(Color.WHITE)
            background = GradientDrawable().apply { shape = GradientDrawable.OVAL; setColor(color(PRIMARY)) }
        }, LinearLayout.LayoutParams(dp(56), dp(56)))
        row.addView(LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; setPadding(dp(13), 0, dp(8), 0)
            addView(TextView(this@MainActivity).apply { text = accountName; textSize = 18f; typeface = Typeface.DEFAULT_BOLD; setTextColor(color(INK)); maxLines = 1 })
            addView(TextView(this@MainActivity).apply { text = "@${s.persistent.profileHandle}"; textSize = 13f; setTextColor(color(MUTED)); setPadding(0, dp(2), 0, 0) })
            addView(TextView(this@MainActivity).apply { text = "✓ Verified identity"; textSize = 12f; setTextColor(color("#08735E")); setPadding(0, dp(4), 0, 0) })
        }, LinearLayout.LayoutParams(0, -2, 1f))
        row.addView(IdentityLevelRingView(this).apply { setIdentityScore(score, verified); setOnClickListener { identityLevelDialog(s) } }, LinearLayout.LayoutParams(dp(82), dp(82)))
        c.addView(row)
        c.setOnClickListener { section = Section.YOU; navigation.selectedItemId = 5 }
        content.addView(c, marginLp(-1, -2, 0, 0, 0, 14))
    }

    private fun quickActions(s: AppSnapshot) {
        val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        row.addView(actionTile(pro.digitalspace.android.R.drawable.ic_av_send, "Send", "Message") {
            if (s.state == SpaceState.INDOORS) chooseChatContact(s) else showError(IllegalStateException("Connect to a Private Network before messaging."))
        }, LinearLayout.LayoutParams(0, dp(94), 1f).apply { marginEnd = dp(8) })
        row.addView(actionTile(pro.digitalspace.android.R.drawable.ic_av_share, "Share", "Securely") { shareActionDialog(s) }, LinearLayout.LayoutParams(0, dp(94), 1f).apply { marginEnd = dp(8) })
        row.addView(actionTile(pro.digitalspace.android.R.drawable.ic_av_open, "Open", "Browser") { section = Section.BROWSER; navigation.selectedItemId = 4 }, LinearLayout.LayoutParams(0, dp(94), 1f))
        content.addView(row, marginLp(-1, -2, 0, 0, 0, 14))
    }

    private fun actionTile(icon: Int, title: String, subtitle: String, action: () -> Unit): View {
        val c = card()
        c.isClickable = true; c.isFocusable = true; c.setOnClickListener { action() }
        val box = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; gravity = Gravity.CENTER; setPadding(dp(8)) }
        box.addView(ImageView(this).apply { setImageResource(icon); imageTintList = ColorStateList.valueOf(color(PRIMARY)); contentDescription = title }, LinearLayout.LayoutParams(dp(24), dp(24)))
        box.addView(TextView(this).apply { text = title; textSize = 14f; typeface = Typeface.DEFAULT_BOLD; setTextColor(color(INK)); gravity = Gravity.CENTER; setPadding(0, dp(7), 0, 0) })
        box.addView(TextView(this).apply { text = subtitle; textSize = 10f; setTextColor(color(MUTED)); gravity = Gravity.CENTER })
        c.addView(box)
        return c
    }

    private fun protectionSummary(s: AppSnapshot): String = when (s.state) {
        SpaceState.INDOORS -> if (s.persistent.isolatedIndoor) "Private Network connected · public internet paused" else "Private Network connected · identity authenticated"
        SpaceState.UNINITIALIZED -> "Identity setup required"
        else -> "Device and Vault protected · Private Network disconnected"
    }

    private fun protectionCard(s: AppSnapshot, score: Int, verified: Boolean) {
        val c = card("#F0F8F5")
        c.isClickable = true; c.isFocusable = true; c.setOnClickListener { securityCenterDialog(s) }
        val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL; setPadding(dp(17)) }
        row.addView(ImageView(this).apply { setImageResource(pro.digitalspace.android.R.drawable.ic_av_shield); imageTintList = ColorStateList.valueOf(Color.WHITE); background = GradientDrawable().apply { shape = GradientDrawable.OVAL; setColor(color("#08735E")) }; setPadding(dp(9), dp(9), dp(9), dp(9)); contentDescription = "Protected" }, LinearLayout.LayoutParams(dp(42), dp(42)))
        row.addView(LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; setPadding(dp(12), 0, 0, 0)
            addView(TextView(this@MainActivity).apply { text = "Protected"; textSize = 16f; typeface = Typeface.DEFAULT_BOLD; setTextColor(color(INK)) })
            addView(TextView(this@MainActivity).apply { text = protectionSummary(s); textSize = 12f; setTextColor(color(MUTED)); maxLines = 2 })
            if (verified) addView(TextView(this@MainActivity).apply { text = "Identity Level ${app.idqa.level(score).first}"; textSize = 11f; setTextColor(color("#08735E")); setPadding(0, dp(3), 0, 0) })
        }, LinearLayout.LayoutParams(0, -2, 1f))
        row.addView(TextView(this).apply { text = "›"; textSize = 28f; setTextColor(color("#98A2B3")) })
        c.addView(row)
        content.addView(c, marginLp(-1, -2, 0, 0, 0, 18))
    }

    private fun shareActionDialog(s: AppSnapshot) {
        val actions = arrayOf("Share my contact", "Protect a file", "Create a protected agreement", "Personal information")
        MaterialAlertDialogBuilder(this).setTitle("Share securely").setItems(actions) { _, which ->
            when (which) {
                0 -> { pendingExport = { repository.exchange.exportContact(it, s.persistent) }; createDocument.launch("${s.persistent.profileHandle}.dscontact") }
                1 -> addFile.launch(arrayOf("*/*"))
                2 -> if (s.information.contacts.isNotEmpty() && s.information.ownedFiles.isNotEmpty()) createNdaDialog(s) else showError(IllegalStateException("Add a protected file and a trusted person first."))
                3 -> { section = Section.YOU; navigation.selectedItemId = 5; privacyWalletDialog() }
            }
        }.show()
    }

    private fun securityCenterDialog(s: AppSnapshot) {
        val idqa = runCatching { app.idqa.current(s.persistent) }.getOrNull()
        val score = idqa?.attestation?.scores?.total ?: 0
        val level = app.idqa.level(score).first
        val keyState = app.active?.keys
        val pqReady = runCatching { app.active?.pq?.publicMaterial(); true }.getOrDefault(false)
        val body = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(20), dp(4), dp(20), dp(4)) }
        body.addView(TextView(this).apply { text = "Authentiverse Protection"; textSize = 22f; typeface = Typeface.DEFAULT_BOLD; setTextColor(color(INK)) })
        body.addView(TextView(this).apply { text = "Security stays visible in plain language. Technical details are available when you need them."; textSize = 13f; setTextColor(color(MUTED)); setPadding(0, dp(5), 0, dp(16)) })
        body.addView(securityLine("Identity unlocked", app.vaultSession.isUnlocked))
        body.addView(securityLine("Device key protected", keyState?.isNonExportable("foundational") == true))
        body.addView(securityLine("Post-quantum identity ready", pqReady))
        body.addView(securityLine("Private Network connected", s.state == SpaceState.INDOORS))
        body.addView(securityLine(if (idqa?.validation?.isValid == true) "Identity Level $level · $score trust points" else "Identity assessment not verified", idqa?.validation?.isValid == true))
        MaterialAlertDialogBuilder(this).setView(body)
            .setNegativeButton("Close", null)
            .setNeutralButton("Certificates") { _, _ -> certificateDialog(s) }
            .setPositiveButton("Identity Level") { _, _ -> identityLevelDialog(s) }
            .show()
    }

    private fun securityLine(label: String, positive: Boolean): View = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL; setPadding(0, dp(7), 0, dp(7))
        addView(TextView(this@MainActivity).apply { text = if (positive) "✓" else "•"; textSize = 14f; typeface = Typeface.DEFAULT_BOLD; setTextColor(color(if (positive) "#08735E" else "#98A2B3")); gravity = Gravity.CENTER }, LinearLayout.LayoutParams(dp(28), dp(28)))
        addView(TextView(this@MainActivity).apply { text = label; textSize = 14f; setTextColor(color(INK)) }, LinearLayout.LayoutParams(0, -2, 1f))
    }

    private fun identityLevelDialog(s: AppSnapshot) {
        val idqa = runCatching { app.idqa.current(s.persistent) }.getOrNull()
        val score = idqa?.attestation?.scores?.total ?: 0
        val (level, progressValue) = app.idqa.level(score)
        val valid = idqa?.validation?.isValid == true
        val message = if (valid) "Level $level · $score trust points\n\n$progressValue/12 points toward the next level. Your assessment is bound to this verified profile." else "No verified Identity Level assessment is installed for this profile yet."
        MaterialAlertDialogBuilder(this).setTitle("Identity Level").setMessage(message)
            .setItems(arrayOf("Import trust bundle", "Import identity assessment", "View certificate details")) { _, which ->
                when (which) {
                    0 -> importIdqaBundle.launch(arrayOf("application/json", "*/*"))
                    1 -> importIdqaAttestation.launch(arrayOf("application/json", "*/*"))
                    2 -> certificateDialog(s)
                }
            }.setPositiveButton("Close", null).show()
    }

    private fun trustedPeopleDialog(s: AppSnapshot) {
        val people = s.information.contacts.sortedBy { it.card.handle }
        MaterialAlertDialogBuilder(this).setTitle("Trusted people")
            .setMessage(if (people.isEmpty()) "No verified people have been added yet." else people.joinToString("\n") { "✓ @${it.card.handle}" })
            .setNegativeButton("Close", null)
            .setNeutralButton("Share my contact") { _, _ -> pendingExport = { repository.exchange.exportContact(it, s.persistent) }; createDocument.launch("${s.persistent.profileHandle}.dscontact") }
            .setPositiveButton("Add person") { _, _ -> importPackage.launch(arrayOf("application/json", "*/*")) }
            .show()
    }

    private fun chatBubble(message: ChatStoredMessage, s: AppSnapshot): View {
        val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = if (message.outgoing) Gravity.END else Gravity.START }
        val bubble = TextView(this).apply {
            text = messagePreview(message)
            textSize = 14f
            setTextColor(color(if (message.outgoing) "#FFFFFF" else INK))
            background = rounded(if (message.outgoing) PRIMARY else "#F2F4F7", 16)
            setPadding(dp(13), dp(10), dp(13), dp(10))
            maxWidth = (resources.displayMetrics.widthPixels * 0.72).toInt()
            if ((message.kind == "call_invite" && !message.outgoing) || (message.policy == ChatMessagePolicy.ViewOnce && !message.outgoing && !message.viewConsumed)) {
                isClickable = true
                setOnClickListener {
                    if (message.kind == "call_invite") {
                        val call = app.chat.consumeCall(message.messageId)
                        if (call != null) openCall(call.roomId, call.secret, call.displayName) else showError(IllegalStateException("This call invitation is no longer available."))
                    } else {
                        val viewed = app.chat.consumeViewOnce(message.messageId)
                        MaterialAlertDialogBuilder(this@MainActivity).setTitle(message.contactDisplayName).setMessage(viewed?.text ?: "This view-once message was already consumed.").setPositiveButton("Close", null).show()
                        render(s)
                    }
                }
            }
        }
        row.addView(bubble, LinearLayout.LayoutParams(-2, -2))
        return row
    }

    private fun hero(eyebrow: String, title: String, text: String, active: Boolean) {
        val card = MaterialCardView(this).apply { radius = dp(24).toFloat(); strokeWidth = 0; cardElevation = 0f }
        val box = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; setPadding(dp(22), dp(22), dp(22), dp(24))
            background = GradientDrawable(GradientDrawable.Orientation.TL_BR,
                if (active) intArrayOf(color("#083B3A"), color("#126D62")) else intArrayOf(color("#26245F"), color("#5B58D6"))).apply { cornerRadius = dp(24).toFloat() }
            addView(TextView(this@MainActivity).apply { this.text = eyebrow; textSize = 11f; letterSpacing = .14f; setTextColor(color("#D8D7FF")); typeface = Typeface.DEFAULT_BOLD })
            addView(TextView(this@MainActivity).apply { this.text = title; textSize = 28f; setTextColor(Color.WHITE); typeface = Typeface.create("sans-serif", Typeface.BOLD); setPadding(0, dp(8), 0, dp(5)) })
            addView(TextView(this@MainActivity).apply { this.text = text; textSize = 15f; setTextColor(color("#EEEDF9")); setLineSpacing(0f, 1.15f) })
        }
        card.addView(box); content.addView(card, marginLp(-1, -2, 0, 0, 0, 18))
    }

    private fun sectionTitle(value: String) { content.addView(TextView(this).apply { text = value; textSize = 19f; setTextColor(color(INK)); typeface = Typeface.DEFAULT_BOLD }, marginLp(-1, -2, 2, 22, 0, 10)) }
    private fun listCard(glyph: String, title: String, subtitle: String, trailing: String, click: (() -> Unit)?) {
        val card = card(); if (click != null) { card.isClickable = true; card.isFocusable = true; card.setOnClickListener { click() } }
        val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL; setPadding(dp(16)) }
        row.addView(TextView(this).apply { text = glyph; gravity = Gravity.CENTER; textSize = 16f; setTextColor(color(PRIMARY_DARK)); typeface = Typeface.DEFAULT_BOLD; background = rounded("#ECEBFF", 14) }, LinearLayout.LayoutParams(dp(44), dp(44)).apply { marginEnd = dp(13) })
        row.addView(LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; addView(bodyStrong(title)); addView(caption(subtitle)) }, LinearLayout.LayoutParams(0, -2, 1f))
        row.addView(badge(trailing, trailing in setOf("Signed", "Protected", "Verified", "Complete"))); card.addView(row)
        content.addView(card, marginLp(-1, -2, 0, 0, 0, 10))
    }
    private fun simpleCard(title: String, text: String, trailing: String, positive: Boolean) {
        val card = card(); val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL; setPadding(dp(17)) }
        row.addView(LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; addView(bodyStrong(title)); addView(caption(text)) }, LinearLayout.LayoutParams(0, -2, 1f))
        row.addView(badge(trailing, positive)); card.addView(row); content.addView(card, marginLp(-1, -2, 0, 0, 0, 10))
    }
    private fun emptyState(title: String, text: String) {
        val card = card("#FAFBFC"); card.addView(LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; gravity = Gravity.CENTER; setPadding(dp(22), dp(26), dp(22), dp(26)); addView(bodyStrong(title)); addView(caption(text).apply { gravity = Gravity.CENTER; setPadding(0, dp(6), 0, 0) }) })
        content.addView(card, marginLp(-1, -2, 0, 0, 0, 12))
    }
    private fun metricStrip(values: List<Pair<String, String>>) {
        val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        values.forEachIndexed { index, item ->
            val box = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(14)); background = rounded(Color.WHITE, 16); addView(caption(item.first)); addView(TextView(this@MainActivity).apply { text = item.second; textSize = 17f; setTextColor(color(INK)); typeface = Typeface.DEFAULT_BOLD; maxLines = 1 }) }
            row.addView(box, LinearLayout.LayoutParams(0, dp(76), 1f).apply { if (index < values.lastIndex) marginEnd = dp(8) })
        }
        content.addView(row, marginLp(-1, -2, 0, 0, 0, 18))
    }
    private fun primaryButton(text: String, enabled: Boolean = true, click: () -> Unit) {
        content.addView(MaterialButton(this).apply { this.text = text; isEnabled = enabled; cornerRadius = dp(16); setTextColor(Color.WHITE); setBackgroundColor(color(PRIMARY)); setOnClickListener { click() } }, marginLp(-1, dp(54), 0, 0, 0, 10))
    }
    private fun secondaryButton(text: String, click: () -> Unit) {
        content.addView(MaterialButton(this, null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply { this.text = text; cornerRadius = dp(16); strokeColor = ColorStateList.valueOf(color(BORDER)); setTextColor(color(INK)); setOnClickListener { click() } }, marginLp(-1, dp(52), 0, 0, 0, 8))
    }
    private fun textButton(text: String, danger: Boolean = false, click: () -> Unit) {
        content.addView(MaterialButton(this).apply {
            this.text = text
            backgroundTintList = ColorStateList.valueOf(Color.TRANSPARENT)
            strokeWidth = 0
            elevation = 0f
            setTextColor(color(if (danger) DANGER else PRIMARY))
            setOnClickListener { click() }
        }, marginLp(-1, dp(46), 0, 0, 0, 4))
    }
    private fun rowButtons(first: Pair<String, () -> Unit>, second: Pair<String, () -> Unit>) {
        val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        listOf(first, second).forEachIndexed { index, item ->
            row.addView(MaterialButton(this, null, if (index == 0) com.google.android.material.R.attr.materialButtonStyle else com.google.android.material.R.attr.materialButtonOutlinedStyle).apply { text = item.first; cornerRadius = dp(15); setOnClickListener { item.second() } }, LinearLayout.LayoutParams(0, dp(52), 1f).apply { if (index == 0) marginEnd = dp(8) })
        }; content.addView(row, marginLp(-1, -2, 0, 0, 0, 16))
    }
    private fun smallButton(text: String, click: () -> Unit) = MaterialButton(this).apply {
        this.text = text
        backgroundTintList = ColorStateList.valueOf(Color.TRANSPARENT)
        strokeWidth = 0
        elevation = 0f
        minHeight = 0
        minimumHeight = 0
        setTextColor(color(PRIMARY))
        setOnClickListener { click() }
    }
    private fun card(background: String = "#FFFFFF") = MaterialCardView(this).apply { radius = dp(18).toFloat(); strokeWidth = dp(1); strokeColor = color(BORDER); setCardBackgroundColor(color(background)); cardElevation = 0f }
    private fun badge(value: String, positive: Boolean) = TextView(this).apply { text = value; textSize = 11f; typeface = Typeface.DEFAULT_BOLD; gravity = Gravity.CENTER; setTextColor(color(if (positive) "#08735E" else "#596174")); background = rounded(if (positive) "#E4F6F0" else "#EEF0F4", 20); setPadding(dp(10), dp(6), dp(10), dp(6)) }
    private fun compactLine(glyph: String, value: String) = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL; setPadding(0, dp(5), 0, dp(5)); addView(badge(glyph, false), LinearLayout.LayoutParams(dp(36), dp(30)).apply { marginEnd = dp(8) }); addView(bodyText(value), LinearLayout.LayoutParams(0, -2, 1f)) }
    private fun termsCard(value: String) = TextView(this).apply { text = value; textSize = 14f; setTextColor(color(INK)); setLineSpacing(0f, 1.16f); setPadding(dp(15)); background = rounded("#F8F9FC", 14) }
    private fun detailRow(name: String, value: String) = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; addView(caption(name.uppercase(Locale.ROOT))); addView(bodyStrong(value)); setPadding(0, dp(5), 0, dp(10)) }
    private fun dialogSection(value: String) = TextView(this).apply { text = value; textSize = 14f; setTextColor(color(INK)); typeface = Typeface.DEFAULT_BOLD; setPadding(0, dp(18), 0, dp(8)) }
    private fun dialogIntro(value: String) = TextView(this).apply { text = value; textSize = 13f; setTextColor(color(MUTED)); setLineSpacing(0f, 1.15f); setPadding(0, dp(4), 0, dp(8)) }
    private fun trustNote(value: String) { content.addView(TextView(this).apply { text = "✓  $value"; textSize = 12f; setTextColor(color("#4B5565")); setPadding(dp(14)); background = rounded("#EEF8F5", 14) }, marginLp(-1, -2, 0, 8, 0, 14)) }
    private fun bodyStrong(value: String) = TextView(this).apply { text = value; textSize = 15f; setTextColor(color(INK)); typeface = Typeface.DEFAULT_BOLD }
    private fun bodyText(value: String) = TextView(this).apply { text = value; textSize = 14f; setTextColor(color("#475467")) }
    private fun caption(value: String) = TextView(this).apply { text = value; textSize = 12f; setTextColor(color(MUTED)); setLineSpacing(0f, 1.1f) }

    private fun field(hint: String, multiline: Boolean = false): Pair<TextInputLayout, TextInputEditText> {
        val edit = TextInputEditText(this).apply { if (multiline) { minLines = 6; gravity = Gravity.TOP; inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE } }
        return TextInputLayout(this).apply { this.hint = hint; boxBackgroundMode = TextInputLayout.BOX_BACKGROUND_OUTLINE; boxBackgroundColor = Color.WHITE; setBoxCornerRadii(dp(14).toFloat(), dp(14).toFloat(), dp(14).toFloat(), dp(14).toFloat()); addView(edit); layoutParams = marginLp(-1, -2, 0, 5, 0, 8) } to edit
    }
    private fun form(vararg names: String): Pair<ScrollView, List<TextInputEditText>> {
        val box = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(20)) }; val edits = names.map { field(it).also { pair -> box.addView(pair.first) }.second }
        return ScrollView(this).apply { addView(box) } to edits
    }
    private fun ownContactId(s: AppSnapshot): String? = runCatching { repository.exchange.ownContact(s.persistent).contactId }.getOrNull()
    private fun pendingForMe(s: AppSnapshot): Int { val own = ownContactId(s); return s.information.agreements.count { it.issuerCertificate != s.persistent.foundationalCertificate && it.participants.any { p -> p.contactId == own && p.state == AgreementState.Pending } } }
    private fun fileNameFor(fileId: String, s: AppSnapshot): String = s.information.ownedFiles.firstOrNull { it.descriptor.fileId == fileId }?.descriptor?.fileName ?: s.information.sharedFiles.firstOrNull { it.descriptor.fileId == fileId }?.descriptor?.fileName ?: "Protected file"
    private fun previewTarget(name: String): File { val directory = File(cacheDir, "managed-previews").apply { mkdirs(); listFiles()?.forEach(File::delete) }; return File(directory, safeName(name).take(120)) }
    private fun safeName(value: String): String = value.replace(Regex("[^A-Za-z0-9._-]"), "_").take(160).ifBlank { "authentiverse-file" }
    private fun isSafeTextType(type: String, name: String): Boolean = type.startsWith("text/") || name.substringAfterLast('.', "").lowercase() in setOf("txt", "md", "csv", "json", "xml", "log")
    private fun friendlyDate(value: Instant): String = DateTimeFormatter.ofPattern("d MMM yyyy", Locale.getDefault()).withZone(ZoneId.systemDefault()).format(value)
    private fun friendlyDateTime(value: Instant): String = DateTimeFormatter.ofPattern("d MMM yyyy · HH:mm", Locale.getDefault()).withZone(ZoneId.systemDefault()).format(value)
    private fun bytes(value: Long): String = when { value >= 1L shl 30 -> "%.1f GB".format(value.toDouble() / (1L shl 30)); value >= 1L shl 20 -> "%.1f MB".format(value.toDouble() / (1L shl 20)); value >= 1L shl 10 -> "%.1f KB".format(value.toDouble() / (1L shl 10)); else -> "$value B" }
    private fun launch(block: suspend () -> Unit) { lifecycleScope.launch { runCatching { block() }.onFailure(::showError) } }
    private fun showError(error: Throwable) { Snackbar.make(root, error.message ?: "Something went wrong.", Snackbar.LENGTH_LONG).show() }
    private fun rounded(value: String, radius: Int) = rounded(color(value), radius)
    private fun rounded(value: Int, radius: Int) = GradientDrawable().apply { shape = GradientDrawable.RECTANGLE; setColor(value); cornerRadius = dp(radius).toFloat() }
    private fun color(value: String) = Color.parseColor(value)
    private fun dp(value: Int) = (value * resources.displayMetrics.density).toInt()
    private fun lp(width: Int, height: Int) = LinearLayout.LayoutParams(width, height)
    private fun marginLp(width: Int, height: Int, left: Int, top: Int, right: Int, bottom: Int) = LinearLayout.LayoutParams(width, height).apply { setMargins(dp(left), dp(top), dp(right), dp(bottom)) }
}
