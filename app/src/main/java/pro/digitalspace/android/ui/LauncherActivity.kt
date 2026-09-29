/* SPDX-License-Identifier: MIT */
package pro.digitalspace.android.ui

import android.content.Intent
import android.content.res.ColorStateList
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.WindowCompat
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout
import pro.digitalspace.android.DigitalSpaceApplication
import pro.digitalspace.android.R
import pro.digitalspace.android.account.AuthentiverseAccount
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Locale

class LauncherActivity : AppCompatActivity() {
    companion object {
        private const val BG = "#F7F8FB"
        private const val INK = "#111827"
        private const val MUTED = "#667085"
        private const val PRIMARY = "#5755D9"
        private const val BORDER = "#E4E7EC"
        private const val SAFE = "#08735E"
    }

    private lateinit var app: DigitalSpaceApplication
    private lateinit var content: LinearLayout
    private var pendingUri: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        app = application as DigitalSpaceApplication
        pendingUri = intent?.dataString ?: intent?.getStringExtra("route_uri")
        window.statusBarColor = color(BG)
        window.navigationBarColor = color(BG)
        WindowCompat.getInsetsController(window, window.decorView).apply {
            isAppearanceLightStatusBars = true
            isAppearanceLightNavigationBars = true
        }
        render()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        pendingUri = intent.dataString ?: pendingUri
        render()
    }

    private fun render() {
        val scroll = ScrollView(this).apply {
            isFillViewport = true
            overScrollMode = View.OVER_SCROLL_NEVER
            setBackgroundColor(color(BG))
        }
        content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(22), dp(36), dp(22), dp(32))
        }
        scroll.addView(content)
        setContentView(scroll)

        val brand = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        brand.addView(ImageView(this).apply {
            setImageResource(R.drawable.ic_av_shield)
            imageTintList = ColorStateList.valueOf(Color.WHITE)
            background = circle(PRIMARY)
            setPadding(dp(10), dp(10), dp(10), dp(10))
            contentDescription = "Authentiverse"
        }, LinearLayout.LayoutParams(dp(44), dp(44)))
        brand.addView(TextView(this).apply {
            text = "Authentiverse"
            textSize = 20f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(color(INK))
            setPadding(dp(12), 0, 0, 0)
        })
        content.addView(brand)

        content.addView(TextView(this).apply {
            text = "Choose an account"
            textSize = 30f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(color(INK))
            setPadding(0, dp(32), 0, dp(6))
        })
        content.addView(TextView(this).apply {
            text = "Your messages, Vault and identity stay hidden until you unlock an account."
            textSize = 15f
            setTextColor(color(MUTED))
            setLineSpacing(0f, 1.12f)
            setPadding(0, 0, 0, dp(22))
        })

        val accounts = app.accounts.load()
        if (accounts.isEmpty()) {
            val empty = MaterialCardView(this).apply {
                radius = dp(20).toFloat(); strokeWidth = dp(1); strokeColor = color(BORDER)
                setCardBackgroundColor(Color.WHITE); cardElevation = 0f
            }
            empty.addView(LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL; gravity = Gravity.CENTER
                setPadding(dp(24), dp(30), dp(24), dp(30))
                addView(TextView(this@LauncherActivity).apply { text = "No accounts on this device"; textSize = 17f; typeface = Typeface.DEFAULT_BOLD; setTextColor(color(INK)) })
                addView(TextView(this@LauncherActivity).apply { text = "Create an account to set up your private identity and Vault."; textSize = 13f; gravity = Gravity.CENTER; setTextColor(color(MUTED)); setPadding(0, dp(7), 0, 0) })
            })
            content.addView(empty, marginLp(-1, -2, 0, 0, 0, 14))
        } else {
            accounts.forEach(::accountCard)
        }

        content.addView(MaterialButton(this).apply {
            text = "Add account"
            isAllCaps = false
            cornerRadius = dp(16)
            setTextColor(Color.WHITE)
            backgroundTintList = ColorStateList.valueOf(color(PRIMARY))
            setOnClickListener { createDialog() }
        }, marginLp(-1, dp(54), 0, 8, 0, 0))

        val reloadable = app.accounts.reloadableAccounts()
        if (reloadable.isNotEmpty()) {
            content.addView(MaterialButton(this, null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
                text = "Load an existing account"
                isAllCaps = false
                cornerRadius = dp(16)
                strokeColor = ColorStateList.valueOf(color(BORDER))
                setTextColor(color(INK))
                setOnClickListener { chooseReloadable(reloadable) }
            }, marginLp(-1, dp(52), 0, 8, 0, 0))
        }

        val footer = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER
            setPadding(0, dp(26), 0, 0)
            addView(TextView(this@LauncherActivity).apply {
                text = "✓"
                textSize = 13f
                typeface = Typeface.DEFAULT_BOLD
                setTextColor(color(SAFE))
            })
            addView(TextView(this@LauncherActivity).apply {
                text = "  Protected on this device"
                textSize = 12f
                setTextColor(color(MUTED))
            })
        }
        content.addView(footer)
    }

    private fun accountCard(account: AuthentiverseAccount) {
        val card = MaterialCardView(this).apply {
            radius = dp(20).toFloat(); strokeWidth = dp(1); strokeColor = color(BORDER)
            setCardBackgroundColor(Color.WHITE); cardElevation = 0f
            isClickable = true; isFocusable = true
            foreground = getDrawable(android.R.drawable.list_selector_background)
            setOnClickListener { unlockDialog(account) }
        }
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(16), dp(15), dp(14), dp(15))
        }
        row.addView(TextView(this).apply {
            text = initials(account.displayName)
            gravity = Gravity.CENTER
            textSize = 16f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(Color.WHITE)
            background = circle(PRIMARY)
        }, LinearLayout.LayoutParams(dp(48), dp(48)))
        val labels = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(14), 0, dp(8), 0)
            addView(TextView(this@LauncherActivity).apply {
                text = account.displayName
                textSize = 16f
                typeface = Typeface.DEFAULT_BOLD
                setTextColor(color(INK))
                maxLines = 1
            })
            addView(TextView(this@LauncherActivity).apply {
                text = account.lastKnownHandle?.let { "@$it" } ?: if (account.legacy) "Existing account" else "Local Authentiverse account"
                textSize = 13f
                setTextColor(color(MUTED))
                setPadding(0, dp(3), 0, 0)
            })
            if (account.lastUsedAt.epochSecond > 0) addView(TextView(this@LauncherActivity).apply {
                text = "Last used ${DateTimeFormatter.ofPattern("d MMM", Locale.getDefault()).withZone(ZoneId.systemDefault()).format(account.lastUsedAt)}"
                textSize = 11f
                setTextColor(color("#98A2B3"))
                setPadding(0, dp(3), 0, 0)
            })
        }
        row.addView(labels, LinearLayout.LayoutParams(0, -2, 1f))
        row.addView(TextView(this).apply {
            text = "›"
            textSize = 30f
            setTextColor(color("#98A2B3"))
            gravity = Gravity.CENTER
        }, LinearLayout.LayoutParams(dp(34), dp(48)))
        card.addView(row)
        content.addView(card, marginLp(-1, -2, 0, 0, 0, 10))
    }

    private fun unlockDialog(account: AuthentiverseAccount) {
        val wrap = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(dp(22), dp(4), dp(22), dp(4))
        }
        wrap.addView(TextView(this).apply {
            text = initials(account.displayName)
            gravity = Gravity.CENTER
            textSize = 20f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(Color.WHITE)
            background = circle(PRIMARY)
        }, LinearLayout.LayoutParams(dp(60), dp(60)).apply { bottomMargin = dp(14) })
        wrap.addView(TextView(this).apply {
            text = "Welcome back, ${account.displayName}"
            textSize = 19f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(color(INK))
            gravity = Gravity.CENTER
        })
        account.lastKnownHandle?.let { handle -> wrap.addView(TextView(this).apply { text = "@$handle"; textSize = 13f; setTextColor(color(MUTED)); gravity = Gravity.CENTER; setPadding(0, dp(3), 0, dp(16)) }) }
        val field = pinField(if (account.legacy) "Create or enter your PIN" else "Authentiverse PIN")
        wrap.addView(field.first)
        wrap.addView(TextView(this).apply {
            text = "Your account data remains encrypted until this PIN unlocks the Vault."
            textSize = 11f
            setTextColor(color(MUTED))
            gravity = Gravity.CENTER
            setPadding(dp(8), dp(8), dp(8), 0)
        })
        MaterialAlertDialogBuilder(this)
            .setView(wrap)
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Unlock", null)
            .create().also { dialog ->
                dialog.setOnShowListener {
                    field.second.requestFocus()
                    dialog.getButton(android.app.AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                        runCatching { app.unlockAccount(account, field.second.text.toString()) }
                            .onSuccess { openClient() }
                            .onFailure { field.first.error = it.message }
                    }
                }
                dialog.show()
            }
    }

    private fun createDialog() {
        val box = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(22), dp(4), dp(22), 0) }
        val name = textField("Account name")
        val pin = pinField("Choose a 6–12 digit PIN")
        box.addView(TextView(this).apply {
            text = "Create a private account"
            textSize = 19f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(color(INK))
            setPadding(0, 0, 0, dp(5))
        })
        box.addView(TextView(this).apply {
            text = "The account, identity and Vault are isolated from your other Authentiverse accounts."
            textSize = 13f
            setTextColor(color(MUTED))
            setPadding(0, 0, 0, dp(16))
        })
        box.addView(name.first)
        box.addView(pin.first)
        MaterialAlertDialogBuilder(this).setView(box).setNegativeButton("Cancel", null).setPositiveButton("Create", null).create().also { dialog ->
            dialog.setOnShowListener {
                dialog.getButton(android.app.AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                    runCatching { app.createAccount(name.second.text.toString(), pin.second.text.toString()) }
                        .onSuccess { openClient() }
                        .onFailure { pin.first.error = it.message }
                }
            }
            dialog.show()
        }
    }

    private fun chooseReloadable(items: List<AuthentiverseAccount>) {
        MaterialAlertDialogBuilder(this).setTitle("Load an account")
            .setItems(items.map { it.displayName }.toTypedArray()) { _, index -> unlockDialog(app.accounts.loadExisting(items[index].id)) }
            .show()
    }

    private fun openClient() {
        startActivity(Intent(this, MainActivity::class.java).putExtra("route_uri", pendingUri))
        pendingUri = null
        finish()
    }

    private fun textField(hint: String): Pair<TextInputLayout, TextInputEditText> {
        val edit = TextInputEditText(this).apply { textSize = 16f }
        val layout = TextInputLayout(this).apply {
            this.hint = hint
            boxBackgroundMode = TextInputLayout.BOX_BACKGROUND_OUTLINE
            setBoxCornerRadii(dp(14).toFloat(), dp(14).toFloat(), dp(14).toFloat(), dp(14).toFloat())
            addView(edit)
        }
        return layout to edit
    }

    private fun pinField(hint: String): Pair<TextInputLayout, TextInputEditText> {
        val pair = textField(hint)
        pair.second.inputType = InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD
        pair.first.endIconMode = TextInputLayout.END_ICON_PASSWORD_TOGGLE
        return pair
    }

    private fun initials(value: String): String = value.trim().split(Regex("\\s+")).filter(String::isNotBlank).take(2)
        .joinToString("") { it.take(1).uppercase(Locale.getDefault()) }.ifBlank { "A" }
    private fun circle(value: String) = GradientDrawable().apply { shape = GradientDrawable.OVAL; setColor(color(value)) }
    private fun color(value: String) = Color.parseColor(value)
    private fun dp(value: Int) = (value * resources.displayMetrics.density).toInt()
    private fun marginLp(width: Int, height: Int, left: Int, top: Int, right: Int, bottom: Int) = LinearLayout.LayoutParams(width, height).apply { setMargins(dp(left), dp(top), dp(right), dp(bottom)) }
}
