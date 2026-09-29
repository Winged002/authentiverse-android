/* SPDX-License-Identifier: MIT */
package pro.digitalspace.android.ui

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.RectF
import android.view.View
import kotlin.math.min

/** Compact identity-quality indicator used by the consumer-facing UI. */
class IdentityLevelRingView(context: Context) : View(context) {
    private val track = Paint(Paint.ANTI_ALIAS_FLAG).apply { style = Paint.Style.STROKE; strokeCap = Paint.Cap.ROUND }
    private val progressPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { style = Paint.Style.STROKE; strokeCap = Paint.Cap.ROUND }
    private val levelPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { textAlign = Paint.Align.CENTER; typeface = android.graphics.Typeface.DEFAULT_BOLD }
    private val labelPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply { textAlign = Paint.Align.CENTER }
    private var score: Int = 0
    private var verified: Boolean = false

    fun setIdentityScore(value: Int, isVerified: Boolean) {
        score = value.coerceIn(0, 72)
        verified = isVerified
        contentDescription = if (verified) "Identity level ${level()}, $score trust points" else "Identity level not verified"
        invalidate()
    }

    fun level(): Int = if (score <= 0) 0 else ((score - 1) / 12 + 1).coerceAtMost(6)

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val size = min(width, height).toFloat()
        val stroke = size * 0.075f
        track.strokeWidth = stroke
        progressPaint.strokeWidth = stroke
        track.color = Color.parseColor("#E8E7FF")
        progressPaint.color = if (verified) Color.parseColor("#5755D9") else Color.parseColor("#98A2B3")
        val inset = stroke / 2f + size * 0.05f
        val oval = RectF(inset, inset, width - inset, height - inset)
        canvas.drawArc(oval, -90f, 360f, false, track)
        canvas.drawArc(oval, -90f, 360f * (score / 72f), false, progressPaint)

        levelPaint.color = Color.parseColor("#111827")
        levelPaint.textSize = size * 0.28f
        labelPaint.color = Color.parseColor("#667085")
        labelPaint.textSize = size * 0.10f
        val cx = width / 2f
        val cy = height / 2f
        canvas.drawText(if (verified) level().toString() else "—", cx, cy + size * 0.03f, levelPaint)
        canvas.drawText("LEVEL", cx, cy + size * 0.20f, labelPaint)
    }
}
