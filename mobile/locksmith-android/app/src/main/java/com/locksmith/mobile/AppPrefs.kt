package com.locksmith.mobile

import android.content.Context
import android.content.SharedPreferences

class AppPrefs(ctx: Context) {
    private val prefs: SharedPreferences = ctx.getSharedPreferences("locksmith", Context.MODE_PRIVATE)

    var baseUrl: String
        get() = prefs.getString("base_url", "") ?: ""
        set(v) { prefs.edit().putString("base_url", v.trim().trimEnd('/')).apply() }

    var ussdSubscriptionId: Int?
        get() {
            if (!prefs.contains("ussd_sub_id")) return null
            val v = prefs.getInt("ussd_sub_id", -1)
            return if (v >= 0) v else null
        }
        set(v) {
            if (v == null) prefs.edit().remove("ussd_sub_id").apply()
            else prefs.edit().putInt("ussd_sub_id", v).apply()
        }

    fun cookieKey(host: String) = "cookies_$host"

    fun saveCookies(host: String, cookies: List<String>) {
        prefs.edit().putStringSet(cookieKey(host), cookies.toSet()).apply()
    }

    fun loadCookies(host: String): List<String> {
        val set = prefs.getStringSet(cookieKey(host), emptySet()) ?: emptySet()
        return set.toList()
    }

    fun clearCookies(host: String) {
        prefs.edit().remove(cookieKey(host)).apply()
    }

    fun savePendingWalletSetup(p: PendingWalletSetup) {
        prefs.edit()
            .putString("pending_wallet_lock_id", p.walletLockId)
            .putInt("pending_carrier_id", p.carrierId)
            .putString("pending_unlock_at", p.unlockAt)
            .putString("pending_label", p.label ?: "")
            .putString("pending_pin_ct", p.newPinCipherB64)
            .putString("pending_pin_iv", p.newPinIvB64)
            .putString("pending_stage", p.stage)
            .putString("pending_last_ussd", p.lastUssdMessage ?: "")
            .putLong("pending_updated_at", p.updatedAtMs)
            .apply()
    }

    fun loadPendingWalletSetup(): PendingWalletSetup? {
        val id = prefs.getString("pending_wallet_lock_id", "") ?: ""
        if (id.isBlank()) return null

        val carrierId = prefs.getInt("pending_carrier_id", -1)
        val unlockAt = prefs.getString("pending_unlock_at", "") ?: ""
        val label = (prefs.getString("pending_label", "") ?: "").ifBlank { null }
        val ct = prefs.getString("pending_pin_ct", "") ?: ""
        val iv = prefs.getString("pending_pin_iv", "") ?: ""

        val stage = (prefs.getString("pending_stage", "") ?: "").ifBlank { "pending" }
        val lastUssd = (prefs.getString("pending_last_ussd", "") ?: "").ifBlank { null }

        val updatedAt = if (prefs.contains("pending_updated_at")) {
            prefs.getLong("pending_updated_at", 0L)
        } else {
            // Backward compat with earlier versions
            prefs.getLong("pending_created_at", 0L)
        }

        if (carrierId < 0 || unlockAt.isBlank() || ct.isBlank() || iv.isBlank()) return null

        return PendingWalletSetup(
            walletLockId = id,
            carrierId = carrierId,
            unlockAt = unlockAt,
            label = label,
            newPinCipherB64 = ct,
            newPinIvB64 = iv,
            stage = stage,
            lastUssdMessage = lastUssd,
            updatedAtMs = updatedAt,
        )
    }

    fun clearPendingWalletSetup() {
        prefs.edit()
            .remove("pending_wallet_lock_id")
            .remove("pending_carrier_id")
            .remove("pending_unlock_at")
            .remove("pending_label")
            .remove("pending_pin_ct")
            .remove("pending_pin_iv")
            .remove("pending_stage")
            .remove("pending_last_ussd")
            .remove("pending_updated_at")
            // Backward compat cleanup
            .remove("pending_created_at")
            .apply()
    }
}
