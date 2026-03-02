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
            .putLong("pending_created_at", p.createdAtMs)
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
        val createdAt = prefs.getLong("pending_created_at", 0L)

        if (carrierId < 0 || unlockAt.isBlank() || ct.isBlank() || iv.isBlank()) return null

        return PendingWalletSetup(
            walletLockId = id,
            carrierId = carrierId,
            unlockAt = unlockAt,
            label = label,
            newPinCipherB64 = ct,
            newPinIvB64 = iv,
            createdAtMs = createdAt,
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
            .remove("pending_created_at")
            .apply()
    }
}
