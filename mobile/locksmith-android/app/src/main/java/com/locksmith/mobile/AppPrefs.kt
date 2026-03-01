package com.locksmith.mobile

import android.content.Context
import android.content.SharedPreferences

class AppPrefs(ctx: Context) {
    private val prefs: SharedPreferences = ctx.getSharedPreferences("locksmith", Context.MODE_PRIVATE)

    var baseUrl: String
        get() = prefs.getString("base_url", "") ?: ""
        set(v) { prefs.edit().putString("base_url", v.trim().trimEnd('/')).apply() }

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
}
