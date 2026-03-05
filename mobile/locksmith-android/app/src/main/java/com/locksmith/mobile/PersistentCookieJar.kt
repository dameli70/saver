package com.locksmith.mobile

import okhttp3.Cookie
import okhttp3.CookieJar
import okhttp3.HttpUrl

class PersistentCookieJar(
    private val prefs: AppPrefs,
    private val baseUrlProvider: () -> HttpUrl?,
) : CookieJar {

    override fun saveFromResponse(url: HttpUrl, cookies: List<Cookie>) {
        val host = url.host
        val raw = cookies.map { it.toString() }
        prefs.saveCookies(host, raw)
    }

    override fun loadForRequest(url: HttpUrl): List<Cookie> {
        val host = url.host
        val raw = prefs.loadCookies(host)
        val parsed = raw.mapNotNull { Cookie.parse(url, it) }

        // Drop expired
        val now = System.currentTimeMillis()
        val valid = parsed.filter { it.expiresAt > now }
        if (valid.size != parsed.size) {
            prefs.saveCookies(host, valid.map { it.toString() })
        }

        return valid
    }

    fun clear() {
        val base = baseUrlProvider() ?: return
        prefs.clearCookies(base.host)
    }
}
