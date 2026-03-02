package com.locksmith.mobile

import android.content.Context
import android.os.Handler
import android.os.Looper
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.Response
import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

class LocksmithApi(
    private val ctx: Context,
    private val prefs: AppPrefs,
) {
    private var baseUrl: String = prefs.baseUrl

    private val cookieJar = PersistentCookieJar(prefs) { baseHttpUrl() }

    private var client: OkHttpClient = OkHttpClient.Builder()
        .cookieJar(cookieJar)
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(20, TimeUnit.SECONDS)
        .writeTimeout(20, TimeUnit.SECONDS)
        .callTimeout(30, TimeUnit.SECONDS)
        .retryOnConnectionFailure(true)
        .build()

    private var csrfToken: String? = null

    fun setBaseUrl(url: String) {
        baseUrl = url.trim().trimEnd('/')
    }

    private fun baseHttpUrl() = baseUrl.toHttpUrlOrNull()

    private fun apiUrl(path: String): String {
        val b = baseUrl.trim().trimEnd('/')
        val p = path.trimStart('/')
        return "$b/$p"
    }

    fun logout() {
        csrfToken = null
        cookieJar.clear()
        // Best-effort server logout
        thread {
            try {
                val body = JSONObject().put("action", "logout").toString()
                requestJson("POST", "/api/auth.php", body, addCsrf = false, idempotent = true)
            } catch (_: Throwable) {
            }
        }
    }

    private val mainHandler = Handler(Looper.getMainLooper())

    private fun cbOnMain(r: () -> Unit) {
        if (Looper.getMainLooper().thread == Thread.currentThread()) r() else mainHandler.post(r)
    }

    fun login(email: String, password: String, cb: (LoginResult) -> Unit) {
        thread {
            try {
                val body = JSONObject()
                    .put("action", "login")
                    .put("email", email)
                    .put("login_password", password)
                    .toString()

                val j = requestJson("POST", "/api/auth.php", body, addCsrf = false, idempotent = false)

                if (j.optBoolean("success") && j.optBoolean("needs_totp")) {
                    cbOnMain { cb(LoginResult.NeedsTotp) }
                    return@thread
                }

                if (!j.optBoolean("success")) {
                    cbOnMain { cb(LoginResult.Error(j.optString("error", "Login failed"))) }
                    return@thread
                }

                val ok = refreshCsrf()
                if (!ok) {
                    cbOnMain { cb(LoginResult.Error("Failed to establish session")) }
                    return@thread
                }

                cbOnMain { cb(LoginResult.Success) }
            } catch (e: Throwable) {
                cbOnMain { cb(LoginResult.Error(e.message ?: "Login failed")) }
            }
        }
    }

    fun loginTotp(code: String, cb: (Boolean, String?) -> Unit) {
        thread {
            try {
                val body = JSONObject()
                    .put("action", "login_totp")
                    .put("code", code)
                    .toString()

                val j = requestJson("POST", "/api/auth.php", body, addCsrf = false, idempotent = false)
                if (!j.optBoolean("success")) {
                    cbOnMain { cb(false, j.optString("error", "TOTP failed")) }
                    return@thread
                }

                val ok = refreshCsrf()
                if (!ok) {
                    cbOnMain { cb(false, "Failed to establish session") }
                    return@thread
                }

                cbOnMain { cb(true, null) }
            } catch (e: Throwable) {
                cbOnMain { cb(false, e.message) }
            }
        }
    }

    fun refreshCsrf(): Boolean {
        return try {
            val j = requestJson("GET", "/api/csrf.php", null, addCsrf = false, idempotent = true)
            if (!j.optBoolean("success")) return false
            csrfToken = j.optString("csrf_token", null)
            csrfToken != null
        } catch (_: Throwable) {
            false
        }
    }

    fun getCarriers(cb: (List<Carrier>?, String?) -> Unit) {
        thread {
            try {
                val j = requestJson("GET", "/api/carriers.php", null, addCsrf = false, idempotent = true)
                if (!j.optBoolean("success")) {
                    cbOnMain { cb(null, j.optString("error", "Failed")) }
                    return@thread
                }

                val arr = j.optJSONArray("carriers") ?: JSONArray()
                val out = mutableListOf<Carrier>()
                for (i in 0 until arr.length()) {
                    val c = arr.getJSONObject(i)
                    out.add(
                        Carrier(
                            id = c.getInt("id"),
                            name = c.getString("name"),
                            country = c.optString("country").ifEmpty { null },
                            pinType = c.getString("pin_type"),
                            pinLength = c.getInt("pin_length"),
                            ussdChangePinTemplate = c.getString("ussd_change_pin_template"),
                            ussdBalanceTemplate = c.getString("ussd_balance_template"),
                        )
                    )
                }

                cbOnMain { cb(out, null) }
            } catch (e: Throwable) {
                cbOnMain { cb(null, e.message) }
            }
        }
    }

    fun getWalletLocks(cb: (List<WalletLock>?, String?) -> Unit) {
        thread {
            try {
                val j = requestJson("GET", "/api/wallet_locks.php", null, addCsrf = false, idempotent = true)
                if (!j.optBoolean("success")) {
                    cbOnMain { cb(null, j.optString("error", "Failed")) }
                    return@thread
                }

                val arr = j.optJSONArray("wallet_locks") ?: JSONArray()
                val out = mutableListOf<WalletLock>()
                for (i in 0 until arr.length()) {
                    val w = arr.getJSONObject(i)
                    val tr = w.optJSONObject("time_remaining")
                    val timeRemaining = if (tr != null) {
                        TimeRemaining(
                            days = tr.optInt("days"),
                            hours = tr.optInt("hours"),
                            minutes = tr.optInt("minutes"),
                            totalSeconds = tr.optLong("total_seconds"),
                        )
                    } else {
                        null
                    }

                    out.add(
                        WalletLock(
                            id = w.getString("id"),
                            label = w.optString("label").ifEmpty { null },
                            unlockAt = w.getString("unlock_at"),
                            carrierId = w.getInt("carrier_id"),
                            carrierName = w.getString("carrier_name"),
                            displayStatus = w.getString("display_status"),
                            timeRemaining = timeRemaining,
                        )
                    )
                }

                cbOnMain { cb(out, null) }
            } catch (e: Throwable) {
                cbOnMain { cb(null, e.message) }
            }
        }
    }

    fun getSalt(cb: (String?, Int?, String?) -> Unit) {
        thread {
            try {
                val j = requestJson("GET", "/api/salt.php", null, addCsrf = false, idempotent = true)
                if (!j.optBoolean("success")) {
                    cbOnMain { cb(null, null, j.optString("error", "Failed")) }
                    return@thread
                }
                cbOnMain { cb(j.getString("kdf_salt"), j.getInt("kdf_iterations"), null) }
            } catch (e: Throwable) {
                cbOnMain { cb(null, null, e.message) }
            }
        }
    }

    fun vaultSetupStatus(cb: (VaultCheck?, String?) -> Unit) {
        thread {
            try {
                val body = JSONObject().put("action", "setup_status").toString()
                val j = requestJson("POST", "/api/vault.php", body, addCsrf = true, idempotent = true)
                if (!j.optBoolean("success")) {
                    cbOnMain { cb(null, j.optString("error", "Failed")) }
                    return@thread
                }

                val vc = j.optJSONObject("vault_check")
                if (vc == null) {
                    cbOnMain { cb(null, null) }
                    return@thread
                }

                cbOnMain {
                    cb(
                        VaultCheck(
                            cipherBlob = vc.getString("cipher_blob"),
                            iv = vc.getString("iv"),
                            authTag = vc.getString("auth_tag"),
                            kdfSalt = vc.getString("kdf_salt"),
                            kdfIterations = vc.getInt("kdf_iterations"),
                        ),
                        null,
                    )
                }
            } catch (e: Throwable) {
                cbOnMain { cb(null, e.message) }
            }
        }
    }

    fun totpReauth(code: String, cb: (Boolean, String?) -> Unit) {
        thread {
            try {
                val body = JSONObject()
                    .put("action", "reauth")
                    .put("code", code)
                    .toString()

                val j = requestJson("POST", "/api/totp.php", body, addCsrf = true, idempotent = false)
                if (!j.optBoolean("success")) {
                    cbOnMain { cb(false, j.optString("error", "Reauth failed")) }
                    return@thread
                }
                cbOnMain { cb(true, null) }
            } catch (e: Throwable) {
                cbOnMain { cb(false, e.message) }
            }
        }
    }

    fun vaultSetupSave(enc: VaultCrypto.EncBlob, kdfSalt: String, kdfIterations: Int, cb: (Boolean, String?) -> Unit) {
        thread {
            try {
                val body = JSONObject()
                    .put("action", "setup_save")
                    .put("cipher_blob", enc.cipherBlobB64)
                    .put("iv", enc.ivB64)
                    .put("auth_tag", enc.authTagB64)
                    .put("kdf_salt", kdfSalt)
                    .put("kdf_iterations", kdfIterations)
                    .toString()

                val j = requestJson("POST", "/api/vault.php", body, addCsrf = true, idempotent = false)
                if (!j.optBoolean("success")) {
                    cbOnMain { cb(false, j.optString("error", "Failed")) }
                    return@thread
                }
                cbOnMain { cb(true, null) }
            } catch (e: Throwable) {
                cbOnMain { cb(false, e.message) }
            }
        }
    }

    fun walletCreate(
        carrierId: Int,
        label: String?,
        unlockAt: String,
        cipher: VaultCrypto.EncBlob,
        kdfSalt: String,
        kdfIterations: Int,
        cb: (Boolean, JSONObject?) -> Unit,
    ) {
        thread {
            try {
                val body = JSONObject()
                    .put("carrier_id", carrierId)
                    .put("label", label ?: "")
                    .put("unlock_at", unlockAt)
                    .put("cipher_blob", cipher.cipherBlobB64)
                    .put("iv", cipher.ivB64)
                    .put("auth_tag", cipher.authTagB64)
                    .put("kdf_salt", kdfSalt)
                    .put("kdf_iterations", kdfIterations)
                    .toString()

                val j = requestJson("POST", "/api/wallet_create.php", body, addCsrf = true, idempotent = false)
                cbOnMain { cb(j.optBoolean("success"), j) }
            } catch (e: Throwable) {
                cbOnMain { cb(false, JSONObject().put("error", e.message ?: "Failed")) }
            }
        }
    }

    fun walletConfirm(walletLockId: String, cb: (Boolean, JSONObject?) -> Unit) {
        thread {
            try {
                val body = JSONObject().put("wallet_lock_id", walletLockId).toString()
                val j = requestJson("POST", "/api/wallet_confirm.php", body, addCsrf = true, idempotent = true)
                cbOnMain { cb(j.optBoolean("success"), j) }
            } catch (e: Throwable) {
                cbOnMain { cb(false, JSONObject().put("error", e.message ?: "Failed")) }
            }
        }
    }

    fun walletReveal(walletLockId: String, cb: (Boolean, JSONObject?) -> Unit) {
        thread {
            try {
                val body = JSONObject().put("wallet_lock_id", walletLockId).toString()
                val j = requestJson("POST", "/api/wallet_reveal.php", body, addCsrf = true, idempotent = false)
                cbOnMain { cb(j.optBoolean("success"), j) }
            } catch (e: Throwable) {
                cbOnMain { cb(false, JSONObject().put("error", e.message ?: "Failed")) }
            }
        }
    }

    fun walletFail(walletLockId: String, cb: (Boolean, JSONObject?) -> Unit) {
        thread {
            try {
                val body = JSONObject().put("wallet_lock_id", walletLockId).toString()
                val j = requestJson("POST", "/api/wallet_fail.php", body, addCsrf = true, idempotent = true)
                cbOnMain { cb(j.optBoolean("success"), j) }
            } catch (e: Throwable) {
                cbOnMain { cb(false, JSONObject().put("error", e.message ?: "Failed")) }
            }
        }
    }

    private data class HttpJson(val code: Int, val text: String, val json: JSONObject?)

    private fun decodeJson(text: String): JSONObject? {
        if (text.isBlank()) return null
        return try {
            JSONObject(text)
        } catch (_: Throwable) {
            null
        }
    }

    private fun execute(req: Request): HttpJson {
        client.newCall(req).execute().use { resp: Response ->
            val text = resp.body?.string() ?: ""
            return HttpJson(code = resp.code, text = text, json = decodeJson(text))
        }
    }

    private fun requestJson(
        method: String,
        path: String,
        jsonBody: String?,
        addCsrf: Boolean,
        idempotent: Boolean,
    ): JSONObject {
        val url = apiUrl(path)

        fun build(csrf: String?): Request {
            val builder = Request.Builder().url(url)

            if (addCsrf) {
                val token = csrf ?: throw IllegalStateException("Missing CSRF token. Re-login.")
                builder.header("X-CSRF-Token", token)
            }

            return if (method.uppercase() == "POST") {
                val media = "application/json".toMediaType()
                val body = (jsonBody ?: "{}").toRequestBody(media)
                builder.post(body).build()
            } else {
                builder.get().build()
            }
        }

        val retries = if (idempotent) 2 else 0
        var attempt = 0
        var csrf = csrfToken

        while (true) {
            try {
                val res = execute(build(csrf))

                // CSRF can expire mid-session. Refresh and retry once.
                if (addCsrf && res.code == 403 && res.json?.optString("error") == "Invalid CSRF token") {
                    if (refreshCsrf()) {
                        csrf = csrfToken
                        attempt++
                        if (attempt <= retries + 1) continue
                    }
                }

                val j = res.json
                if (j != null) return j

                if (res.text.isBlank()) {
                    return JSONObject().put("success", false).put("error", "Empty response")
                }

                return JSONObject().put("success", false).put("error", "Invalid JSON response")

            } catch (e: IOException) {
                if (attempt >= retries) {
                    throw e
                }
                val sleepMs = if (attempt == 0) 400L else 1200L
                Thread.sleep(sleepMs)
                attempt++
                continue
            }
        }
    }
}
