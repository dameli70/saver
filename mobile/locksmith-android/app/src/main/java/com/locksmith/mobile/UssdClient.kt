package com.locksmith.mobile

import android.annotation.SuppressLint
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.telephony.TelephonyManager

class UssdClient(private val ctx: Context) {

    @SuppressLint("MissingPermission")
    fun sendUssd(ussd: String, onResult: (String) -> Unit, onError: (String) -> Unit) {
        val tm = ctx.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
        val handler = Handler(Looper.getMainLooper())

        try {
            tm.sendUssdRequest(ussd, object : TelephonyManager.UssdResponseCallback() {
                override fun onReceiveUssdResponse(
                    telephonyManager: TelephonyManager,
                    request: String,
                    response: CharSequence,
                ) {
                    onResult(response.toString())
                }

                override fun onReceiveUssdResponseFailed(
                    telephonyManager: TelephonyManager,
                    request: String,
                    failureCode: Int,
                ) {
                    onError("USSD failed (code $failureCode)")
                }
            }, handler)
        } catch (e: Throwable) {
            onError(e.message ?: "USSD failed")
        }
    }
}
