package com.locksmith.mobile

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.telephony.SubscriptionInfo
import android.telephony.SubscriptionManager
import android.telephony.TelephonyManager

data class SimSlot(
    val subscriptionId: Int,
    val displayName: String,
)

class UssdClient(private val ctx: Context) {

    fun listActiveSims(): List<SimSlot> {
        return try {
            val sm = ctx.getSystemService(Context.TELEPHONY_SUBSCRIPTION_SERVICE) as SubscriptionManager
            val infos: List<SubscriptionInfo> = sm.activeSubscriptionInfoList ?: emptyList()
            infos.mapNotNull { info ->
                val name = (info.displayName?.toString() ?: "SIM ${info.simSlotIndex + 1}").ifBlank { "SIM ${info.simSlotIndex + 1}" }
                SimSlot(subscriptionId = info.subscriptionId, displayName = name)
            }
        } catch (_: Throwable) {
            emptyList()
        }
    }

    @SuppressLint("MissingPermission")
    fun sendUssd(
        ussd: String,
        subscriptionId: Int? = null,
        onResult: (String) -> Unit,
        onError: (String) -> Unit,
    ) {
        val base = ctx.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
        val tm = if (subscriptionId != null) {
            try {
                base.createForSubscriptionId(subscriptionId)
            } catch (_: Throwable) {
                base
            }
        } else {
            base
        }

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

    fun openDialer(ussd: String) {
        val uri = Uri.parse("tel:" + Uri.encode(ussd))
        val i = Intent(Intent.ACTION_DIAL, uri).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        ctx.startActivity(i)
    }
}
