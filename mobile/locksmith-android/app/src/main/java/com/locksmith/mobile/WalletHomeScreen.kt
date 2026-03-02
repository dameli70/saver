package com.locksmith.mobile

import android.app.DatePickerDialog
import android.app.TimePickerDialog
import android.content.pm.PackageManager
import android.content.res.Configuration
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import kotlinx.coroutines.delay
import java.security.SecureRandom
import java.time.LocalDate
import java.time.LocalDateTime
import java.time.LocalTime
import java.time.format.DateTimeFormatter

private const val VAULT_CHECK_PLAIN = "LOCKSMITH_VAULT_CHECK_v1"

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun WalletHomeScreen(
    api: LocksmithApi,
    prefs: AppPrefs,
    onRequestCallPermission: () -> Unit,
    onLogout: () -> Unit,
) {
    val ctx = LocalContext.current
    val ussdClient = remember { UssdClient(ctx) }

    var tab by remember { mutableIntStateOf(0) }

    var carriers by remember { mutableStateOf<List<Carrier>>(emptyList()) }
    var walletLocks by remember { mutableStateOf<List<WalletLock>>(emptyList()) }

    var pendingSetup by remember { mutableStateOf<PendingWalletSetup?>(prefs.loadPendingWalletSetup()) }

    val sims = remember { ussdClient.listActiveSims() }
    var ussdSubId by remember { mutableStateOf(prefs.ussdSubscriptionId) }

    var ussdFallback by remember { mutableStateOf<UssdFallbackDialog?>(null) }

    var msg by remember { mutableStateOf<String?>(null) }
    var err by remember { mutableStateOf<String?>(null) }

    var vaultPassphrase by remember { mutableStateOf<String?>(null) }

    var showPassDialog by remember { mutableStateOf(false) }
    var passDialogMode by remember { mutableStateOf(PassDialogMode.Unlock) }
    var pendingPassAction by remember { mutableStateOf<(() -> Unit)?>(null) }

    var showTotpDialog by remember { mutableStateOf(false) }
    var pendingTotpAction by remember { mutableStateOf<(() -> Unit)?>(null) }

    fun refreshAll() {
        msg = null
        err = null
        api.getCarriers { list, e ->
            if (e != null) err = e else carriers = list ?: emptyList()
        }
        api.getWalletLocks { list, e ->
            if (e != null) err = e else walletLocks = list ?: emptyList()
        }
    }

    LaunchedEffect(Unit) {
        refreshAll()

        if (ussdSubId == null && sims.isNotEmpty()) {
            ussdSubId = sims.first().subscriptionId
        }
    }

    LaunchedEffect(ussdSubId) {
        prefs.ussdSubscriptionId = ussdSubId
    }

    fun ensureCallPermission(): Boolean {
        val ok = ContextCompat.checkSelfPermission(ctx, android.Manifest.permission.CALL_PHONE) == PackageManager.PERMISSION_GRANTED
        if (!ok) {
            onRequestCallPermission()
        }
        return ok
    }

    fun ensureVaultUnlocked(onReady: (String) -> Unit) {
        val cached = vaultPassphrase
        if (cached != null) {
            onReady(cached)
            return
        }

        passDialogMode = PassDialogMode.Unlock
        pendingPassAction = {
            val p = vaultPassphrase
            if (p != null) onReady(p)
        }
        showPassDialog = true
    }

    fun ensureVaultInitialized(onReady: (String) -> Unit) {
        api.vaultSetupStatus { vaultCheck, e ->
            if (e != null) {
                err = e
                return@vaultSetupStatus
            }

            if (vaultCheck == null) {
                passDialogMode = PassDialogMode.SetNew
                pendingPassAction = {
                    val p = vaultPassphrase
                    if (p != null) onReady(p)
                }
                showPassDialog = true
                return@vaultSetupStatus
            }

            ensureVaultUnlocked(onReady)
        }
    }

    fun ensureStrongAuthThen(run: () -> Unit) {
        // We detect strong-auth requirement by the API response error_code.
        // This helper just opens a TOTP dialog and runs the action after reauth.
        pendingTotpAction = run
        showTotpDialog = true
    }

    fun callWithTotpRetry(call: (cb: (Boolean, org.json.JSONObject?) -> Unit) -> Unit, cb: (Boolean, org.json.JSONObject?) -> Unit) {
        call { ok, j ->
            if (ok) {
                cb(true, j)
                return@call
            }

            val errorCode = j?.optString("error_code") ?: ""
            if (errorCode == "reauth_required" && j.optJSONObject("methods")?.optBoolean("totp") == true) {
                ensureStrongAuthThen { callWithTotpRetry(call, cb) }
                return@call
            }

            cb(false, j)
        }
    }

    fun sendUssdWithFallback(
        ussd: String,
        dialerFallbackUssd: String?,
        onResult: (String) -> Unit,
    ) {
        ussdClient.sendUssd(
            ussd = ussd,
            subscriptionId = ussdSubId,
            onResult = onResult,
            onError = { e ->
                ussdFallback = UssdFallbackDialog(
                    message = e,
                    dialerUssd = dialerFallbackUssd,
                    onRetry = {
                        ussdFallback = null
                        sendUssdWithFallback(ussd, dialerFallbackUssd, onResult)
                    },
                    onOpenDialer = if (dialerFallbackUssd != null) {
                        {
                            ussdFallback = null
                            ussdClient.openDialer(dialerFallbackUssd)
                        }
                    } else {
                        null
                    },
                    onDismiss = { ussdFallback = null },
                )
            },
        )
    }

    if (showPassDialog) {
        VaultPassphraseDialog(
            mode = passDialogMode,
            onDismiss = { showPassDialog = false },
            onSubmit = { p1, p2 ->
                if (passDialogMode == PassDialogMode.SetNew && p1 != p2) {
                    err = "Passphrases do not match"
                    return@VaultPassphraseDialog
                }

                if (p1.length < 8) {
                    err = "Vault passphrase must be at least 8 characters"
                    return@VaultPassphraseDialog
                }

                showPassDialog = false

                if (passDialogMode == PassDialogMode.SetNew) {
                    val saltBytes = ByteArray(32)
                    SecureRandom().nextBytes(saltBytes)
                    val kdfSalt = VaultCrypto.b64Encode(saltBytes)
                    val iters = 310000

                    val key = VaultCrypto.deriveKey(p1, kdfSalt, iters)
                    val enc = VaultCrypto.encryptAesGcm(VAULT_CHECK_PLAIN, key)

                    api.vaultSetupSave(enc, kdfSalt, iters) { ok, e ->
                        if (!ok) {
                            err = e ?: "Failed to set vault"
                            return@vaultSetupSave
                        }
                        vaultPassphrase = p1
                        pendingPassAction?.invoke()
                        pendingPassAction = null
                        msg = "Vault passphrase set."
                    }
                } else {
                    // Unlock: validate against vault check blob
                    api.vaultSetupStatus { vaultCheck, e ->
                        if (e != null) {
                            err = e
                            return@vaultSetupStatus
                        }
                        if (vaultCheck == null) {
                            err = "Vault passphrase is not set yet"
                            return@vaultSetupStatus
                        }

                        try {
                            val key = VaultCrypto.deriveKey(p1, vaultCheck.kdfSalt, vaultCheck.kdfIterations)
                            val plain = VaultCrypto.decryptAesGcm(vaultCheck.cipherBlob, vaultCheck.iv, vaultCheck.authTag, key)
                            if (plain != VAULT_CHECK_PLAIN) {
                                err = "Incorrect vault passphrase"
                                return@vaultSetupStatus
                            }

                            vaultPassphrase = p1
                            pendingPassAction?.invoke()
                            pendingPassAction = null
                        } catch (t: Throwable) {
                            err = "Incorrect vault passphrase"
                        }
                    }
                }
            },
        )
    }

    if (showTotpDialog) {
        TotpReauthDialog(
            onDismiss = { showTotpDialog = false },
            onSubmit = { code ->
                showTotpDialog = false
                api.totpReauth(code) { ok, e ->
                    if (!ok) {
                        err = e ?: "Re-auth failed"
                        return@totpReauth
                    }
                    pendingTotpAction?.invoke()
                    pendingTotpAction = null
                }
            }
        )
    }

    val uf = ussdFallback
    if (uf != null) {
        AlertDialog(
            onDismissRequest = uf.onDismiss,
            title = { Text("USSD failed") },
            text = { Text(uf.message) },
            confirmButton = {
                Button(onClick = uf.onRetry) { Text("Retry") }
            },
            dismissButton = {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (uf.onOpenDialer != null) {
                        OutlinedButton(onClick = uf.onOpenDialer) { Text("Open dialer") }
                    }
                    OutlinedButton(onClick = uf.onDismiss) { Text("Close") }
                }
            },
        )
    }

    Column(modifier = Modifier.fillMaxSize()) {
        TopAppBar(
            title = { Text("Wallet Locks") },
            actions = {
                TextButton(onClick = refreshAll) { Text("Refresh") }
                TextButton(onClick = onLogout) { Text("Logout") }
            }
        )

        TabRow(selectedTabIndex = tab) {
            Tab(selected = tab == 0, onClick = { tab = 0 }, text = { Text("Locks") })
            Tab(selected = tab == 1, onClick = { tab = 1 }, text = { Text("Setup") })
        }

        if (sims.isNotEmpty()) {
            SimSelector(
                sims = sims,
                selectedSubscriptionId = ussdSubId,
                onSelect = { ussdSubId = it },
            )
        }

        if (msg != null) {
            Text(
                msg!!,
                modifier = Modifier.padding(12.dp),
                color = MaterialTheme.colorScheme.primary,
            )
        }

        if (err != null) {
            Text(
                err!!,
                modifier = Modifier.padding(12.dp),
                color = MaterialTheme.colorScheme.error,
            )
        }

        when (tab) {
            0 -> WalletLocksTab(
                carriers = carriers,
                walletLocks = walletLocks,
                onCheckBalance = { carrierId ->
                    val c = carriers.firstOrNull { it.id == carrierId } ?: return@WalletLocksTab
                    if (!ensureCallPermission()) return@WalletLocksTab

                    msg = "Sending USSD…"
                    sendUssdWithFallback(
                        ussd = c.ussdBalanceTemplate,
                        dialerFallbackUssd = c.ussdBalanceTemplate,
                        onResult = { resp -> msg = resp },
                    )
                },
                onRevealPin = { lock ->
                    callWithTotpRetry(
                        call = { cb -> api.walletReveal(lock.id, cb) },
                        cb = { ok, j ->
                            if (!ok) {
                                err = j?.optString("error") ?: "Reveal failed"
                                return@callWithTotpRetry
                            }

                            val wl = j?.optJSONObject("wallet_lock")
                            if (wl == null) {
                                err = "Invalid response"
                                return@callWithTotpRetry
                            }

                            ensureVaultInitialized { pass ->
                                try {
                                    val key = VaultCrypto.deriveKey(pass, wl.getString("kdf_salt"), wl.getInt("kdf_iterations"))
                                    val pin = VaultCrypto.decryptAesGcm(
                                        wl.getString("cipher_blob"),
                                        wl.getString("iv"),
                                        wl.getString("auth_tag"),
                                        key,
                                    )
                                    msg = "PIN: $pin"
                                    refreshAll()
                                } catch (t: Throwable) {
                                    err = "Failed to decrypt"
                                }
                            }
                        },
                    )
                },
            )

            1 -> WalletSetupTab(
                carriers = carriers,
                pending = pendingSetup,
                onLockWallet = { carrier, currentPin, unlockAt, label ->
                    if (!ensureCallPermission()) return@WalletSetupTab

                    ensureVaultInitialized { passphrase ->
                        val newPin = generateCarrierPin(carrier)

                        api.getSalt { salt, iters, e ->
                            if (e != null || salt == null || iters == null) {
                                err = e ?: "Failed to get salt"
                                return@getSalt
                            }

                            try {
                                val key = VaultCrypto.deriveKey(passphrase, salt, iters)
                                val enc = VaultCrypto.encryptAesGcm(newPin, key)

                                callWithTotpRetry(
                                    call = { cb ->
                                        api.walletCreate(
                                            carrierId = carrier.id,
                                            label = label,
                                            unlockAt = unlockAt,
                                            cipher = enc,
                                            kdfSalt = salt,
                                            kdfIterations = iters,
                                            cb = cb,
                                        )
                                    },
                                    cb = { ok, j ->
                                        if (!ok) {
                                            err = j?.optString("error") ?: "Failed"
                                            return@callWithTotpRetry
                                        }

                                        val walletLockId = j?.optString("wallet_lock_id") ?: ""
                                        if (walletLockId.isBlank()) {
                                            err = "Invalid response"
                                            return@callWithTotpRetry
                                        }

                                        val devEnc = DeviceCrypto.encrypt(newPin)
                                        prefs.savePendingWalletSetup(
                                            PendingWalletSetup(
                                                walletLockId = walletLockId,
                                                carrierId = carrier.id,
                                                unlockAt = unlockAt,
                                                label = label,
                                                newPinCipherB64 = devEnc.cipherB64,
                                                newPinIvB64 = devEnc.ivB64,
                                                createdAtMs = System.currentTimeMillis(),
                                            )
                                        )
                                        pendingSetup = prefs.loadPendingWalletSetup()

                                        val ussd = carrier.ussdChangePinTemplate
                                            .replace("{old_pin}", currentPin)
                                            .replace("{new_pin}", newPin)

                                        msg = "Sending PIN-change USSD…"
                                        sendUssdWithFallback(
                                            ussd = ussd,
                                            dialerFallbackUssd = null,
                                            onResult = { resp ->
                                                msg = resp

                                                callWithTotpRetry(
                                                    call = { cb2 -> api.walletConfirm(walletLockId, cb2) },
                                                    cb = { ok2, j2 ->
                                                        if (!ok2) {
                                                            err = j2?.optString("error") ?: "Failed to confirm"
                                                            return@callWithTotpRetry
                                                        }

                                                        prefs.clearPendingWalletSetup()
                                                        pendingSetup = null
                                                        msg = "Wallet locked until $unlockAt"
                                                        refreshAll()
                                                    },
                                                )
                                            },
                                        )
                                    },
                                )

                            } catch (t: Throwable) {
                                err = "Encryption failed"
                            }
                        }
                    }
                },
                onResumePending = { p, currentPin ->
                    if (!ensureCallPermission()) return@WalletSetupTab

                    val carrier = carriers.firstOrNull { it.id == p.carrierId }
                    if (carrier == null) {
                        err = "Carrier not found"
                        return@WalletSetupTab
                    }

                    val newPin = try {
                        DeviceCrypto.decrypt(DeviceEnc(cipherB64 = p.newPinCipherB64, ivB64 = p.newPinIvB64))
                    } catch (_: Throwable) {
                        err = "Failed to resume setup (device storage)"
                        return@WalletSetupTab
                    }

                    val ussd = carrier.ussdChangePinTemplate
                        .replace("{old_pin}", currentPin)
                        .replace("{new_pin}", newPin)

                    msg = "Sending PIN-change USSD…"
                    sendUssdWithFallback(
                        ussd = ussd,
                        dialerFallbackUssd = null,
                        onResult = { resp ->
                            msg = resp

                            callWithTotpRetry(
                                call = { cb2 -> api.walletConfirm(p.walletLockId, cb2) },
                                cb = { ok2, j2 ->
                                    if (!ok2) {
                                        err = j2?.optString("error") ?: "Failed to confirm"
                                        return@callWithTotpRetry
                                    }

                                    prefs.clearPendingWalletSetup()
                                    pendingSetup = null
                                    msg = "Wallet locked until ${p.unlockAt}"
                                    refreshAll()
                                },
                            )
                        },
                    )
                },
                onDiscardPending = { p ->
                    callWithTotpRetry(
                        call = { cb -> api.walletFail(p.walletLockId, cb) },
                        cb = { ok, j ->
                            if (!ok) {
                                err = j?.optString("error") ?: "Failed"
                                return@callWithTotpRetry
                            }
                            prefs.clearPendingWalletSetup()
                            pendingSetup = null
                            msg = "Pending setup discarded"
                            refreshAll()
                        },
                    )
                },
            )
        }

        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = "Server: ${prefs.baseUrl}",
            modifier = Modifier.padding(horizontal = 12.dp),
            style = MaterialTheme.typography.bodySmall,
        )
        Spacer(modifier = Modifier.height(10.dp))
    }
}

@Composable
private fun WalletLocksTab(
    carriers: List<Carrier>,
    walletLocks: List<WalletLock>,
    onCheckBalance: (carrierId: Int) -> Unit,
    onRevealPin: (WalletLock) -> Unit,
) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        if (walletLocks.isEmpty()) {
            item {
                Text("No wallet locks yet.")
            }
        }

        items(walletLocks) { lock ->
            Card {
                Column(modifier = Modifier.padding(12.dp)) {
                    Text(lock.label ?: lock.carrierName, fontWeight = FontWeight.SemiBold)
                    Spacer(modifier = Modifier.height(4.dp))
                    Text("Carrier: ${lock.carrierName}")
                    Text("Status: ${lock.displayStatus}")
                    Text("Unlock at: ${lock.unlockAt}")

                    val tr = lock.timeRemaining
                    if (tr != null) {
                        ServerCountdown(totalSeconds = tr.totalSeconds)
                    }

                    Spacer(modifier = Modifier.height(10.dp))

                    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        OutlinedButton(onClick = { onCheckBalance(lock.carrierId) }) {
                            Text("Check balance")
                        }

                        Button(
                            onClick = { onRevealPin(lock) },
                            enabled = lock.displayStatus == "unlocked",
                        ) {
                            Text("Reveal PIN")
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun WalletSetupTab(
    carriers: List<Carrier>,
    pending: PendingWalletSetup?,
    onLockWallet: (carrier: Carrier, currentPin: String, unlockAt: String, label: String?) -> Unit,
    onResumePending: (PendingWalletSetup, String) -> Unit,
    onDiscardPending: (PendingWalletSetup) -> Unit,
) {
    val ctx = LocalContext.current

    var resumePin by rememberSaveable { mutableStateOf("") }

    var selectedCarrierId by rememberSaveable { mutableStateOf<Int?>(null) }
    val selectedCarrier = remember(selectedCarrierId, carriers) {
        carriers.firstOrNull { it.id == selectedCarrierId }
    }
    var carrierMenu by remember { mutableStateOf(false) }

    var label by rememberSaveable { mutableStateOf("") }
    var currentPin by rememberSaveable { mutableStateOf("") }

    var dateStr by rememberSaveable { mutableStateOf(LocalDate.now().plusDays(1).toString()) }
    var timeStr by rememberSaveable { mutableStateOf("09:00") }

    val date = remember(dateStr) { runCatching { LocalDate.parse(dateStr) }.getOrElse { LocalDate.now().plusDays(1) } }
    val time = remember(timeStr) { runCatching { LocalTime.parse(timeStr) }.getOrElse { LocalTime.of(9, 0) } }

    val dt = remember(date, time) { LocalDateTime.of(date, time) }
    val fmt = remember { DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss") }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        if (pending != null) {
            item {
                Card {
                    Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        Text("Pending setup detected", fontWeight = FontWeight.SemiBold)
                        Text(pending.label ?: "Wallet lock")
                        Text("Unlock at: ${pending.unlockAt}")

                        OutlinedTextField(
                            value = resumePin,
                            onValueChange = { resumePin = it },
                            label = { Text("Current wallet PIN (for USSD)") },
                            visualTransformation = PasswordVisualTransformation(),
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true,
                        )

                        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                            Button(
                                onClick = { onResumePending(pending, resumePin) },
                                enabled = resumePin.isNotBlank(),
                            ) {
                                Text("Continue")
                            }
                            OutlinedButton(onClick = { onDiscardPending(pending) }) {
                                Text("Discard")
                            }
                        }

                        Text(
                            "If setup was interrupted, you can continue here. The generated PIN is kept encrypted in device storage and is not shown.",
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
            }
        }

        item {
            Text("Create wallet lock", style = MaterialTheme.typography.titleMedium)
        }

        item {
            Text(
                "Unlock timing is enforced by the server. Choose a date/time you can rely on.",
                style = MaterialTheme.typography.bodySmall,
            )
        }

        item {
            Box {
                OutlinedButton(onClick = { carrierMenu = true }, modifier = Modifier.fillMaxWidth()) {
                    Text(selectedCarrier?.name ?: "Select carrier")
                }

                DropdownMenu(expanded = carrierMenu, onDismissRequest = { carrierMenu = false }) {
                    carriers.forEach { c ->
                        DropdownMenuItem(
                            text = { Text(c.name) },
                            onClick = {
                                selectedCarrierId = c.id
                                carrierMenu = false
                            }
                        )
                    }
                }
            }
        }

        item {
            OutlinedTextField(
                value = label,
                onValueChange = { label = it },
                label = { Text("Label (optional)") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
        }

        item {
            OutlinedTextField(
                value = currentPin,
                onValueChange = { currentPin = it },
                label = { Text("Current wallet PIN") },
                visualTransformation = PasswordVisualTransformation(),
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
        }

        item {
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp), modifier = Modifier.fillMaxWidth()) {
                OutlinedButton(
                    onClick = {
                        DatePickerDialog(
                            ctx,
                            { _, y, m, d -> dateStr = LocalDate.of(y, m + 1, d).toString() },
                            date.year,
                            date.monthValue - 1,
                            date.dayOfMonth,
                        ).show()
                    },
                    modifier = Modifier.weight(1f)
                ) {
                    Text("Date: ${date}")
                }

                OutlinedButton(
                    onClick = {
                        TimePickerDialog(
                            ctx,
                            { _, hh, mm -> timeStr = "%02d:%02d".format(hh, mm) },
                            time.hour,
                            time.minute,
                            true,
                        ).show()
                    },
                    modifier = Modifier.weight(1f)
                ) {
                    Text("Time: ${timeStr}")
                }
            }
        }

        item {
            Text("Unlock at: ${dt.format(fmt)}")
        }

        item {
            Button(
                onClick = {
                    val c = selectedCarrier ?: return@Button
                    if (currentPin.isBlank()) return@Button
                    val unlockAt = dt.format(fmt)
                    onLockWallet(c, currentPin, unlockAt, label.trim().ifEmpty { null })
                },
                modifier = Modifier.fillMaxWidth(),
                enabled = selectedCarrier != null && currentPin.isNotBlank(),
            ) {
                Text("Lock wallet")
            }
        }

        item {
            Spacer(modifier = Modifier.height(8.dp))
        }
    }
}

private data class UssdFallbackDialog(
    val message: String,
    val dialerUssd: String?,
    val onRetry: () -> Unit,
    val onOpenDialer: (() -> Unit)?,
    val onDismiss: () -> Unit,
)

@Composable
private fun SimSelector(
    sims: List<SimSlot>,
    selectedSubscriptionId: Int?,
    onSelect: (Int?) -> Unit,
) {
    var expanded by remember { mutableStateOf(false) }

    val selected = sims.firstOrNull { it.subscriptionId == selectedSubscriptionId }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 6.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text("USSD SIM", style = MaterialTheme.typography.bodySmall)

        Box {
            TextButton(onClick = { expanded = true }) {
                Text(selected?.displayName ?: (sims.firstOrNull()?.displayName ?: "Default"))
            }

            DropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
                sims.forEach { s ->
                    DropdownMenuItem(
                        text = { Text(s.displayName) },
                        onClick = {
                            expanded = false
                            onSelect(s.subscriptionId)
                        }
                    )
                }
            }
        }
    }
}

@Composable
private fun ServerCountdown(totalSeconds: Long) {
    var remaining by remember(totalSeconds) { mutableStateOf(totalSeconds) }

    LaunchedEffect(totalSeconds) {
        remaining = totalSeconds
        while (remaining > 0) {
            delay(1000)
            remaining -= 1
        }
    }

    val days = remaining / 86400
    val hours = (remaining % 86400) / 3600
    val mins = (remaining % 3600) / 60

    Text("Remaining: ${days}d ${hours}h ${mins}m")
}

private fun generateCarrierPin(carrier: Carrier): String {
    val len = carrier.pinLength
    val chars = when (carrier.pinType) {
        "alphanumeric" -> ("ABCDEFGHJKLMNPQRSTUVWXYZ" + "23456789")
        else -> "0123456789"
    }

    val rnd = SecureRandom()
    val sb = StringBuilder()
    repeat(len) {
        sb.append(chars[rnd.nextInt(chars.length)])
    }
    return sb.toString()
}

private enum class PassDialogMode { Unlock, SetNew }

@Composable
private fun VaultPassphraseDialog(
    mode: PassDialogMode,
    onDismiss: () -> Unit,
    onSubmit: (String, String) -> Unit,
) {
    var p1 by remember { mutableStateOf("") }
    var p2 by remember { mutableStateOf("") }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(if (mode == PassDialogMode.SetNew) "Set vault passphrase" else "Unlock vault") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                OutlinedTextField(
                    value = p1,
                    onValueChange = { p1 = it },
                    label = { Text("Vault passphrase") },
                    visualTransformation = PasswordVisualTransformation(),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )

                if (mode == PassDialogMode.SetNew) {
                    OutlinedTextField(
                        value = p2,
                        onValueChange = { p2 = it },
                        label = { Text("Confirm passphrase") },
                        visualTransformation = PasswordVisualTransformation(),
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
            }
        },
        confirmButton = {
            Button(onClick = { onSubmit(p1, p2) }) {
                Text(if (mode == PassDialogMode.SetNew) "Set" else "Unlock")
            }
        },
        dismissButton = {
            OutlinedButton(onClick = onDismiss) { Text("Cancel") }
        }
    )
}

@Composable
private fun TotpReauthDialog(
    onDismiss: () -> Unit,
    onSubmit: (String) -> Unit,
) {
    var code by remember { mutableStateOf("") }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Re-authentication required") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text("Enter your TOTP code to continue.")
                OutlinedTextField(
                    value = code,
                    onValueChange = { code = it },
                    label = { Text("6-digit code") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        },
        confirmButton = {
            Button(onClick = { onSubmit(code.trim()) }) { Text("Verify") }
        },
        dismissButton = {
            OutlinedButton(onClick = onDismiss) { Text("Cancel") }
        }
    )
}

private fun previewCarriers(): List<Carrier> {
    return listOf(
        Carrier(
            id = 1,
            name = "MTN MoMo",
            country = "GH",
            pinType = "numeric",
            pinLength = 4,
            ussdChangePinTemplate = "*170*9*{old_pin}*{new_pin}#",
            ussdBalanceTemplate = "*170#",
        ),
        Carrier(
            id = 2,
            name = "Airtel Money",
            country = "KE",
            pinType = "numeric",
            pinLength = 5,
            ussdChangePinTemplate = "*334*5*{old_pin}*{new_pin}#",
            ussdBalanceTemplate = "*334#",
        ),
    )
}

private fun previewWalletLocks(): List<WalletLock> {
    return listOf(
        WalletLock(
            id = "wl_001",
            carrierId = 1,
            carrierName = "MTN MoMo",
            label = "Main wallet",
            unlockAt = "2026-03-12 09:00:00",
            displayStatus = "locked",
            timeRemaining = TimeRemaining(days = 2, hours = 3, minutes = 12, totalSeconds = 184320),
        ),
        WalletLock(
            id = "wl_002",
            carrierId = 2,
            carrierName = "Airtel Money",
            label = "Savings",
            unlockAt = "2026-03-02 18:00:00",
            displayStatus = "unlocked",
            timeRemaining = null,
        ),
        WalletLock(
            id = "wl_003",
            carrierId = 1,
            carrierName = "MTN MoMo",
            label = "Trip fund",
            unlockAt = "2026-03-20 09:00:00",
            displayStatus = "setup_pending",
            timeRemaining = TimeRemaining(days = 0, hours = 1, minutes = 45, totalSeconds = 6300),
        ),
    )
}

private fun previewPendingSetup(): PendingWalletSetup? {
    return PendingWalletSetup(
        walletLockId = "wl_pending_001",
        carrierId = 1,
        unlockAt = "2026-03-12 09:00:00",
        label = "Resume example",
        newPinCipherB64 = "AA==",
        newPinIvB64 = "AA==",
        createdAtMs = System.currentTimeMillis(),
    )
}

@Preview(name = "Wallet Locks (Light)", showBackground = true, widthDp = 360, heightDp = 760)
@Composable
private fun PreviewWalletLocksTabLight() {
    MaterialTheme {
        WalletLocksTab(
            carriers = previewCarriers(),
            walletLocks = previewWalletLocks(),
            onCheckBalance = {},
            onRevealPin = {},
        )
    }
}

@Preview(
    name = "Wallet Locks (Dark)",
    showBackground = true,
    widthDp = 360,
    heightDp = 760,
    uiMode = Configuration.UI_MODE_NIGHT_YES,
)
@Composable
private fun PreviewWalletLocksTabDark() {
    MaterialTheme {
        WalletLocksTab(
            carriers = previewCarriers(),
            walletLocks = previewWalletLocks(),
            onCheckBalance = {},
            onRevealPin = {},
        )
    }
}

@Preview(name = "Wallet Setup (Light)", showBackground = true, widthDp = 360, heightDp = 760)
@Composable
private fun PreviewWalletSetupTabLight() {
    MaterialTheme {
        WalletSetupTab(
            carriers = previewCarriers(),
            pending = previewPendingSetup(),
            onLockWallet = { _, _, _, _ -> },
            onResumePending = { _, _ -> },
            onDiscardPending = { _ -> },
        )
    }
}

@Preview(
    name = "Wallet Setup (Dark)",
    showBackground = true,
    widthDp = 360,
    heightDp = 760,
    uiMode = Configuration.UI_MODE_NIGHT_YES,
)
@Composable
private fun PreviewWalletSetupTabDark() {
    MaterialTheme {
        WalletSetupTab(
            carriers = previewCarriers(),
            pending = previewPendingSetup(),
            onLockWallet = { _, _, _, _ -> },
            onResumePending = { _, _ -> },
            onDiscardPending = { _ -> },
        )
    }
}
