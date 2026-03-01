package com.locksmith.mobile

import android.app.DatePickerDialog
import android.app.TimePickerDialog
import android.content.pm.PackageManager
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import org.json.JSONObject
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
                    ussdClient.sendUssd(
                        ussd = c.ussdBalanceTemplate,
                        onResult = { resp -> msg = resp },
                        onError = { e -> err = e },
                    )
                },
                onRevealPin = { lock ->
                    fun doReveal() {
                        api.walletReveal(lock.id) { ok, j ->
                            if (ok) {
                                val wl = j?.optJSONObject("wallet_lock")
                                if (wl == null) {
                                    err = "Invalid response"
                                    return@walletReveal
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
                                return@walletReveal
                            }

                            val errorCode = j?.optString("error_code") ?: ""
                            if (errorCode == "reauth_required" && j.optJSONObject("methods")?.optBoolean("totp") == true) {
                                ensureStrongAuthThen { doReveal() }
                                return@walletReveal
                            }

                            err = j?.optString("error") ?: "Reveal failed"
                        }
                    }

                    doReveal()
                },
            )

            1 -> WalletSetupTab(
                carriers = carriers,
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

                                fun doCreate() {
                                    api.walletCreate(
                                        carrierId = carrier.id,
                                        label = label,
                                        unlockAt = unlockAt,
                                        cipher = enc,
                                        kdfSalt = salt,
                                        kdfIterations = iters,
                                    ) { ok, j ->
                                        if (!ok) {
                                            val errorCode = j?.optString("error_code") ?: ""
                                            if (errorCode == "reauth_required" && j.optJSONObject("methods")?.optBoolean("totp") == true) {
                                                ensureStrongAuthThen { doCreate() }
                                                return@walletCreate
                                            }

                                            err = j?.optString("error") ?: "Failed"
                                            return@walletCreate
                                        }

                                        val walletLockId = j?.optString("wallet_lock_id") ?: ""
                                        if (walletLockId.isBlank()) {
                                            err = "Invalid response"
                                            return@walletCreate
                                        }

                                        val ussd = carrier.ussdChangePinTemplate
                                            .replace("{old_pin}", currentPin)
                                            .replace("{new_pin}", newPin)

                                        msg = "Sending PIN-change USSD…"
                                        ussdClient.sendUssd(
                                            ussd = ussd,
                                            onResult = { resp ->
                                                msg = resp

                                                fun doConfirm() {
                                                    api.walletConfirm(walletLockId) { ok2, j2 ->
                                                        if (!ok2) {
                                                            val errorCode2 = j2?.optString("error_code") ?: ""
                                                            if (errorCode2 == "reauth_required" && j2.optJSONObject("methods")?.optBoolean("totp") == true) {
                                                                ensureStrongAuthThen { doConfirm() }
                                                                return@walletConfirm
                                                            }
                                                            err = j2?.optString("error") ?: "Failed to confirm"
                                                            return@walletConfirm
                                                        }

                                                        msg = "Wallet locked until $unlockAt"
                                                        refreshAll()
                                                    }
                                                }

                                                doConfirm()
                                            },
                                            onError = { e2 -> err = e2 },
                                        )
                                    }
                                }

                                doCreate()

                            } catch (t: Throwable) {
                                err = "Encryption failed"
                            }
                        }
                    }
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
                        Text("Remaining: ${tr.days}d ${tr.hours}h ${tr.minutes}m")
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
    onLockWallet: (carrier: Carrier, currentPin: String, unlockAt: String, label: String?) -> Unit,
) {
    val ctx = LocalContext.current

    var selectedCarrier by remember { mutableStateOf<Carrier?>(null) }
    var carrierMenu by remember { mutableStateOf(false) }

    var label by remember { mutableStateOf("") }
    var currentPin by remember { mutableStateOf("") }

    var date by remember { mutableStateOf(LocalDate.now().plusDays(1)) }
    var time by remember { mutableStateOf(LocalTime.of(9, 0)) }

    val dt = remember(date, time) { LocalDateTime.of(date, time) }
    val fmt = remember { DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss") }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Create wallet lock", style = MaterialTheme.typography.titleMedium)

        Box {
            OutlinedButton(onClick = { carrierMenu = true }, modifier = Modifier.fillMaxWidth()) {
                Text(selectedCarrier?.name ?: "Select carrier")
            }

            DropdownMenu(expanded = carrierMenu, onDismissRequest = { carrierMenu = false }) {
                carriers.forEach { c ->
                    DropdownMenuItem(
                        text = { Text(c.name) },
                        onClick = {
                            selectedCarrier = c
                            carrierMenu = false
                        }
                    )
                }
            }
        }

        OutlinedTextField(
            value = label,
            onValueChange = { label = it },
            label = { Text("Label (optional)") },
            modifier = Modifier.fillMaxWidth(),
        )

        OutlinedTextField(
            value = currentPin,
            onValueChange = { currentPin = it },
            label = { Text("Current wallet PIN") },
            visualTransformation = PasswordVisualTransformation(),
            modifier = Modifier.fillMaxWidth(),
        )

        Row(horizontalArrangement = Arrangement.spacedBy(12.dp), modifier = Modifier.fillMaxWidth()) {
            OutlinedButton(
                onClick = {
                    DatePickerDialog(
                        ctx,
                        { _, y, m, d -> date = LocalDate.of(y, m + 1, d) },
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
                        { _, hh, mm -> time = LocalTime.of(hh, mm) },
                        time.hour,
                        time.minute,
                        true,
                    ).show()
                },
                modifier = Modifier.weight(1f)
            ) {
                Text("Time: %02d:%02d".format(time.hour, time.minute))
            }
        }

        Text("Unlock at: ${dt.format(fmt)}")

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
