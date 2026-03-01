package com.locksmith.mobile

import android.Manifest
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setContent {
            MaterialTheme {
                val ctx = LocalContext.current
                val prefs = remember { AppPrefs(ctx) }
                val api = remember { LocksmithApi(ctx, prefs) }

                var screen by remember { mutableStateOf<Screen>(Screen.Login) }
                var pendingTotp by remember { mutableStateOf(false) }

                val requestCallPhone = rememberLauncherForActivityResult(
                    ActivityResultContracts.RequestPermission()
                ) { /* no-op */ }

                LaunchedEffect(Unit) {
                    // Attempt session restore
                    val ok = api.refreshCsrf()
                    if (ok) {
                        screen = Screen.WalletHome
                    }
                }

                when (val s = screen) {
                    Screen.Login -> LoginScreen(
                        api = api,
                        prefs = prefs,
                        onNeedsTotp = {
                            pendingTotp = true
                            screen = Screen.Totp
                        },
                        onLoggedIn = {
                            pendingTotp = false
                            screen = Screen.WalletHome
                        }
                    )

                    Screen.Totp -> TotpScreen(
                        api = api,
                        onBack = {
                            pendingTotp = false
                            screen = Screen.Login
                        },
                        onLoggedIn = {
                            pendingTotp = false
                            screen = Screen.WalletHome
                        }
                    )

                    Screen.WalletHome -> WalletHomeScreen(
                        api = api,
                        prefs = prefs,
                        onRequestCallPermission = { requestCallPhone.launch(Manifest.permission.CALL_PHONE) },
                        onLogout = {
                            api.logout()
                            screen = Screen.Login
                        }
                    )

                    is Screen.Error -> ErrorScreen(message = s.message) {
                        screen = Screen.Login
                    }
                }
            }
        }
    }
}

sealed class Screen {
    data object Login : Screen()
    data object Totp : Screen()
    data object WalletHome : Screen()
    data class Error(val message: String) : Screen()
}

@Composable
private fun ErrorScreen(message: String, onBack: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(20.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(text = message)
        Spacer(modifier = Modifier.height(16.dp))
        Button(onClick = onBack) { Text("Back") }
    }
}

@Composable
private fun LoginScreen(
    api: LocksmithApi,
    prefs: AppPrefs,
    onNeedsTotp: () -> Unit,
    onLoggedIn: () -> Unit,
) {
    var baseUrl by remember { mutableStateOf(prefs.baseUrl) }
    var email by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var err by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(20.dp),
        verticalArrangement = Arrangement.Center,
    ) {
        Text("LOCKSMITH", style = MaterialTheme.typography.headlineMedium)
        Spacer(modifier = Modifier.height(18.dp))

        OutlinedTextField(
            value = baseUrl,
            onValueChange = { baseUrl = it },
            label = { Text("Server base URL") },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
        )
        Spacer(modifier = Modifier.height(10.dp))

        OutlinedTextField(
            value = email,
            onValueChange = { email = it },
            label = { Text("Email") },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
        )
        Spacer(modifier = Modifier.height(10.dp))

        OutlinedTextField(
            value = password,
            onValueChange = { password = it },
            label = { Text("Login password") },
            visualTransformation = PasswordVisualTransformation(),
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
        )

        if (err != null) {
            Spacer(modifier = Modifier.height(12.dp))
            Text(err!!, color = MaterialTheme.colorScheme.error)
        }

        Spacer(modifier = Modifier.height(16.dp))

        Button(
            onClick = {
                err = null
                busy = true
                prefs.baseUrl = baseUrl
                api.setBaseUrl(baseUrl)

                api.login(email.trim(), password) { res ->
                    busy = false
                    when (res) {
                        is LoginResult.Success -> onLoggedIn()
                        is LoginResult.NeedsTotp -> onNeedsTotp()
                        is LoginResult.Error -> err = res.message
                    }
                }
            },
            enabled = !busy,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(if (busy) "Signing in…" else "Sign in")
        }
    }
}

@Composable
private fun TotpScreen(
    api: LocksmithApi,
    onBack: () -> Unit,
    onLoggedIn: () -> Unit,
) {
    var code by remember { mutableStateOf("") }
    var err by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(20.dp),
        verticalArrangement = Arrangement.Center,
    ) {
        Text("TOTP required", style = MaterialTheme.typography.headlineSmall)
        Spacer(modifier = Modifier.height(10.dp))

        OutlinedTextField(
            value = code,
            onValueChange = { code = it },
            label = { Text("6-digit code") },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
        )

        if (err != null) {
            Spacer(modifier = Modifier.height(12.dp))
            Text(err!!, color = MaterialTheme.colorScheme.error)
        }

        Spacer(modifier = Modifier.height(16.dp))

        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            OutlinedButton(onClick = onBack, enabled = !busy, modifier = Modifier.weight(1f)) {
                Text("Back")
            }
            Button(
                onClick = {
                    err = null
                    busy = true
                    api.loginTotp(code.trim()) { ok, msg ->
                        busy = false
                        if (ok) onLoggedIn() else err = msg
                    }
                },
                enabled = !busy,
                modifier = Modifier.weight(1f),
            ) {
                Text(if (busy) "Verifying…" else "Verify")
            }
        }
    }
}
