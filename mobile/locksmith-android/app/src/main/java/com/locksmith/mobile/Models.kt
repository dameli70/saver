package com.locksmith.mobile

data class Carrier(
    val id: Int,
    val name: String,
    val country: String?,
    val pinType: String,
    val pinLength: Int,
    val ussdChangePinTemplate: String,
    val ussdBalanceTemplate: String,
)

data class TimeRemaining(
    val days: Int,
    val hours: Int,
    val minutes: Int,
    val totalSeconds: Long,
)

data class WalletLock(
    val id: String,
    val label: String?,
    val unlockAt: String,
    val carrierId: Int,
    val carrierName: String,
    val displayStatus: String,
    val timeRemaining: TimeRemaining?,
)

data class VaultCheck(
    val cipherBlob: String,
    val iv: String,
    val authTag: String,
    val kdfSalt: String,
    val kdfIterations: Int,
)

data class WalletCipher(
    val cipherBlob: String,
    val iv: String,
    val authTag: String,
    val kdfSalt: String,
    val kdfIterations: Int,
)

sealed class LoginResult {
    data object Success : LoginResult()
    data object NeedsTotp : LoginResult()
    data class Error(val message: String) : LoginResult()
}
