package com.locksmith.mobile

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

data class DeviceEnc(
    val cipherB64: String,
    val ivB64: String,
)

object DeviceCrypto {
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val KEY_ALIAS = "locksmith_device_aes_v1"

    private fun getOrCreateKey(): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE)
        ks.load(null)

        val existing = ks.getKey(KEY_ALIAS, null)
        if (existing is SecretKey) return existing

        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        gen.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return gen.generateKey()
    }

    fun encrypt(plain: String): DeviceEnc {
        val key = getOrCreateKey()
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, key)
        val ct = c.doFinal(plain.toByteArray(StandardCharsets.UTF_8))
        return DeviceEnc(
            cipherB64 = Base64.encodeToString(ct, Base64.NO_WRAP),
            ivB64 = Base64.encodeToString(c.iv, Base64.NO_WRAP),
        )
    }

    fun decrypt(enc: DeviceEnc): String {
        val key = getOrCreateKey()
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        val iv = Base64.decode(enc.ivB64, Base64.NO_WRAP)
        val spec = GCMParameterSpec(128, iv)
        c.init(Cipher.DECRYPT_MODE, key, spec)
        val ct = Base64.decode(enc.cipherB64, Base64.NO_WRAP)
        val pt = c.doFinal(ct)
        return String(pt, StandardCharsets.UTF_8)
    }
}
