package com.locksmith.mobile

import android.util.Base64
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

object VaultCrypto {

    fun b64Decode(s: String): ByteArray = Base64.decode(s, Base64.DEFAULT)
    fun b64Encode(bytes: ByteArray): String = Base64.encodeToString(bytes, Base64.NO_WRAP)

    fun deriveKey(passphrase: String, kdfSaltB64: String, iterations: Int): SecretKey {
        val salt = b64Decode(kdfSaltB64)
        val spec = PBEKeySpec(passphrase.toCharArray(), salt, iterations, 256)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val keyBytes = factory.generateSecret(spec).encoded
        return SecretKeySpec(keyBytes, "AES")
    }

    data class EncBlob(
        val cipherBlobB64: String,
        val ivB64: String,
        val authTagB64: String,
    )

    fun encryptAesGcm(plain: String, key: SecretKey): EncBlob {
        val iv = ByteArray(12)
        SecureRandom().nextBytes(iv)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
        val out = cipher.doFinal(plain.toByteArray(Charsets.UTF_8))

        val tag = out.copyOfRange(out.size - 16, out.size)
        val ct = out.copyOfRange(0, out.size - 16)

        return EncBlob(
            cipherBlobB64 = b64Encode(ct),
            ivB64 = b64Encode(iv),
            authTagB64 = b64Encode(tag),
        )
    }

    fun decryptAesGcm(cipherBlobB64: String, ivB64: String, authTagB64: String, key: SecretKey): String {
        val ct = b64Decode(cipherBlobB64)
        val iv = b64Decode(ivB64)
        val tag = b64Decode(authTagB64)

        val combined = ByteArray(ct.size + tag.size)
        System.arraycopy(ct, 0, combined, 0, ct.size)
        System.arraycopy(tag, 0, combined, ct.size, tag.size)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
        val pt = cipher.doFinal(combined)
        return pt.toString(Charsets.UTF_8)
    }
}
