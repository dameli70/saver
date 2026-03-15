<?php
// ============================================================
//  Media crypto helpers (server-side only)
//
//  Used for encrypting/decrypting stored binary media (e.g., profile avatars).
//  This does NOT touch any vault passphrase / zero-knowledge lock crypto.
// ============================================================

function mediaEncKey(): string {
    // Derive a dedicated key from APP_HMAC_SECRET (domain-separated from appEncKey()).
    return hash('sha256', APP_HMAC_SECRET . '|media', true);
}

function mediaEncryptBytes(string $plaintext): array {
    $iv = random_bytes(12);
    $tag = '';

    $cipher = openssl_encrypt($plaintext, 'aes-256-gcm', mediaEncKey(), OPENSSL_RAW_DATA, $iv, $tag);
    if ($cipher === false) {
        throw new RuntimeException('Encryption failed');
    }

    return ['cipher' => $cipher, 'iv' => $iv, 'tag' => $tag];
}

function mediaDecryptBytes(string $cipher, string $iv, string $tag): string {
    $plain = openssl_decrypt($cipher, 'aes-256-gcm', mediaEncKey(), OPENSSL_RAW_DATA, $iv, $tag);
    if ($plain === false) {
        throw new RuntimeException('Decryption failed');
    }

    return $plain;
}
