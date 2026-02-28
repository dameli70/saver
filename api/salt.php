<?php
// ============================================================
//  API: GET /api/salt.php
//  Issues a fresh 256-bit KDF salt for one password generation.
//  Salt is stored in session to prevent reuse or forgery.
//  One salt = one lock. Expired after use.
//
//  WHY server generates the salt:
//  - Prevents client from reusing salts (weakens key derivation)
//  - Ensures per-lock key uniqueness even if client is compromised
//  - Salt is not secret — it's returned in plaintext — but must be authentic
// ============================================================

require_once __DIR__ . '/../includes/helpers.php';
header('Content-Type: application/json');
requireLogin();

if ($_SERVER['REQUEST_METHOD'] !== 'GET') jsonResponse(['error' => 'Method not allowed'], 405);

$salt       = generateKdfSalt(); // base64(32 random bytes)
$sessionKey = 'pending_salt_' . getCurrentUserId();
$_SESSION[$sessionKey] = $salt;

jsonResponse([
    'success'        => true,
    'kdf_salt'       => $salt,
    'kdf_iterations' => PBKDF2_ITERATIONS,
]);
