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

require_once __DIR__ . '/../includes/install_guard.php';
requireInstalledForApi();

require_once __DIR__ . '/../includes/helpers.php';
header('Content-Type: application/json');
registerApiErrorHandling();
requireLogin();
requireVerifiedEmail();

if ($_SERVER['REQUEST_METHOD'] !== 'GET') jsonResponse(['error' => 'Method not allowed'], 405);

$salt = generateKdfSalt(); // base64(32 random bytes)

// Allow multiple concurrent "generate" flows (e.g., multiple tabs).
$userId = (int)getCurrentUserId();
$listKey = 'pending_salts_' . $userId;
$pending = [];
if (!empty($_SESSION[$listKey]) && is_array($_SESSION[$listKey])) {
    $pending = array_values(array_filter($_SESSION[$listKey], 'is_string'));
}
$pending[] = $salt;
// Keep the list bounded to reduce session bloat.
$pending = array_slice($pending, -25);
$_SESSION[$listKey] = $pending;

// Backward compatibility: also set the single key (older code paths).
$_SESSION['pending_salt_' . $userId] = $salt;

jsonResponse([
    'success'        => true,
    'kdf_salt'       => $salt,
    'kdf_iterations' => PBKDF2_ITERATIONS,
]);
