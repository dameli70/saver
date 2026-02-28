<?php
// ============================================================
//  API: POST /api/vault_verify.php
//
//  Verifies a vault passphrase against the user's verifier(s)
//  and returns which slot it matches (1=primary, 2=alt).
// ============================================================

require_once __DIR__ . '/../includes/install_guard.php';
requireInstalledForApi();

require_once __DIR__ . '/../includes/helpers.php';
header('Content-Type: application/json; charset=utf-8');
startSecureSession();

requireLogin();
requireCsrf();
requireVerifiedEmail();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') jsonResponse(['error' => 'Method not allowed'], 405);

$body = json_decode(file_get_contents('php://input'), true);
$vp   = (string)($body['vault_passphrase'] ?? '');

if (strlen($vp) < 10) jsonResponse(['error' => 'Vault passphrase must be at least 10 characters'], 400);

$userId = getCurrentUserId();
$db     = getDB();

$select = hasVaultAltVerifierColumns()
    ? "vault_verifier, vault_verifier_salt, vault_verifier_alt, vault_verifier_alt_salt"
    : "vault_verifier, vault_verifier_salt, NULL AS vault_verifier_alt, NULL AS vault_verifier_alt_salt";

$stmt = $db->prepare("SELECT {$select} FROM users WHERE id = ?");
$stmt->execute([(int)$userId]);
$u = $stmt->fetch();

if (!$u) jsonResponse(['error' => 'Unauthorized'], 401);

$ok1 = verifyVaultPassphrase($vp . ($u['vault_verifier_salt'] ?? ''), $u['vault_verifier']);
$ok2 = false;
if (!empty($u['vault_verifier_alt']) && !empty($u['vault_verifier_alt_salt'])) {
    $ok2 = verifyVaultPassphrase($vp . $u['vault_verifier_alt_salt'], $u['vault_verifier_alt']);
}

if (!$ok1 && !$ok2) {
    auditLog('vault_auth_fail');
    jsonResponse(['error' => 'Incorrect vault passphrase'], 403);
}

// If the passphrase matches both, prefer slot 2 (it implies rotation target).
$slot = $ok2 ? 2 : 1;

jsonResponse(['success' => true, 'slot' => $slot]);
