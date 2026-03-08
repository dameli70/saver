<?php
// ============================================================
//  API: GET /api/carriers.php
//  Lists active carriers + their USSD templates (non-secret)
// ============================================================

require_once __DIR__ . '/../includes/install_guard.php';
requireInstalledForApi();

require_once __DIR__ . '/../includes/helpers.php';
header('Content-Type: application/json');
startSecureSession();

requireLogin();
requireVerifiedEmail();

if ($_SERVER['REQUEST_METHOD'] !== 'GET') jsonResponse(['error' => 'Method not allowed'], 405);

try {
    $db = getDB();

    $has = (bool)$db->query("SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'carriers' LIMIT 1")->fetchColumn();
    if (!$has) {
        jsonResponse(['error' => 'Carriers are not available. Apply migrations in config/migrations/.'], 500);
    }

    $hasCol = function (string $column) use ($db): bool {
        $stmt = $db->prepare("SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'carriers' AND column_name = ? LIMIT 1");
        $stmt->execute([$column]);
        return (bool)$stmt->fetchColumn();
    };

    $hasWalletCols = $hasCol('wallet_default_action') && $hasCol('wallet_allow_open_dialer') && $hasCol('wallet_allow_copy_ussd');

    if ($hasWalletCols) {
        $rows = $db->query("SELECT id, name, country, pin_type, pin_length, ussd_change_pin_template, ussd_balance_template, wallet_allow_open_dialer, wallet_allow_copy_ussd, wallet_default_action FROM carriers WHERE is_active = 1 ORDER BY name ASC")->fetchAll();
        foreach ($rows as &$r) {
            $r['wallet_allow_open_dialer'] = (int)$r['wallet_allow_open_dialer'];
            $r['wallet_allow_copy_ussd'] = (int)$r['wallet_allow_copy_ussd'];
            $r['wallet_default_action'] = (string)$r['wallet_default_action'];
        }
        unset($r);
    } else {
        $rows = $db->query("SELECT id, name, country, pin_type, pin_length, ussd_change_pin_template, ussd_balance_template FROM carriers WHERE is_active = 1 ORDER BY name ASC")->fetchAll();
        foreach ($rows as &$r) {
            $r['wallet_allow_open_dialer'] = 1;
            $r['wallet_allow_copy_ussd'] = 1;
            $r['wallet_default_action'] = 'open_dialer';
        }
        unset($r);
    }

    jsonResponse(['success' => true, 'carriers' => $rows]);
} catch (Throwable $e) {
    jsonResponse(['error' => 'Failed to load carriers'], 500);
}
