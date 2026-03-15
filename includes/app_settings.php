<?php
// ============================================================
//  App settings helpers (singleton row)
//
//  Currently used for app-level branding assets like the app logo.
// ============================================================

require_once __DIR__ . '/helpers.php';

function hasAppSettingsTable(): bool {
    static $cached = null;
    if ($cached !== null) return $cached;

    try {
        $db = getDB();
        $stmt = $db->query("SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'app_settings' LIMIT 1");
        $cached = (bool)$stmt->fetchColumn();
        return $cached;
    } catch (Throwable) {
        $cached = false;
        return false;
    }
}

function ensureAppSettingsRow(): void {
    if (!hasAppSettingsTable()) return;

    try {
        $db = getDB();
        $db->exec('INSERT IGNORE INTO app_settings (id) VALUES (1)');
    } catch (Throwable) {
        // best effort
    }
}

function appLogoRow(): ?array {
    static $cached = null;
    static $loaded = false;

    if ($loaded) return $cached;
    $loaded = true;

    if (!hasAppSettingsTable()) {
        $cached = null;
        return null;
    }

    ensureAppSettingsRow();

    $db = getDB();
    $stmt = $db->prepare('SELECT logo_content_type, logo_enc_cipher, logo_iv, logo_tag, logo_updated_at FROM app_settings WHERE id = 1 LIMIT 1');
    $stmt->execute();
    $row = $stmt->fetch();

    if (!$row) {
        $cached = null;
        return null;
    }

    if (empty($row['logo_enc_cipher']) || empty($row['logo_iv']) || empty($row['logo_tag'])) {
        $cached = null;
        return null;
    }

    $cached = $row;
    return $cached;
}

function appHasUploadedLogo(): bool {
    return appLogoRow() !== null;
}

function appUploadedLogoContentType(): string {
    $row = appLogoRow();
    $ct = $row ? (string)($row['logo_content_type'] ?? '') : '';
    return $ct !== '' ? $ct : 'application/octet-stream';
}

function appUploadedLogoVersion(): string {
    $row = appLogoRow();
    if (!$row) return '0';

    $ts = $row['logo_updated_at'] ? strtotime((string)$row['logo_updated_at']) : 0;
    if ($ts && $ts > 0) return (string)$ts;

    $cipher = (string)$row['logo_enc_cipher'];
    $iv = (string)$row['logo_iv'];
    $tag = (string)$row['logo_tag'];

    return substr(hash('sha256', $cipher . $iv . $tag), 0, 16);
}

function appUploadedLogoUrl(string $prefix = ''): string {
    $row = appLogoRow();
    if (!$row) return '';

    $pfx = (string)$prefix;
    return $pfx . 'api/app_logo.php?v=' . rawurlencode(appUploadedLogoVersion());
}
