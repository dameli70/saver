<?php

function getAppBasePath(): string {
    $dir = rtrim(dirname($_SERVER['SCRIPT_NAME'] ?? '/'), '/');
    $dir = preg_replace('#/(api|install)$#', '', $dir);
    return ($dir === '/' ? '' : $dir);
}

function getInstallUrlPath(): string {
    $base = getAppBasePath();
    return ($base ? $base : '') . '/install/index.php';
}

function isAppInstalled(): bool {
    if (file_exists(__DIR__ . '/../config/installed.flag')) return true;

    $cfg = __DIR__ . '/../config/database.php';
    if (!file_exists($cfg)) return false;

    require_once $cfg;

    if (!defined('APP_HMAC_SECRET') || str_contains(APP_HMAC_SECRET, 'REPLACE_WITH_64+_RANDOM_BYTES')) {
        return false;
    }

    if (!defined('DB_HOST') || !defined('DB_NAME') || !defined('DB_USER') || !defined('DB_PASS') || !defined('DB_CHARSET')) {
        return false;
    }

    // If core PHP extensions are missing, route to installer so it can show a clear error.
    if (!extension_loaded('pdo_mysql')) return false;

    // Best-effort schema check:
    // - If DB is reachable and required tables are missing => not installed
    // - If DB is temporarily unreachable => treat as installed (avoid redirect loops)
    try {
        $dsn = "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=" . DB_CHARSET;
        $pdo = new PDO($dsn, DB_USER, DB_PASS, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);

        $stmt = $pdo->prepare("SELECT table_name FROM information_schema.tables WHERE table_schema = ? AND table_name IN ('users','locks','audit_log')");
        $stmt->execute([DB_NAME]);
        $names = array_column($stmt->fetchAll(), 'table_name');

        return count(array_intersect(['users','locks','audit_log'], $names)) === 3;

    } catch (Throwable) {
        return true;
    }
}

function requireInstalledForPage(): void {
    if (isAppInstalled()) return;
    header('Location: ' . getInstallUrlPath());
    exit;
}

function requireInstalledForApi(): void {
    if (isAppInstalled()) return;

    http_response_code(503);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('Pragma: no-cache');
    echo json_encode([
        'error' => 'Application not installed. Visit ' . getInstallUrlPath() . ' to complete setup.',
    ], JSON_UNESCAPED_UNICODE);
    exit;
}
