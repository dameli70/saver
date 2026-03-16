<?php
// ============================================================
//  API: /api/system_backups.php
//  Admin-only list + download of daily SQL backups.
// ============================================================

require_once __DIR__ . '/../includes/install_guard.php';
requireInstalledForApi();

require_once __DIR__ . '/../includes/helpers.php';
startSecureSession();

requireLogin();
requireVerifiedEmail();
requireAdmin();
requireStrongAuth();

function backupDir(): string {
    $root = realpath(__DIR__ . '/..');
    if ($root === false) $root = dirname(__DIR__);
    return $root . '/storage/daily_backups';
}

function isValidBackupName(string $name): bool {
    return (bool)preg_match('/^system_backup_\d{8}\.sql\.gz$/', $name);
}

function listBackups(): array {
    $dir = backupDir();
    if (!is_dir($dir)) return [];

    $files = @scandir($dir);
    if (!is_array($files)) return [];

    $out = [];
    foreach ($files as $f) {
        if (!isValidBackupName($f)) continue;
        $path = $dir . '/' . $f;
        if (!is_file($path)) continue;

        $st = @stat($path);
        $bytes = $st ? (int)$st['size'] : (int)@filesize($path);
        $mtime = $st ? (int)$st['mtime'] : (int)@filemtime($path);

        $out[] = [
            'name' => $f,
            'bytes' => $bytes,
            'created_at' => $mtime > 0 ? gmdate('Y-m-d H:i:s', $mtime) : null,
        ];
    }

    usort($out, function(array $a, array $b) {
        $at = (string)($a['created_at'] ?? '');
        $bt = (string)($b['created_at'] ?? '');
        return strcmp($bt, $at);
    });

    return $out;
}

function resolveBackupPath(string $name): string {
    if (!isValidBackupName($name)) {
        throw new RuntimeException('Invalid backup name');
    }

    $dir = backupDir();
    $path = $dir . '/' . $name;

    $realDir = realpath($dir);
    $realPath = realpath($path);
    if ($realDir === false || $realPath === false) {
        throw new RuntimeException('Backup not found');
    }

    if (strpos($realPath, $realDir . DIRECTORY_SEPARATOR) !== 0 && $realPath !== $realDir) {
        throw new RuntimeException('Invalid backup path');
    }

    if (!is_file($realPath)) {
        throw new RuntimeException('Backup not found');
    }

    return $realPath;
}

$action = (string)($_GET['action'] ?? 'list');

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    jsonResponse(['error' => 'Method not allowed'], 405);
}

if ($action === 'list') {
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('Pragma: no-cache');

    jsonResponse(['success' => true, 'backups' => listBackups()]);
}

if ($action === 'download') {
    $name = (string)($_GET['name'] ?? '');
    if ($name === '') jsonResponse(['error' => 'name required'], 400);

    try {
        $path = resolveBackupPath($name);
    } catch (Throwable $e) {
        jsonResponse(['error' => $e->getMessage()], 404);
    }

    $size = (int)(@filesize($path) ?: 0);

    header('Content-Type: application/gzip');
    header('Content-Disposition: attachment; filename="' . basename($name) . '"');
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('Pragma: no-cache');
    header('X-Content-Type-Options: nosniff');
    if ($size > 0) header('Content-Length: ' . $size);

    readfile($path);
    exit;
}

jsonResponse(['error' => 'Unknown action'], 400);
