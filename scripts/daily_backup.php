<?php
// ============================================================
//  Controle — Daily System Backup (cron)
//
//  Run once per day:
//    php scripts/daily_backup.php
//
//  Writes:
//    storage/daily_backups/system_backup_YYYYMMDD.sql.gz
//
//  Notes:
//   - Requires mysqldump + gzip on PATH.
//   - Uses --defaults-extra-file so DB password is not exposed in argv.
//   - Creates storage/daily_backups with 0700 and drops a defensive .htaccess.
// ============================================================

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "This script must be run from the command line.\n");
    exit(1);
}

$lockPath = __DIR__ . '/daily_backup.lock';
$lockFp = @fopen($lockPath, 'c');
if (!$lockFp) {
    fwrite(STDERR, "Could not open lock file: {$lockPath}\n");
    exit(1);
}
if (!flock($lockFp, LOCK_EX | LOCK_NB)) {
    fwrite(STDOUT, '[' . date('c') . "] Another daily_backup is running; exiting.\n");
    exit(0);
}
register_shutdown_function(function() use ($lockFp) {
    @flock($lockFp, LOCK_UN);
    @fclose($lockFp);
});

require_once __DIR__ . '/../config/database.php';

function logLine(string $s): void {
    fwrite(STDOUT, '[' . date('c') . '] ' . $s . "\n");
}

function rootDir(): string {
    $root = realpath(__DIR__ . '/..');
    return $root !== false ? $root : dirname(__DIR__);
}

function ensureBackupDir(): string {
    $dir = rootDir() . '/storage/daily_backups';

    if (!is_dir($dir)) {
        if (!@mkdir($dir, 0700, true) && !is_dir($dir)) {
            throw new RuntimeException('Failed to create backup directory: ' . $dir);
        }
    }

    @chmod($dir, 0700);

    // Best-effort protection if served by Apache.
    $htaccess = $dir . '/.htaccess';
    if (!file_exists($htaccess)) {
        @file_put_contents($htaccess, "Deny from all\n");
        @chmod($htaccess, 0600);
    }

    $index = $dir . '/index.html';
    if (!file_exists($index)) {
        @file_put_contents($index, "");
        @chmod($index, 0600);
    }

    return $dir;
}

function findBin(array $candidates): ?string {
    foreach ($candidates as $c) {
        $c = (string)$c;
        if ($c === '') continue;

        if (strpos($c, '/') !== false) {
            if (is_file($c) && is_executable($c)) return $c;
            continue;
        }

        $out = [];
        $rc = 0;
        @exec('command -v ' . escapeshellarg($c) . ' 2>/dev/null', $out, $rc);
        if ($rc === 0 && !empty($out[0])) {
            $p = trim((string)$out[0]);
            if ($p !== '' && is_executable($p)) return $p;
        }
    }

    return null;
}

function safeCnfValue(string $v): string {
    return str_replace(["\r", "\n"], '', $v);
}

function rotateBackups(string $dir, int $keepCount): int {
    $keepCount = max(1, $keepCount);

    $files = @scandir($dir);
    if (!is_array($files)) return 0;

    $names = [];
    foreach ($files as $f) {
        if (!preg_match('/^system_backup_\d{8}\.sql\.gz$/', $f)) continue;
        $path = $dir . '/' . $f;
        if (!is_file($path)) continue;
        $names[] = $f;
    }

    rsort($names, SORT_STRING);

    $deleted = 0;
    foreach (array_slice($names, $keepCount) as $f) {
        $path = $dir . '/' . $f;
        if (@unlink($path)) $deleted++;
    }

    return $deleted;
}

$keepCount = 14;

try {
    if (!defined('DB_HOST') || !defined('DB_NAME') || !defined('DB_USER') || !defined('DB_PASS')) {
        throw new RuntimeException('Missing DB_* constants (check config/database.php)');
    }

    $backupDir = ensureBackupDir();

    $date = gmdate('Ymd');
    $finalPath = $backupDir . '/system_backup_' . $date . '.sql.gz';

    if (is_file($finalPath) && filesize($finalPath) > 0) {
        logLine('Backup already exists for today: ' . basename($finalPath));
        $deleted = rotateBackups($backupDir, $keepCount);
        if ($deleted > 0) logLine('Rotated ' . $deleted . ' old backup(s).');
        exit(0);
    }

    $mysqldump = findBin(['mysqldump', '/usr/bin/mysqldump', '/usr/local/bin/mysqldump']);
    if ($mysqldump === null) {
        throw new RuntimeException('mysqldump not found on PATH');
    }

    $gzip = findBin(['gzip', '/bin/gzip', '/usr/bin/gzip', '/usr/local/bin/gzip']);
    if ($gzip === null) {
        throw new RuntimeException('gzip not found on PATH');
    }

    $cnfPath = tempnam(sys_get_temp_dir(), 'controle_mysql_');
    if ($cnfPath === false) {
        throw new RuntimeException('Failed to create temporary mysql config');
    }
    @chmod($cnfPath, 0600);

    $cnf = "[client]\n";
    $cnf .= 'user=' . safeCnfValue((string)DB_USER) . "\n";
    $cnf .= 'password=' . safeCnfValue((string)DB_PASS) . "\n";
    $cnf .= 'host=' . safeCnfValue((string)DB_HOST) . "\n";
    $cnf .= "default-character-set=utf8mb4\n";

    if (file_put_contents($cnfPath, $cnf) === false) {
        throw new RuntimeException('Failed to write temporary mysql config');
    }

    $tmpOut = $finalPath . '.tmp.' . getmypid();

    // Use shell pipeline for gzip.
    $cmd = escapeshellarg($mysqldump)
        . ' --defaults-extra-file=' . escapeshellarg($cnfPath)
        . ' --single-transaction --quick --routines --events --triggers --hex-blob'
        . ' ' . escapeshellarg((string)DB_NAME)
        . ' | ' . escapeshellarg($gzip) . ' -c'
        . ' > ' . escapeshellarg($tmpOut);

    logLine('Starting mysqldump...');

    $proc = proc_open(['/bin/sh', '-c', $cmd], [
        0 => ['file', '/dev/null', 'r'],
        1 => ['file', 'php://stdout', 'w'],
        2 => ['file', 'php://stderr', 'w'],
    ], $pipes);

    $rc = 1;
    if (is_resource($proc)) {
        $rc = proc_close($proc);
    }

    @unlink($cnfPath);

    if ($rc !== 0) {
        @unlink($tmpOut);
        throw new RuntimeException('mysqldump failed with exit code ' . $rc);
    }

    if (!is_file($tmpOut) || filesize($tmpOut) < 1) {
        @unlink($tmpOut);
        throw new RuntimeException('Backup output is empty');
    }

    @chmod($tmpOut, 0600);

    if (!@rename($tmpOut, $finalPath)) {
        @unlink($tmpOut);
        throw new RuntimeException('Failed to move backup into place');
    }

    @chmod($finalPath, 0600);

    logLine('Wrote backup: ' . $finalPath);

    $deleted = rotateBackups($backupDir, $keepCount);
    if ($deleted > 0) logLine('Rotated ' . $deleted . ' old backup(s).');

    logLine('Done.');

} catch (Throwable $e) {
    fwrite(STDERR, '[' . date('c') . '] ERROR: ' . $e->getMessage() . "\n");
    exit(1);
}
