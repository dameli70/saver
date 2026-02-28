<?php
// ============================================================
//  LOCKSMITH — CLI Installer
//
//  Usage:
//    php install/install.php
//    php install/install.php --non-interactive --init-db=1 \
//      --db-host=localhost --db-name=locksmith --db-user=root --db-pass='' \
//      --app-env=development --app-name=LOCKSMITH --mail-from=no-reply@localhost \
//      --email-verify-ttl-hours=24
// ============================================================

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "This installer must be run from the command line.\n");
    exit(1);
}

$root = realpath(__DIR__ . '/..');
if ($root === false) {
    fwrite(STDERR, "Could not resolve project root.\n");
    exit(1);
}

$configPath   = $root . '/config/database.php';
$schemaPath   = $root . '/config/schema.sql';
$migrationsDir = $root . '/config/migrations';

function usage(): void {
    $msg = <<<TXT
LOCKSMITH Installer

Options:
  --non-interactive               Do not prompt. Require flags for all values.
  --force=1                       Overwrite config/database.php without prompting.

  --db-host=HOST                  Database host
  --db-name=NAME                  Database name
  --db-user=USER                  Database user
  --db-pass=PASS                  Database password
  --db-charset=CHARSET            Database charset (default: utf8mb4)

  --app-env=development|production
  --app-name=NAME                 Default: LOCKSMITH
  --mail-from=EMAIL               Default: no-reply@localhost
  --email-verify-ttl-hours=HOURS  Default: 24

  --init-db=1                     Create tables by running config/schema.sql
  --apply-migrations=1            Apply SQL files in config/migrations (safe to re-run)

TXT;
    fwrite(STDOUT, $msg);
}

function parseArgs(array $argv): array {
    $out = [];
    foreach ($argv as $i => $arg) {
        if ($i === 0) continue;
        if ($arg === '--help' || $arg === '-h') {
            $out['help'] = true;
            continue;
        }
        if (str_starts_with($arg, '--')) {
            $kv = substr($arg, 2);
            $eq = strpos($kv, '=');
            if ($eq === false) {
                $out[$kv] = true;
            } else {
                $k = substr($kv, 0, $eq);
                $v = substr($kv, $eq + 1);
                $out[$k] = $v;
            }
        }
    }
    return $out;
}

function prompt(string $label, ?string $default = null): string {
    $suffix = $default !== null ? " [{$default}]" : '';
    fwrite(STDOUT, $label . $suffix . ': ');
    $in = fgets(STDIN);
    if ($in === false) return $default ?? '';
    $in = trim($in);
    if ($in === '' && $default !== null) return $default;
    return $in;
}

function promptYesNo(string $label, bool $default): bool {
    $d = $default ? 'Y/n' : 'y/N';
    $in = strtolower(prompt($label . " ({$d})", ''));
    if ($in === '') return $default;
    return in_array($in, ['y', 'yes'], true);
}

function requireExt(string $ext): void {
    if (!extension_loaded($ext)) {
        fwrite(STDERR, "Missing required PHP extension: {$ext}\n");
        exit(1);
    }
}

function phpSingleQuoted(string $value): string {
    return "'" . str_replace(["\\", "'"], ["\\\\", "\\'"], $value) . "'";
}

function updateConfigFile(string $path, array $vals, bool $force): void {
    if (!file_exists($path)) {
        fwrite(STDERR, "Missing config file: {$path}\n");
        exit(1);
    }

    if (!$force) {
        $ok = promptYesNo("Update {$path}?", true);
        if (!$ok) {
            fwrite(STDOUT, "Aborted.\n");
            exit(0);
        }
    }

    $backupPath = $path . '.bak.' . date('Ymd_His');
    if (!copy($path, $backupPath)) {
        fwrite(STDERR, "Failed to create backup: {$backupPath}\n");
        exit(1);
    }

    $src = file_get_contents($path);
    if ($src === false) {
        fwrite(STDERR, "Failed to read: {$path}\n");
        exit(1);
    }

    $repls = [
        'DB_HOST' => $vals['db_host'],
        'DB_NAME' => $vals['db_name'],
        'DB_USER' => $vals['db_user'],
        'DB_PASS' => $vals['db_pass'],
        'DB_CHARSET' => $vals['db_charset'],
        'APP_HMAC_SECRET' => $vals['app_hmac_secret'],
        'APP_ENV' => $vals['app_env'],
        'APP_NAME' => $vals['app_name'],
        'MAIL_FROM' => $vals['mail_from'],
        'EMAIL_VERIFY_TTL_HOURS' => (string)$vals['email_verify_ttl_hours'],
    ];

    foreach ($repls as $const => $val) {
        if (in_array($const, ['EMAIL_VERIFY_TTL_HOURS'], true)) {
            $pattern = "/define\\('" . preg_quote($const, '/') . "',\\s*[^)]+\\);/";
            $replace = "define('{$const}', " . (int)$val . ");";
        } else {
            $pattern = "/define\\('" . preg_quote($const, '/') . "',\\s*'[^']*'\\);/";
            $replace = "define('{$const}', " . phpSingleQuoted($val) . ");";
        }
        $src = preg_replace($pattern, $replace, $src, 1, $count);
        if ($count !== 1) {
            fwrite(STDERR, "Could not update {$const} in {$path} (pattern mismatch).\n");
            fwrite(STDERR, "Backup remains at {$backupPath}.\n");
            exit(1);
        }
    }

    if (file_put_contents($path, $src) === false) {
        fwrite(STDERR, "Failed to write: {$path}\n");
        fwrite(STDERR, "Backup remains at {$backupPath}.\n");
        exit(1);
    }

    fwrite(STDOUT, "Updated {$path}\n");
    fwrite(STDOUT, "Backup saved to {$backupPath}\n");
}

function connectPdoServer(string $host, string $charset, string $user, string $pass): PDO {
    $dsn = "mysql:host={$host};charset={$charset}";
    return new PDO($dsn, $user, $pass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);
}

function connectPdoDb(string $host, string $db, string $charset, string $user, string $pass): PDO {
    $dsn = "mysql:host={$host};dbname={$db};charset={$charset}";
    return new PDO($dsn, $user, $pass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);
}

function splitSqlStatements(string $sql): array {
    // schema.sql is simple (no stored procedures). We strip -- comments and split on semicolons.
    $lines = preg_split('/\R/', $sql);
    $buf = [];
    foreach ($lines as $line) {
        $trim = ltrim($line);
        if (str_starts_with($trim, '--')) continue;
        $buf[] = $line;
    }
    $sql = implode("\n", $buf);
    $parts = array_map('trim', explode(';', $sql));
    return array_values(array_filter($parts, fn($p) => $p !== ''));
}

function ensureMigrationsTable(PDO $pdo): void {
    $pdo->exec("CREATE TABLE IF NOT EXISTS schema_migrations (filename VARCHAR(255) PRIMARY KEY, applied_at DATETIME DEFAULT CURRENT_TIMESTAMP) ENGINE=InnoDB");
}

function migrationApplied(PDO $pdo, string $filename): bool {
    $stmt = $pdo->prepare("SELECT filename FROM schema_migrations WHERE filename = ?");
    $stmt->execute([$filename]);
    return (bool)$stmt->fetch();
}

function markMigrationApplied(PDO $pdo, string $filename): void {
    $stmt = $pdo->prepare("INSERT IGNORE INTO schema_migrations (filename) VALUES (?)");
    $stmt->execute([$filename]);
}

function applySqlFile(PDO $pdo, string $path, bool $ignoreDuplicates): void {
    $sql = file_get_contents($path);
    if ($sql === false) {
        throw new RuntimeException("Failed to read SQL file: {$path}");
    }
    $stmts = splitSqlStatements($sql);
    foreach ($stmts as $stmt) {
        $trim = ltrim($stmt);
        if ($trim === '') continue;
        if (preg_match('/^CREATE\s+DATABASE/i', $trim)) continue;
        if (preg_match('/^USE\s+/i', $trim)) continue;

        try {
            $pdo->exec($stmt);
        } catch (PDOException $e) {
            $msg = $e->getMessage();
            if ($ignoreDuplicates && (
                str_contains($msg, 'Duplicate column name') ||
                str_contains($msg, 'Duplicate key name') ||
                str_contains($msg, 'Duplicate index')
            )) {
                continue;
            }
            throw $e;
        }
    }
}

$args = parseArgs($argv);
if (!empty($args['help'])) {
    usage();
    exit(0);
}

$nonInteractive = !empty($args['non-interactive']);
$force         = (($args['force'] ?? '') === '1');

// ── Basic checks ───────────────────────────────────────────
if (version_compare(PHP_VERSION, '8.1.0', '<')) {
    fwrite(STDERR, "PHP 8.1+ required. You are running " . PHP_VERSION . "\n");
    exit(1);
}
requireExt('openssl');
requireExt('pdo');
requireExt('pdo_mysql');
requireExt('mbstring');

if (!file_exists($schemaPath)) {
    fwrite(STDERR, "Missing schema file: {$schemaPath}\n");
    exit(1);
}

// ── Gather values ──────────────────────────────────────────
$get = function(string $key, ?string $default = null) use ($args, $nonInteractive): string {
    if (isset($args[$key])) return (string)$args[$key];
    if ($nonInteractive) {
        if ($default !== null) return $default;
        fwrite(STDERR, "Missing required option --{$key}=... (non-interactive).\n");
        exit(1);
    }
    return prompt(str_replace('-', ' ', strtoupper($key)), $default);
};

$vals = [];
$vals['db_host']    = $get('db-host', 'localhost');
$vals['db_name']    = $get('db-name', 'locksmith');
$vals['db_user']    = $get('db-user', 'root');
$vals['db_pass']    = $get('db-pass', '');
$vals['db_charset'] = $get('db-charset', 'utf8mb4');

$vals['app_env'] = $get('app-env', 'development');
if (!in_array($vals['app_env'], ['development', 'production'], true)) {
    fwrite(STDERR, "Invalid --app-env (must be development or production).\n");
    exit(1);
}

$vals['app_name'] = $get('app-name', 'LOCKSMITH');
$vals['mail_from'] = $get('mail-from', 'no-reply@localhost');
$ttl = $get('email-verify-ttl-hours', '24');
if (!ctype_digit((string)$ttl) || (int)$ttl < 1 || (int)$ttl > 168) {
    fwrite(STDERR, "Invalid --email-verify-ttl-hours (1-168).\n");
    exit(1);
}
$vals['email_verify_ttl_hours'] = (int)$ttl;

$vals['app_hmac_secret'] = bin2hex(random_bytes(32));

$initDb = (($args['init-db'] ?? '') === '1');
$applyMigrations = (($args['apply-migrations'] ?? '') === '1');

if (!$nonInteractive) {
    $initDb = $initDb || promptYesNo('Initialize database schema now?', true);
    $applyMigrations = $applyMigrations || promptYesNo('Apply migrations now? (safe to re-run)', true);
}

// ── Write config/database.php ───────────────────────────────
updateConfigFile($configPath, $vals, $force);

// ── Initialize DB ──────────────────────────────────────────
if ($initDb || $applyMigrations) {
    fwrite(STDOUT, "Connecting to MySQL...\n");

    $serverPdo = connectPdoServer($vals['db_host'], $vals['db_charset'], $vals['db_user'], $vals['db_pass']);

    // Create DB if possible. If privileges are missing, the next step will fail clearly.
    $dbName = $vals['db_name'];
    $quotedDb = '`' . str_replace('`', '``', $dbName) . '`';
    $serverPdo->exec("CREATE DATABASE IF NOT EXISTS {$quotedDb} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");

    $dbPdo = connectPdoDb($vals['db_host'], $vals['db_name'], $vals['db_charset'], $vals['db_user'], $vals['db_pass']);

    if ($initDb) {
        fwrite(STDOUT, "Applying schema (config/schema.sql)...\n");
        applySqlFile($dbPdo, $schemaPath, true);
        fwrite(STDOUT, "Schema applied.\n");
    }

    if ($applyMigrations) {
        if (is_dir($migrationsDir)) {
            ensureMigrationsTable($dbPdo);
            $files = array_values(array_filter(scandir($migrationsDir) ?: [], fn($f) => preg_match('/\\.sql$/i', $f)));
            sort($files, SORT_NATURAL);

            foreach ($files as $f) {
                if (migrationApplied($dbPdo, $f)) continue;
                $path = $migrationsDir . '/' . $f;
                fwrite(STDOUT, "Applying migration {$f}...\n");
                applySqlFile($dbPdo, $path, true);
                markMigrationApplied($dbPdo, $f);
            }

            fwrite(STDOUT, "Migrations applied.\n");
        } else {
            fwrite(STDOUT, "No migrations directory found; skipping.\n");
        }
    }
}

fwrite(STDOUT, "\nDone.\n\nNext steps:\n");
fwrite(STDOUT, "- Point your web server document root at this project folder.\n");
fwrite(STDOUT, "- Visit / (index.php) to access the app.\n");
fwrite(STDOUT, "- Ensure PHP mail() is configured if you want real verification emails.\n");
