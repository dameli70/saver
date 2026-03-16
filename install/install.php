<?php
// ============================================================
//  Controle — CLI Installer
//
//  Usage (interactive):
//    php install/install.php
//
//  Usage (non-interactive):
//    php install/install.php --non-interactive --init-db=1 --apply-migrations=1 --seed-demo=1 \
//      --db-host=localhost --db-name=locksmith --db-user=root --db-pass='' \
//      --app-env=development --app-name=Controle --app-logo-url='' --mail-from=no-reply@localhost \
//      --email-verify-ttl-hours=24 \
//      --smtp-host=smtp.example.com --smtp-port=587 --smtp-secure=tls \
//      --smtp-user=user --smtp-pass=pass --smtp-verify-peer=1 \
//      --admin-email=admin@example.com --admin-pass='change_me_please'
// ============================================================

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "This installer must be run from the command line.\n");
    exit(1);
}

requireExt('openssl');
requireExt('pdo_mysql');
requireExt('mbstring');

require_once __DIR__ . '/demo_seed.php';

$args = parseArgs($argv);
if (!empty($args['help'])) {
    usage();
    exit(0);
}

$root = realpath(__DIR__ . '/..');
if ($root === false) {
    fwrite(STDERR, "Could not resolve project root.\n");
    exit(1);
}

$configPath    = $root . '/config/database.php';
$schemaPath    = $root . '/config/schema.sql';
$migrationsDir = $root . '/config/migrations';

if (!file_exists($schemaPath)) {
    fwrite(STDERR, "Missing schema file: {$schemaPath}\n");
    exit(1);
}

$nonInteractive = !empty($args['non-interactive']);
$force          = (($args['force'] ?? '') === '1');

$get = function(string $key, ?string $default = null) use ($args, $nonInteractive): string {
    if (array_key_exists($key, $args)) return (string)$args[$key];
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

$vals['app_name'] = $get('app-name', 'Controle');
$vals['app_logo_url'] = $get('app-logo-url', '');
$vals['mail_from'] = $get('mail-from', 'no-reply@localhost');

$ttl = $get('email-verify-ttl-hours', '24');
if (!ctype_digit((string)$ttl) || (int)$ttl < 1 || (int)$ttl > 168) {
    fwrite(STDERR, "Invalid --email-verify-ttl-hours (1-168).\n");
    exit(1);
}
$vals['email_verify_ttl_hours'] = (int)$ttl;

$vals['smtp_host'] = $get('smtp-host', '');
$vals['smtp_port'] = 587;
$vals['smtp_user'] = '';
$vals['smtp_pass'] = '';
$vals['smtp_secure'] = 'tls';
$vals['smtp_verify_peer'] = 1;

if ($vals['smtp_host'] !== '') {
    $smtpPort = $get('smtp-port', '587');
    if (!ctype_digit((string)$smtpPort) || (int)$smtpPort < 1 || (int)$smtpPort > 65535) {
        fwrite(STDERR, "Invalid --smtp-port (1-65535).\n");
        exit(1);
    }
    $vals['smtp_port'] = (int)$smtpPort;

    $vals['smtp_user'] = $get('smtp-user', '');
    $vals['smtp_pass'] = $get('smtp-pass', '');

    $smtpSecure = strtolower(trim($get('smtp-secure', 'tls')));
    if ($smtpSecure === 'none') $smtpSecure = '';
    if (!in_array($smtpSecure, ['', 'tls', 'ssl'], true)) {
        fwrite(STDERR, "Invalid --smtp-secure (none|tls|ssl).\n");
        exit(1);
    }
    $vals['smtp_secure'] = $smtpSecure;

    $smtpVerify = $get('smtp-verify-peer', '1');
    if (!in_array((string)$smtpVerify, ['0', '1'], true)) {
        fwrite(STDERR, "Invalid --smtp-verify-peer (0|1).\n");
        exit(1);
    }
    $vals['smtp_verify_peer'] = (int)$smtpVerify;
}

$vals['app_hmac_secret'] = bin2hex(random_bytes(32));

$initDb = (($args['init-db'] ?? '') === '1');
$applyMigrations = (($args['apply-migrations'] ?? '') === '1');
$seedDemo = (($args['seed-demo'] ?? '') === '1');

if (!$nonInteractive) {
    $initDb = $initDb || promptYesNo('Initialize database schema now?', true);
    $applyMigrations = $applyMigrations || promptYesNo('Apply migrations now? (safe to re-run)', true);
    $seedDemo = $seedDemo || promptYesNo('Seed demo data (10 Togolese users/rooms)? (development only)', false);
}

if ($seedDemo && ($vals['app_env'] ?? 'development') !== 'development') {
    fwrite(STDERR, "Demo data seeding is only allowed in APP_ENV=development.\n");
    exit(1);
}

fwrite(STDOUT, "Validating MySQL credentials...\n");

try {
    // Validate credentials against the server (catches wrong user/pass).
    $serverPdo = connectPdoServer($vals['db_host'], $vals['db_charset'], $vals['db_user'], $vals['db_pass']);

    if ($initDb || $applyMigrations) {
        $dbName = $vals['db_name'];
        $quotedDb = '`' . str_replace('`', '``', $dbName) . '`';
        $serverPdo->exec("CREATE DATABASE IF NOT EXISTS {$quotedDb} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
    }

    $dbPdo = connectPdoDb($vals['db_host'], $vals['db_name'], $vals['db_charset'], $vals['db_user'], $vals['db_pass']);

    if ($initDb) {
        fwrite(STDOUT, "Applying schema (config/schema.sql)...\n");
        applySqlFile($dbPdo, $schemaPath, true);
        fwrite(STDOUT, "Schema applied.\n");
    }

    if ($applyMigrations && is_dir($migrationsDir)) {
        ensureMigrationsTable($dbPdo);

        $files = array_values(array_filter(scandir($migrationsDir) ?: [], fn($f) => preg_match('/\\.sql$/i', $f)));
        sort($files, SORT_NATURAL);

        foreach ($files as $f) {
            // Always attempt to apply migrations (idempotent with ignoreDuplicateErrors).
            // This avoids getting stuck if schema_migrations is out of sync.
            $path = $migrationsDir . '/' . $f;
            fwrite(STDOUT, "Applying migration {$f}...\n");
            applySqlFile($dbPdo, $path, true);
            markMigrationApplied($dbPdo, $f);
        }

        fwrite(STDOUT, "Migrations applied.\n");
    }

    $adminEmail = trim($get('admin-email', ''));
    $adminPass  = (string)$get('admin-pass', '');

    createInitialAdmin($dbPdo, $adminEmail, $adminPass);

    if ($seedDemo) {
        $adminEmailLower = strtolower(trim($adminEmail));
        $st = $dbPdo->prepare('SELECT id FROM users WHERE email = ? LIMIT 1');
        $st->execute([$adminEmailLower]);
        $adminUserId = (int)$st->fetchColumn();
        $st->closeCursor();
        if ($adminUserId <= 0) {
            throw new RuntimeException('Failed to resolve Super Admin user id.');
        }

        fwrite(STDOUT, "Seeding demo data (10 users + rooms)...\n");
        $demo = seedDemoData($dbPdo, $adminUserId, 'DemoPass123!');

        if (!empty($demo['seeded'])) {
            fwrite(STDOUT, "Demo users password: " . ($demo['demo_password'] ?? 'DemoPass123!') . "\n");
            if (!empty($demo['users']) && is_array($demo['users'])) {
                foreach ($demo['users'] as $u) {
                    $email = (string)($u['email'] ?? '');
                    $name = (string)($u['display'] ?? '');
                    if ($email !== '') {
                        fwrite(STDOUT, "  - {$name} <{$email}>\n");
                    }
                }
            }
        } else {
            fwrite(STDOUT, "Demo seed skipped: " . ($demo['reason'] ?? 'unknown') . "\n");
        }
    }

} catch (Throwable $e) {
    fwrite(STDERR, "\nERROR: " . $e->getMessage() . "\n");
    fwrite(STDERR, "Config was NOT written. Check DB_HOST/DB_USER/DB_PASS (and DB_NAME if not initializing).\n");
    exit(1);
}

fwrite(STDOUT, "Writing config/database.php...\n");
writeConfigFile($configPath, $vals, $force);

$flagPath = $root . '/config/installed.flag';
$flagBody = "installed_at=" . date('c') . "\n";
$flagBody .= "installed_by=cli\n";
file_put_contents($flagPath, $flagBody);

fwrite(STDOUT, "\nDone.\n");

// ───────────────────────────────────────────────────────────

function usage(): void {
    $msg = <<<TXT
Controle Installer

Run:
  php install/install.php

Non-interactive example:
  php install/install.php --non-interactive --init-db=1 --apply-migrations=1 --seed-demo=1 \
    --db-host=localhost --db-name=locksmith --db-user=root --db-pass='' \
    --app-env=development --app-name=Controle --app-logo-url='' --mail-from=no-reply@localhost \
    --email-verify-ttl-hours=24 \
    --smtp-host=smtp.example.com --smtp-port=587 --smtp-secure=tls \
    --smtp-user=user --smtp-pass=pass --smtp-verify-peer=1 \
    --admin-email=admin@example.com --admin-pass='change_me_please'

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
        if (!str_starts_with($arg, '--')) continue;

        $kv = substr($arg, 2);
        $eq = strpos($kv, '=');
        if ($eq === false) {
            $out[$kv] = true;
            continue;
        }
        $out[substr($kv, 0, $eq)] = substr($kv, $eq + 1);
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
    $in = strtolower(prompt($label . " ({$d})"));
    if ($in === '') return $default;
    return in_array($in, ['y', 'yes'], true);
}

function requireExt(string $ext): void {
    if (!extension_loaded($ext)) {
        fwrite(STDERR, "Missing required PHP extension: {$ext}\n");
        exit(1);
    }
}

function connectPdoServer(string $host, string $charset, string $user, string $pass): PDO {
    $dsn = "mysql:host={$host};charset={$charset}";
    $opts = [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ];
    if (extension_loaded('pdo_mysql')) {
        $opts[PDO::MYSQL_ATTR_USE_BUFFERED_QUERY] = true;
    }

    $pdo = new PDO($dsn, $user, $pass, $opts);
    if (extension_loaded('pdo_mysql')) {
        $pdo->setAttribute(PDO::MYSQL_ATTR_USE_BUFFERED_QUERY, true);
    }
    return $pdo;
}

function connectPdoDb(string $host, string $dbName, string $charset, string $user, string $pass): PDO {
    $dsn = "mysql:host={$host};dbname={$dbName};charset={$charset}";
    $opts = [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ];
    if (extension_loaded('pdo_mysql')) {
        $opts[PDO::MYSQL_ATTR_USE_BUFFERED_QUERY] = true;
    }

    $pdo = new PDO($dsn, $user, $pass, $opts);
    if (extension_loaded('pdo_mysql')) {
        $pdo->setAttribute(PDO::MYSQL_ATTR_USE_BUFFERED_QUERY, true);
    }
    return $pdo;
}

function splitSqlStatements(string $sql): array {
    $sql = preg_replace("/\r\n?/", "\n", $sql);
    $sql = preg_replace('/^\xEF\xBB\xBF/', '', $sql); // strip BOM

    // Remove /* */ comments.
    $sql = preg_replace('#/\*.*?\*/#s', '', $sql);

    $out = [];
    $buf = '';
    $inStr = false;
    $strCh = '';

    $len = strlen($sql);
    for ($i = 0; $i < $len; $i++) {
        $ch = $sql[$i];

        if ($inStr) {
            $buf .= $ch;
            if ($ch === $strCh) {
                $prev = $i > 0 ? $sql[$i - 1] : '';
                $next = ($i + 1) < $len ? $sql[$i + 1] : '';
                if ($strCh === "'" && $next === "'") {
                    $buf .= $next;
                    $i++;
                    continue;
                }
                if ($prev !== '\\') {
                    $inStr = false;
                    $strCh = '';
                }
            }
            continue;
        }

        if ($ch === '-' && ($i + 1) < $len && $sql[$i + 1] === '-') {
            while ($i < $len && $sql[$i] !== "\n") $i++;
            $buf .= "\n";
            continue;
        }
        if ($ch === '#') {
            while ($i < $len && $sql[$i] !== "\n") $i++;
            $buf .= "\n";
            continue;
        }

        if ($ch === "'" || $ch === '"') {
            $inStr = true;
            $strCh = $ch;
            $buf .= $ch;
            continue;
        }

        if ($ch === ';') {
            $stmt = trim($buf);
            if ($stmt !== '') $out[] = $stmt;
            $buf = '';
            continue;
        }

        $buf .= $ch;
    }

    $tail = trim($buf);
    if ($tail !== '') $out[] = $tail;

    return $out;
}

function stripLeadingSqlComments(string $sql): string {
    $s = ltrim($sql);
    while ($s !== '') {
        if (str_starts_with($s, '--')) {
            $pos = strpos($s, "\n");
            $s = $pos === false ? '' : ltrim(substr($s, $pos + 1));
            continue;
        }
        if (str_starts_with($s, '#')) {
            $pos = strpos($s, "\n");
            $s = $pos === false ? '' : ltrim(substr($s, $pos + 1));
            continue;
        }
        if (str_starts_with($s, '/*')) {
            $end = strpos($s, '*/');
            $s = $end === false ? '' : ltrim(substr($s, $end + 2));
            continue;
        }
        break;
    }
    return $s;
}

function applySqlFile(PDO $db, string $path, bool $ignoreDuplicateErrors): void {
    $sql = file_get_contents($path);
    if ($sql === false) throw new RuntimeException("Failed to read SQL file: {$path}");

    $stmts = splitSqlStatements($sql);
    foreach ($stmts as $stmt) {
        $trim = ltrim($stmt);
        if ($trim === '') continue;

        if (preg_match('/^CREATE\s+DATABASE/i', $trim)) continue;
        if (preg_match('/^USE\s+/i', $trim)) continue;

        try {
            $head = stripLeadingSqlComments($trim);
            // Some migrations include SELECT/SHOW fallbacks (e.g. "SELECT 1").
            // If a statement returns a result set, fully consume all rowsets.
            if (preg_match('/^(SELECT|SHOW|DESCRIBE|EXPLAIN|WITH|CALL|EXECUTE)\b/i', $head)) {
                $q = $db->query($stmt);
                if ($q) {
                    do {
                        $q->fetchAll();
                    } while ($q->nextRowset());
                    $q->closeCursor();
                }
            } else {
                $db->exec($stmt);
            }
        } catch (PDOException $e) {
            $code = (int)($e->errorInfo[1] ?? 0);
            if ($ignoreDuplicateErrors && in_array($code, [1050, 1060, 1061, 1062, 1068, 1091], true)) {
                continue;
            }
            $snippet = preg_replace('/\s+/', ' ', substr($head ?: $trim, 0, 220));
            throw new RuntimeException('SQL error in ' . basename($path) . ': ' . $e->getMessage() . ' | ' . $snippet, 0, $e);
        }
    }
}

function ensureMigrationsTable(PDO $db): void {
    $db->exec("CREATE TABLE IF NOT EXISTS schema_migrations (filename VARCHAR(255) PRIMARY KEY, applied_at DATETIME DEFAULT CURRENT_TIMESTAMP) ENGINE=InnoDB");
}

function migrationApplied(PDO $db, string $filename): bool {
    $st = $db->prepare('SELECT 1 FROM schema_migrations WHERE filename = ? LIMIT 1');
    $st->execute([$filename]);
    $v = (bool)$st->fetchColumn();
    $st->closeCursor();
    return $v;
}

function markMigrationApplied(PDO $db, string $filename): void {
    $db->prepare('INSERT IGNORE INTO schema_migrations (filename) VALUES (?)')->execute([$filename]);
}

function hashLoginPassword(string $password): string {
    return password_hash($password, PASSWORD_ARGON2ID, [
        'memory_cost' => 65536,
        'time_cost'   => 4,
        'threads'     => 2,
    ]);
}

function hashVaultVerifier(string $passphrase): string {
    return password_hash($passphrase, PASSWORD_ARGON2ID, [
        'memory_cost' => 65536,
        'time_cost'   => 4,
        'threads'     => 2,
    ]);
}

function createInitialAdmin(PDO $db, string $email, string $loginPwd): void {
    $st = $db->query('SELECT COUNT(*) FROM users');
    $users = (int)$st->fetchColumn();
    $st->closeCursor();
    if ($users !== 0) return;

    $email = strtolower(trim($email));
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        throw new RuntimeException('Admin email must be provided (valid email).');
    }
    if (strlen($loginPwd) < 8) {
        throw new RuntimeException('Admin password must be at least 8 characters.');
    }

    $vaultVerifierSalt = bin2hex(random_bytes(32));
    $vaultVerifier = hashVaultVerifier(bin2hex(random_bytes(32)) . $vaultVerifierSalt);

    $loginHash = hashLoginPassword($loginPwd);

    $db->prepare("INSERT INTO users (email, login_hash, vault_verifier, vault_verifier_salt, email_verified_at, is_admin)
                  VALUES (?, ?, ?, ?, NOW(), 1)")
       ->execute([$email, $loginHash, $vaultVerifier, $vaultVerifierSalt]);

    fwrite(STDOUT, "Created initial Super Admin: {$email}\n");
}

function renderConfigPhp(array $vals): string {
    $dbHost = addslashes($vals['db_host']);
    $dbName = addslashes($vals['db_name']);
    $dbUser = addslashes($vals['db_user']);
    $dbPass = addslashes($vals['db_pass']);
    $dbCharset = addslashes($vals['db_charset']);

    $appSecret = addslashes($vals['app_hmac_secret']);
    $appEnv = addslashes($vals['app_env']);
    $appName = addslashes($vals['app_name']);
    $appLogoUrl = addslashes($vals['app_logo_url'] ?? '');

    $mailFrom = addslashes($vals['mail_from']);
    $ttl = (int)$vals['email_verify_ttl_hours'];

    $smtpHost = addslashes($vals['smtp_host']);
    $smtpPort = (int)$vals['smtp_port'];
    $smtpUser = addslashes($vals['smtp_user']);
    $smtpPass = addslashes($vals['smtp_pass']);
    $smtpSecure = addslashes($vals['smtp_secure']);
    $smtpVerifyPeer = (int)$vals['smtp_verify_peer'];

    return "<?php\n"
        . "// ============================================================\n"
        . "//  Controle — Database Configuration\n"
        . "//  Generated by the installer.\n"
        . "// ============================================================\n\n"
        . "define('DB_HOST',    '" . $dbHost . "');\n"
        . "define('DB_NAME',    '" . $dbName . "');\n"
        . "define('DB_USER',    '" . $dbUser . "');\n"
        . "define('DB_PASS',    '" . $dbPass . "');\n"
        . "define('DB_CHARSET', '" . $dbCharset . "');\n\n"
        . "define('APP_HMAC_SECRET', '" . $appSecret . "');\n\n"
        . "define('APP_ENV', '" . $appEnv . "');\n\n"
        . "define('APP_NAME', '" . $appName . "');\n"
        . "define('APP_LOGO_URL', '" . $appLogoUrl . "');\n\n"
        . "define('APP_BASE_URL', '');\n\n"
        . "define('MAIL_FROM', '" . $mailFrom . "');\n"
        . "define('EMAIL_VERIFY_TTL_HOURS', " . $ttl . ");\n\n"
        . "define('SMTP_HOST', '" . $smtpHost . "');\n"
        . "define('SMTP_PORT', " . $smtpPort . ");\n"
        . "define('SMTP_USER', '" . $smtpUser . "');\n"
        . "define('SMTP_PASS', '" . $smtpPass . "');\n"
        . "define('SMTP_SECURE', '" . $smtpSecure . "');\n"
        . "define('SMTP_VERIFY_PEER', " . $smtpVerifyPeer . ");\n\n"
        . "define('PBKDF2_ITERATIONS', 310000);\n\n"
        . "date_default_timezone_set('UTC');\n\n"
        . "function isApiRequest(): bool {\n"
        . "    try {\n"
        . "        \\\$script = (string)(\\\$_SERVER['SCRIPT_NAME'] ?? '');\n"
        . "        \\\$uri    = (string)(\\\$_SERVER['REQUEST_URI'] ?? '');\n\n"
        . "        if (preg_match('#/api/#', \\\$script) || preg_match('#/api/#', \\\$uri)) return true;\n\n"
        . "        \\\$accept = strtolower((string)(\\\$_SERVER['HTTP_ACCEPT'] ?? ''));\n"
        . "        if (str_contains(\\\$accept, 'application/json') || str_contains(\\\$accept, '+json')) return true;\n\n"
        . "        \\\$ctype = strtolower((string)(\\\$_SERVER['CONTENT_TYPE'] ?? \\\$_SERVER['HTTP_CONTENT_TYPE'] ?? ''));\n"
        . "        if (str_contains(\\\$ctype, 'application/json')) return true;\n\n"
        . "        \\\$xrw = strtolower((string)(\\\$_SERVER['HTTP_X_REQUESTED_WITH'] ?? ''));\n"
        . "        if (\\\$xrw === 'xmlhttprequest') return true;\n\n"
        . "    } catch (Throwable) {\n"
        . "    }\n\n"
        . "    return false;\n"
        . "}\n\n"
        . "function dbUnavailableResponse(?string \\\$devDetail = null): void {\n"
        . "    \\\$isDev = defined('APP_ENV') && APP_ENV === 'development';\n"
        . "    \\\$msg = (\\\$isDev && \\\$devDetail) ? ('DB: ' . \\\$devDetail) : 'Database unavailable';\n\n"
        . "    if (PHP_SAPI === 'cli') {\n"
        . "        fwrite(STDERR, \\\$msg . \\\"\\n\\\");\n"
        . "        exit(1);\n"
        . "    }\n\n"
        . "    http_response_code(503);\n\n"
        . "    if (!headers_sent()) {\n"
        . "        header('Cache-Control: no-store, no-cache, must-revalidate');\n"
        . "        header('Pragma: no-cache');\n"
        . "    }\n\n"
        . "    if (isApiRequest()) {\n"
        . "        if (!headers_sent()) {\n"
        . "            header('Content-Type: application/json; charset=utf-8');\n"
        . "        }\n"
        . "        echo json_encode(['error' => \\\$msg], JSON_UNESCAPED_UNICODE);\n"
        . "        exit;\n"
        . "    }\n\n"
        . "    if (!headers_sent()) {\n"
        . "        header('Content-Type: text/html; charset=utf-8');\n"
        . "    }\n\n"
        . "    \\\$app = defined('APP_NAME') ? (string)APP_NAME : 'Application';\n"
        . "    \\\$safeApp = htmlspecialchars(\\\$app, ENT_QUOTES, 'UTF-8');\n"
        . "    \\\$safeMsg = htmlspecialchars(\\\$msg, ENT_QUOTES, 'UTF-8');\n\n"
        . "    echo \\\"<!doctype html>\\n\\\";\n"
        . "    echo \\\"<html lang=\\\"en\\\">\\n\\\";\n"
        . "    echo \\\"<head>\\n\\\";\n"
        . "    echo \\\"  <meta charset=\\\"utf-8\\\">\\n\\\";\n"
        . "    echo \\\"  <meta name=\\\"viewport\\\" content=\\\"width=device-width, initial-scale=1\\\">\\n\\\";\n"
        . "    echo \\\"  <title>{\\\$safeApp} — Service unavailable</title>\\n\\\";\n"
        . "    echo \\\"  <style>body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;margin:40px;color:#111}h1{margin:0 0 10px}p{margin:0 0 10px;color:#333}code{background:#f3f3f3;padding:2px 4px;border-radius:4px}</style>\\n\\\";\n"
        . "    echo \\\"</head>\\n\\\";\n"
        . "    echo \\\"<body>\\n\\\";\n"
        . "    echo \\\"  <h1>Service unavailable</h1>\\n\\\";\n"
        . "    echo \\\"  <p>{\\\$safeMsg}</p>\\n\\\";\n"
        . "    echo \\\"  <p>Please try again in a moment.</p>\\n\\\";\n"
        . "    echo \\\"</body>\\n\\\";\n"
        . "    echo \\\"</html>\\\";\n"
        . "    exit;\n"
        . "}\n\n"
        . "function getDB(): PDO {\n"
        . "    static \\\$pdo = null;\n"
        . "    if (\\\$pdo === null) {\n"
        . "        \\\$dsn = \\\"mysql:host=\\\".DB_HOST.\\\";dbname=\\\".DB_NAME.\\\";charset=\\\".DB_CHARSET;\n"
        . "        \\\$opts = [\n"
        . "            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,\n"
        . "            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,\n"
        . "            PDO::ATTR_EMULATE_PREPARES   => false,\n"
        . "        ];\n"
        . "        try {\n"
        . "            \\\$pdo = new PDO(\\\$dsn, DB_USER, DB_PASS, \\\$opts);\n"
        . "            try {\n"
        . "                \\\$pdo->exec(\\\"SET time_zone = '+00:00'\\\");\n"
        . "            } catch (Throwable) {\n"
        . "            }\n"
        . "        } catch (PDOException \\\$e) {\n"
        . "            dbUnavailableResponse(\\\$e->getMessage());\n"
        . "        }\n"
        . "    }\n"
        . "    return \\\$pdo;\n"
        . "}\n";
}

function writeConfigFile(string $path, array $vals, bool $force): void {
    if (file_exists($path) && !$force) {
        $ok = promptYesNo("Overwrite {$path}?", true);
        if (!$ok) {
            fwrite(STDOUT, "Aborted.\n");
            exit(0);
        }
    }

    if (file_exists($path)) {
        $backup = $path . '.bak.' . date('Ymd_His');
        @copy($path, $backup);
    }

    $src = renderConfigPhp($vals);
    if (file_put_contents($path, $src) === false) {
        throw new RuntimeException("Failed to write {$path}");
    }
}
