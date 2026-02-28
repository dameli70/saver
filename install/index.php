<?php
require_once __DIR__ . '/../includes/install_guard.php';

function startInstallerSession(): void {
    if (session_status() === PHP_SESSION_NONE) {
        ini_set('session.cookie_httponly', 1);
        ini_set('session.cookie_secure', (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 1 : 0);
        ini_set('session.cookie_samesite', 'Strict');
        ini_set('session.use_strict_mode', 1);
        session_start();
    }
}

function csrfToken(): string {
    startInstallerSession();
    if (empty($_SESSION['install_csrf'])) {
        $_SESSION['install_csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['install_csrf'];
}

function requireCsrf(): void {
    startInstallerSession();
    $t = $_POST['csrf'] ?? '';
    if (empty($_SESSION['install_csrf']) || !hash_equals($_SESSION['install_csrf'], $t)) {
        http_response_code(403);
        echo 'Invalid CSRF token.';
        exit;
    }
}

function phpSingleQuoted(string $value): string {
    return "'" . str_replace(["\\", "'"], ["\\\\", "\\'"], $value) . "'";
}

function updateConfigFile(string $path, array $vals): void {
    if (!file_exists($path)) {
        throw new RuntimeException("Missing config file: {$path}");
    }
    if (!is_writable($path)) {
        throw new RuntimeException("Config file is not writable: {$path}");
    }

    $backupPath = $path . '.bak.' . date('Ymd_His');
    if (!copy($path, $backupPath)) {
        throw new RuntimeException("Failed to create backup: {$backupPath}");
    }

    $src = file_get_contents($path);
    if ($src === false) {
        throw new RuntimeException("Failed to read: {$path}");
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

        'SMTP_HOST' => $vals['smtp_host'],
        'SMTP_PORT' => (string)$vals['smtp_port'],
        'SMTP_USER' => $vals['smtp_user'],
        'SMTP_PASS' => $vals['smtp_pass'],
        'SMTP_SECURE' => $vals['smtp_secure'],
        'SMTP_VERIFY_PEER' => (string)$vals['smtp_verify_peer'],
    ];

    foreach ($repls as $const => $val) {
        if (in_array($const, ['EMAIL_VERIFY_TTL_HOURS', 'SMTP_PORT', 'SMTP_VERIFY_PEER'], true)) {
            $pattern = "/define\\('" . preg_quote($const, '/') . "',\\s*[^)]+\\);/";
            $replace = "define('{$const}', " . (int)$val . ");";
        } else {
            $pattern = "/define\\('" . preg_quote($const, '/') . "',\\s*'(?:\\\\'|[^'])*'\\);/";
            $replace = "define('{$const}', " . phpSingleQuoted($val) . ");";
        }
        $src = preg_replace($pattern, $replace, $src, 1, $count);
        if ($count !== 1) {
            throw new RuntimeException("Could not update {$const} in {$path} (pattern mismatch). Backup: {$backupPath}");
        }
    }

    if (file_put_contents($path, $src) === false) {
        throw new RuntimeException("Failed to write: {$path} (backup: {$backupPath})");
    }
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

$basePath   = getAppBasePath();
$installUrl = getInstallUrlPath();

if (isAppInstalled()) {
    header('Location: ' . ($basePath ? $basePath : '') . '/');
    exit;
}

$errors = [];
$okMsg  = '';

$vals = [
    'db_host' => 'localhost',
    'db_name' => 'locksmith',
    'db_user' => 'root',
    'db_pass' => '',
    'db_charset' => 'utf8mb4',
    'app_env' => 'development',
    'app_name' => 'LOCKSMITH',
    'mail_from' => 'no-reply@localhost',
    'email_verify_ttl_hours' => 24,

    'smtp_host' => '',
    'smtp_port' => 587,
    'smtp_user' => '',
    'smtp_pass' => '',
    'smtp_secure' => 'tls',
    'smtp_verify_peer' => 1,

    'init_db' => 1,
    'apply_migrations' => 1,
];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    requireCsrf();

    $vals['db_host'] = trim((string)($_POST['db_host'] ?? ''));
    $vals['db_name'] = trim((string)($_POST['db_name'] ?? ''));
    $vals['db_user'] = trim((string)($_POST['db_user'] ?? ''));
    $vals['db_pass'] = (string)($_POST['db_pass'] ?? '');
    $vals['db_charset'] = trim((string)($_POST['db_charset'] ?? 'utf8mb4'));

    $vals['app_env'] = trim((string)($_POST['app_env'] ?? 'development'));
    $vals['app_name'] = trim((string)($_POST['app_name'] ?? 'LOCKSMITH'));
    $vals['mail_from'] = trim((string)($_POST['mail_from'] ?? 'no-reply@localhost'));
    $vals['email_verify_ttl_hours'] = (int)($_POST['email_verify_ttl_hours'] ?? 24);

    $vals['smtp_host'] = trim((string)($_POST['smtp_host'] ?? ''));
    $vals['smtp_port'] = (int)($_POST['smtp_port'] ?? 587);
    $vals['smtp_user'] = trim((string)($_POST['smtp_user'] ?? ''));
    $vals['smtp_pass'] = (string)($_POST['smtp_pass'] ?? '');
    $vals['smtp_secure'] = trim((string)($_POST['smtp_secure'] ?? 'tls'));
    $vals['smtp_verify_peer'] = !empty($_POST['smtp_verify_peer']) ? 1 : 0;

    $vals['init_db'] = !empty($_POST['init_db']) ? 1 : 0;
    $vals['apply_migrations'] = !empty($_POST['apply_migrations']) ? 1 : 0;

    if ($vals['db_host'] === '') $errors[] = 'Database host is required.';
    if ($vals['db_name'] === '') $errors[] = 'Database name is required.';
    if ($vals['db_user'] === '') $errors[] = 'Database user is required.';
    if (!in_array($vals['app_env'], ['development', 'production'], true)) $errors[] = 'Invalid APP_ENV.';
    if ($vals['app_name'] === '') $errors[] = 'APP_NAME is required.';
    if (!filter_var($vals['mail_from'], FILTER_VALIDATE_EMAIL)) $errors[] = 'MAIL_FROM must be a valid email.';
    if ($vals['email_verify_ttl_hours'] < 1 || $vals['email_verify_ttl_hours'] > 168) $errors[] = 'Email verification TTL must be 1–168 hours.';

    if ($vals['smtp_host'] !== '') {
        if ($vals['smtp_port'] < 1 || $vals['smtp_port'] > 65535) $errors[] = 'SMTP_PORT must be 1–65535.';
        if (!in_array($vals['smtp_secure'], ['', 'tls', 'ssl'], true)) $errors[] = 'SMTP_SECURE must be empty, tls, or ssl.';
        if (!in_array((int)$vals['smtp_verify_peer'], [0, 1], true)) $errors[] = 'SMTP_VERIFY_PEER must be 0 or 1.';
    }

    $root = realpath(__DIR__ . '/..');
    $configPath = $root . '/config/database.php';
    $schemaPath = $root . '/config/schema.sql';
    $migrationsDir = $root . '/config/migrations';
    $flagPath = $root . '/config/installed.flag';

    if ($root === false) $errors[] = 'Could not resolve app root.';
    if (!file_exists($configPath)) $errors[] = 'Missing config/database.php';
    if (!file_exists($schemaPath)) $errors[] = 'Missing config/schema.sql';

    if (!extension_loaded('pdo_mysql')) $errors[] = 'Missing PHP extension: pdo_mysql';
    if (!extension_loaded('openssl')) $errors[] = 'Missing PHP extension: openssl';

    if (empty($errors)) {
        try {
            $vals['app_hmac_secret'] = bin2hex(random_bytes(32));

            updateConfigFile($configPath, $vals);

            if ($vals['init_db'] || $vals['apply_migrations']) {
                $serverPdo = connectPdoServer($vals['db_host'], $vals['db_charset'], $vals['db_user'], $vals['db_pass']);
                $dbName = $vals['db_name'];
                $quotedDb = '`' . str_replace('`', '``', $dbName) . '`';
                $serverPdo->exec("CREATE DATABASE IF NOT EXISTS {$quotedDb} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");

                $dbPdo = connectPdoDb($vals['db_host'], $vals['db_name'], $vals['db_charset'], $vals['db_user'], $vals['db_pass']);

                if ($vals['init_db']) {
                    applySqlFile($dbPdo, $schemaPath, true);
                }

                if ($vals['apply_migrations'] && is_dir($migrationsDir)) {
                    ensureMigrationsTable($dbPdo);
                    $files = array_values(array_filter(scandir($migrationsDir) ?: [], fn($f) => preg_match('/\\.sql$/i', $f)));
                    sort($files, SORT_NATURAL);
                    foreach ($files as $f) {
                        if (migrationApplied($dbPdo, $f)) continue;
                        applySqlFile($dbPdo, $migrationsDir . '/' . $f, true);
                        markMigrationApplied($dbPdo, $f);
                    }
                }
            }

            $flagBody = "installed_at=" . date('c') . "\n";
            $flagBody .= "app_base_path=" . ($basePath ? $basePath : '/') . "\n";
            if (file_put_contents($flagPath, $flagBody) === false) {
                throw new RuntimeException('Failed to write config/installed.flag (make config/ writable).');
            }

            header('Location: ' . ($basePath ? $basePath : '') . '/');
            exit;

        } catch (Throwable $e) {
            $errors[] = $e->getMessage();
        }
    }
}

$csrf = csrfToken();

header("Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; font-src https://fonts.gstatic.com; frame-ancestors 'none';");
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: no-referrer");

?><!doctype html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Install — LOCKSMITH</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@300;400;500&family=Unbounded:wght@400;700;900&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#06070a;--s1:#0d0f14;--s2:#13161d;--s3:#1a1d27;
  --b1:rgba(255,255,255,.07);--b2:rgba(255,255,255,.13);
  --accent:#e8ff47;--red:#ff4757;--green:#47ffb0;--orange:#ffaa00;
  --text:#dde1ec;--muted:#525970;
  --mono:'DM Mono',monospace;--display:'Unbounded',sans-serif;
  --sat:env(safe-area-inset-top,0px);--sab:env(safe-area-inset-bottom,0px);
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:var(--mono);min-height:100vh;}
.orb{position:fixed;border-radius:50%;filter:blur(120px);pointer-events:none;z-index:0;}
.orb1{width:520px;height:520px;background:rgba(232,255,71,.035);top:-170px;right:-120px;}
.orb2{width:360px;height:360px;background:rgba(71,184,255,.03);bottom:40px;left:-90px;}
.wrap{position:relative;z-index:1;max-width:980px;margin:0 auto;padding:max(24px,var(--sat)) 18px 60px;}
.logo{font-family:var(--display);font-weight:900;letter-spacing:-1px;font-size:28px;margin-bottom:4px;}
.logo span{color:var(--accent);} 
.sub{color:var(--muted);font-size:11px;letter-spacing:2px;text-transform:uppercase;margin-bottom:18px;}
.card{background:rgba(13,15,20,.9);border:1px solid var(--b1);padding:18px;}
.grid{display:grid;grid-template-columns:1fr;gap:12px;}
@media(min-width:840px){.grid{grid-template-columns:1fr 1fr;}}
.field{margin-bottom:12px;}
.field label{display:block;font-size:10px;letter-spacing:2px;text-transform:uppercase;color:var(--muted);margin-bottom:6px;}
.field input,.field select{width:100%;background:var(--s2);border:1px solid var(--b1);color:var(--text);
  font-family:var(--mono);font-size:14px;padding:12px;outline:none;border-radius:0;-webkit-appearance:none;}
.field input:focus,.field select:focus{border-color:var(--accent);} 
.note{color:var(--muted);font-size:12px;line-height:1.6;margin-top:10px;}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;
  padding:14px 18px;font-family:var(--mono);font-size:11px;letter-spacing:2px;
  text-transform:uppercase;cursor:pointer;border:none;transition:all .15s;border-radius:0;
  -webkit-appearance:none;min-height:44px;text-decoration:none;}
.btn-primary{background:var(--accent);color:#000;font-weight:600;}
.btn-primary:hover{background:#f0ff60;}
.msg{padding:12px 14px;font-size:12px;margin-bottom:12px;letter-spacing:.4px;line-height:1.6;}
.msg-err{background:rgba(255,71,87,.08);border:1px solid rgba(255,71,87,.2);color:var(--red);} 
.msg-ok{background:rgba(71,255,176,.08);border:1px solid rgba(71,255,176,.2);color:var(--green);} 
.chk{display:flex;align-items:center;gap:10px;color:var(--muted);font-size:12px;line-height:1.4;}
.chk input{width:16px;height:16px;}
hr{border:none;border-top:1px solid var(--b1);margin:16px 0;}
</style>
</head>
<body>
<div class="orb orb1"></div><div class="orb orb2"></div>
<div class="wrap">
  <div class="logo">LOCK<span>SMITH</span></div>
  <div class="sub">// Installation</div>

  <?php if ($errors): ?>
    <div class="msg msg-err">
      <strong>Install failed.</strong><br>
      <?php foreach ($errors as $e): ?>
        • <?= htmlspecialchars($e) ?><br>
      <?php endforeach; ?>
    </div>
  <?php endif; ?>

  <?php if ($okMsg): ?>
    <div class="msg msg-ok"><?= htmlspecialchars($okMsg) ?></div>
  <?php endif; ?>

  <form method="post" action="<?= htmlspecialchars($installUrl) ?>">
    <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">

    <div class="card">
      <div class="grid">
        <div>
          <h3 style="font-family:var(--display);font-size:12px;letter-spacing:2px;text-transform:uppercase;color:var(--accent);margin-bottom:12px;">Database</h3>

          <div class="field"><label>DB Host</label><input name="db_host" value="<?= htmlspecialchars($vals['db_host']) ?>" required></div>
          <div class="field"><label>DB Name</label><input name="db_name" value="<?= htmlspecialchars($vals['db_name']) ?>" required></div>
          <div class="field"><label>DB User</label><input name="db_user" value="<?= htmlspecialchars($vals['db_user']) ?>" required></div>
          <div class="field"><label>DB Password</label><input type="password" name="db_pass" value=""></div>
          <div class="field"><label>DB Charset</label><input name="db_charset" value="<?= htmlspecialchars($vals['db_charset']) ?>"></div>

          <hr>

          <div class="chk"><input type="checkbox" name="init_db" value="1" <?= $vals['init_db'] ? 'checked' : '' ?>> <span>Initialize database schema (config/schema.sql)</span></div>
          <div style="height:10px"></div>
          <div class="chk"><input type="checkbox" name="apply_migrations" value="1" <?= $vals['apply_migrations'] ? 'checked' : '' ?>> <span>Apply migrations (config/migrations/*.sql)</span></div>
        </div>

        <div>
          <h3 style="font-family:var(--display);font-size:12px;letter-spacing:2px;text-transform:uppercase;color:var(--accent);margin-bottom:12px;">App</h3>

          <div class="field">
            <label>APP_ENV</label>
            <select name="app_env">
              <option value="development" <?= $vals['app_env']==='development'?'selected':'' ?>>development</option>
              <option value="production" <?= $vals['app_env']==='production'?'selected':'' ?>>production</option>
            </select>
          </div>

          <div class="field"><label>APP_NAME</label><input name="app_name" value="<?= htmlspecialchars($vals['app_name']) ?>" required></div>
          <div class="field"><label>MAIL_FROM</label><input name="mail_from" value="<?= htmlspecialchars($vals['mail_from']) ?>" required></div>
          <div class="field"><label>Email verification TTL (hours)</label><input name="email_verify_ttl_hours" type="number" min="1" max="168" value="<?= (int)$vals['email_verify_ttl_hours'] ?>" required></div>

          <hr>
          <h3 style="font-family:var(--display);font-size:12px;letter-spacing:2px;text-transform:uppercase;color:var(--accent);margin-bottom:12px;">Mail (SMTP optional)</h3>

          <div class="field"><label>SMTP Host (optional)</label><input name="smtp_host" value="<?= htmlspecialchars($vals['smtp_host']) ?>" placeholder="smtp.example.com"></div>
          <div class="field"><label>SMTP Port</label><input name="smtp_port" type="number" min="1" max="65535" value="<?= (int)$vals['smtp_port'] ?>"></div>

          <div class="field">
            <label>SMTP Secure</label>
            <select name="smtp_secure">
              <option value="" <?= $vals['smtp_secure']===''?'selected':'' ?>>none</option>
              <option value="tls" <?= $vals['smtp_secure']==='tls'?'selected':'' ?>>tls (STARTTLS)</option>
              <option value="ssl" <?= $vals['smtp_secure']==='ssl'?'selected':'' ?>>ssl</option>
            </select>
          </div>

          <div class="field"><label>SMTP User</label><input name="smtp_user" value="<?= htmlspecialchars($vals['smtp_user']) ?>"></div>
          <div class="field"><label>SMTP Password</label><input type="password" name="smtp_pass" value=""></div>

          <div class="chk"><input type="checkbox" name="smtp_verify_peer" value="1" <?= $vals['smtp_verify_peer'] ? 'checked' : '' ?>> <span>Verify TLS certificate</span></div>

          <div class="note">
            This installer will write <code>config/database.php</code> and generate a fresh <code>APP_HMAC_SECRET</code>.
            After installing, the app will bypass this page.
          </div>

          <div style="height:14px"></div>
          <button class="btn btn-primary" type="submit">Install</button>

          <div class="note" style="margin-top:14px;">
            If installation fails with “not writable”, ensure the web server user can write to <code>config/</code>.
            In production, you should protect or remove the <code>/install</code> directory after installation.
          </div>
        </div>
      </div>
    </div>
  </form>
</div>
</body>
</html>
