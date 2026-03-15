<?php
// ============================================================
// Packages / Plans
//
// A "package" grants feature limits to a user:
// - max_active_locks (codes)
// - max_active_rooms
// - max_active_wallet_locks (mobile money locks)
// - fast_support
//
// Default (no package assigned): 1 active lock + 1 active room + 1 active wallet lock.
// ============================================================

require_once __DIR__ . '/helpers.php';

const DEFAULT_PACKAGE_LIMITS = [
    'package_id' => null,
    'package_slug' => 'free',
    'package_name' => 'Free',
    'max_active_locks' => 1,
    'max_active_rooms' => 1,
    'max_active_wallet_locks' => 1,
    'fast_support' => 0,
];

function hasPackagesTables(): bool {
    static $cached = null;
    if ($cached !== null) return $cached;

    try {
        $db = getDB();
        $stmt = $db->query("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name IN ('packages','user_packages','package_purchases')");
        $cached = ((int)$stmt->fetchColumn() === 3);
        return $cached;
    } catch (Throwable) {
        $cached = false;
        return false;
    }
}

function packagesSeedDefaults(PDO $db): void {
    // Idempotent seed of the two default plans.
    if (!hasPackagesTables()) return;

    try {
        $db->exec("INSERT IGNORE INTO packages (slug, name, max_active_locks, max_active_rooms, max_active_wallet_locks, fast_support, is_active, sort_order)
                  VALUES
                    ('controle_plus', 'Controle+', 10, 3, 3, 1, 1, 10),
                    ('control_max',  'Control Max', 100, 20, 20, 1, 1, 20)");
    } catch (Throwable) {
        // best-effort
    }
}

function packagesGetAll(PDO $db, bool $onlyActive = true): array {
    if (!hasPackagesTables()) return [];

    packagesSeedDefaults($db);

    if ($onlyActive) {
        return $db->query('SELECT id, slug, name, max_active_locks, max_active_rooms, max_active_wallet_locks, fast_support, is_active, updated_at FROM packages WHERE is_active = 1 ORDER BY sort_order ASC, id ASC')->fetchAll();
    }

    return $db->query('SELECT id, slug, name, max_active_locks, max_active_rooms, max_active_wallet_locks, fast_support, is_active, updated_at FROM packages ORDER BY sort_order ASC, id ASC')->fetchAll();
}

function packagesGetUserPackageRow(PDO $db, int $userId): ?array {
    if (!hasPackagesTables()) return null;

    $stmt = $db->prepare('SELECT p.id, p.slug, p.name, p.max_active_locks, p.max_active_rooms, p.max_active_wallet_locks, p.fast_support
                          FROM user_packages up
                          JOIN packages p ON p.id = up.package_id
                          WHERE up.user_id = ? AND up.is_active = 1
                          LIMIT 1');
    $stmt->execute([(int)$userId]);
    $row = $stmt->fetch();
    return $row ?: null;
}

function packagesGetUserLimits(int $userId): array {
    if ($userId < 1) return DEFAULT_PACKAGE_LIMITS;

    $db = getDB();

    $row = packagesGetUserPackageRow($db, $userId);
    if (!$row) return DEFAULT_PACKAGE_LIMITS;

    return [
        'package_id' => (int)$row['id'],
        'package_slug' => (string)$row['slug'],
        'package_name' => (string)$row['name'],
        'max_active_locks' => (int)$row['max_active_locks'],
        'max_active_rooms' => (int)$row['max_active_rooms'],
        'max_active_wallet_locks' => (int)$row['max_active_wallet_locks'],
        'fast_support' => !empty($row['fast_support']) ? 1 : 0,
    ];
}

function packagesTableExists(PDO $db, string $table): bool {
    static $cache = [];
    if (array_key_exists($table, $cache)) return (bool)$cache[$table];

    try {
        $stmt = $db->prepare("SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ? LIMIT 1");
        $stmt->execute([$table]);
        $cache[$table] = (bool)$stmt->fetchColumn();
        return (bool)$cache[$table];
    } catch (Throwable) {
        $cache[$table] = false;
        return false;
    }
}

function packagesGetUserUsage(int $userId): array {
    $db = getDB();

    // Active codes: resets once revealed_at is set OR lock rejected.
    $st = $db->prepare("SELECT COUNT(*) FROM locks WHERE user_id = ? AND is_active = 1 AND revealed_at IS NULL AND confirmation_status <> 'rejected'");
    $st->execute([(int)$userId]);
    $locks = (int)$st->fetchColumn();

    // Active rooms: resets once user is no longer attached (status not in pending/approved/active).
    $rooms = 0;
    if (packagesTableExists($db, 'saving_room_participants')) {
        $st = $db->prepare("SELECT COUNT(*) FROM saving_room_participants WHERE user_id = ? AND status IN ('pending','approved','active')");
        $st->execute([(int)$userId]);
        $rooms = (int)$st->fetchColumn();
    }

    // Active wallet locks: resets once revealed_at is set OR setup failed.
    $wallet = 0;
    if (packagesTableExists($db, 'wallet_locks')) {
        $st = $db->prepare("SELECT COUNT(*) FROM wallet_locks WHERE user_id = ? AND is_active = 1 AND revealed_at IS NULL AND setup_status <> 'failed'");
        $st->execute([(int)$userId]);
        $wallet = (int)$st->fetchColumn();
    }

    return [
        'active_locks' => $locks,
        'active_rooms' => $rooms,
        'active_wallet_locks' => $wallet,
    ];
}

function packagesGetUserInfo(int $userId): array {
    $db = getDB();

    $limits = packagesGetUserLimits($userId);
    $usage = packagesGetUserUsage($userId);
    $available = packagesGetAll($db, true);

    return [
        'limits' => $limits,
        'usage' => $usage,
        'available_packages' => $available,
    ];
}

function packagesLimitFor(string $resource, array $limits): int {
    if ($resource === 'locks') return (int)($limits['max_active_locks'] ?? 0);
    if ($resource === 'rooms') return (int)($limits['max_active_rooms'] ?? 0);
    if ($resource === 'wallet_locks') return (int)($limits['max_active_wallet_locks'] ?? 0);
    return 0;
}

function packagesUsageFor(string $resource, array $usage): int {
    if ($resource === 'locks') return (int)($usage['active_locks'] ?? 0);
    if ($resource === 'rooms') return (int)($usage['active_rooms'] ?? 0);
    if ($resource === 'wallet_locks') return (int)($usage['active_wallet_locks'] ?? 0);
    return 0;
}

function packagesEnforceLimitOrJson(int $userId, string $resource): void {
    // Even if packages tables are missing (older installs), we still enforce defaults.
    $limits = packagesGetUserLimits($userId);
    $usage = packagesGetUserUsage($userId);

    $limit = packagesLimitFor($resource, $limits);
    $cur = packagesUsageFor($resource, $usage);

    if ($limit > 0 && $cur >= $limit) {
        jsonResponse([
            'error' => 'Package limit reached',
            'error_code' => 'package_limit',
            'redirect_url' => 'packages.php',
            'resource' => $resource,
            'current_usage' => $cur,
            'limit' => $limit,
            'usage' => $usage,
            'package' => $limits,
        ], 403);
    }
}
