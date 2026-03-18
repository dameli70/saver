<?php
// ============================================================
//  Controle — Demo data seeder (installer only)
//
//  Creates 10 Togolese demo users + sample rooms/levels/etc.
//  Intended for development/testing installs.
// ============================================================

function demoSeedHasTable(PDO $db, string $table): bool {
    $stmt = $db->prepare("SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ? LIMIT 1");
    $stmt->execute([$table]);
    $v = (bool)$stmt->fetchColumn();
    $stmt->closeCursor();
    return $v;
}

function demoSeedHasColumn(PDO $db, string $table, string $column): bool {
    $stmt = $db->prepare("SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ? LIMIT 1");
    $stmt->execute([$table, $column]);
    $v = (bool)$stmt->fetchColumn();
    $stmt->closeCursor();
    return $v;
}

function demoSeedGenerateUuid(): string {
    $b = random_bytes(16);
    $b[6] = chr((ord($b[6]) & 0x0f) | 0x40);
    $b[8] = chr((ord($b[8]) & 0x3f) | 0x80);
    return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($b), 4));
}

function demoSeedHashLoginPassword(string $password): string {
    return password_hash($password, PASSWORD_ARGON2ID, [
        'memory_cost' => 65536,
        'time_cost'   => 4,
        'threads'     => 2,
    ]);
}

function demoSeedHashVaultVerifier(string $passphrase): string {
    return password_hash($passphrase, PASSWORD_ARGON2ID, [
        'memory_cost' => 65536,
        'time_cost'   => 4,
        'threads'     => 2,
    ]);
}

function demoSeedEncryptForDb(string $plaintext): string {
    // Matches includes/helpers.php encryptForDb() format so seeded unlock codes are usable.
    //
    // IMPORTANT: The web installer may have already loaded config/database.php (placeholder secret)
    // via includes/install_guard.php -> isAppInstalled(). Since PHP constants can't be redefined,
    // allow the installer to provide the real secret via a global override.
    $secret = (string)($GLOBALS['DEMO_SEED_APP_HMAC_SECRET']
        ?? (defined('APP_HMAC_SECRET') ? (string)APP_HMAC_SECRET : 'demo_seed_fallback_secret'));

    $key = hash('sha256', $secret, true);

    $iv = random_bytes(12);
    $tag = '';
    $cipher = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
    if ($cipher === false) {
        throw new RuntimeException('Encryption failed');
    }

    return base64_encode($iv) . '.' . base64_encode($tag) . '.' . base64_encode($cipher);
}

function demoSeedNow(string $modify = 'now'): string {
    $dt = new DateTime('now', new DateTimeZone('UTC'));
    if ($modify !== 'now') {
        $dt->modify($modify);
    }
    return $dt->format('Y-m-d H:i:s');
}

function seedDemoData(PDO $db, int $adminUserId, string $demoPassword = 'DemoPass123!'): array {
    if (extension_loaded('pdo_mysql')) {
        $db->setAttribute(PDO::MYSQL_ATTR_USE_BUFFERED_QUERY, true);
    }

    $fetchColumn = static function (PDOStatement $stmt) {
        $v = $stmt->fetchColumn();
        $stmt->closeCursor();
        return $v;
    };

    // Don't seed if there are already users beyond the admin created by the installer.
    // (Defensive: in case schema wasn't applied yet.)
    if (!demoSeedHasTable($db, 'users')) {
        return [
            'seeded' => 0,
            'skipped' => 1,
            'reason' => 'Missing users table',
            'demo_password' => $demoPassword,
            'users' => [],
            'rooms' => [],
            'invites' => [],
        ];
    }

    $st = $db->query('SELECT COUNT(*) FROM users');
    $existing = (int)$fetchColumn($st);
    if ($existing > 1) {
        return [
            'seeded' => 0,
            'skipped' => 1,
            'reason' => 'Users already exist',
            'demo_password' => $demoPassword,
            'users' => [],
            'rooms' => [],
            'invites' => [],
        ];
    }

    $has = function(string $table, ?string $col = null) use ($db): bool {
        if ($col === null) return demoSeedHasTable($db, $table);
        return demoSeedHasTable($db, $table) && demoSeedHasColumn($db, $table, $col);
    };

    $out = [
        'seeded' => 0,
        'skipped' => 0,
        'demo_password' => $demoPassword,
        'users' => [],
        'rooms' => [],
        'invites' => [],
    ];

    $pkgId = [];
    if ($has('packages')) {
        $rows = $db->query("SELECT id, slug FROM packages WHERE is_active = 1")->fetchAll();
        foreach ($rows as $r) {
            $pkgId[(string)$r['slug']] = (int)$r['id'];
        }
    }

    $users = [
        [
            'display' => 'Kossi Mensah',
            'email' => 'kossi.mensah@example.com',
            'trust_level' => 3,
            'package_slug' => 'control_max',
            'kyc_status' => 'approved',
            'onboarding_complete' => 1,
            'require_webauthn' => 0,
            'vault_active_slot' => 1,
        ],
        [
            'display' => 'Akossiwa Dossa',
            'email' => 'akossiwa.dossa@example.com',
            'trust_level' => 2,
            'package_slug' => 'controle_plus',
            'kyc_status' => 'submitted',
            'onboarding_complete' => 1,
            'require_webauthn' => 0,
            'vault_active_slot' => 1,
        ],
        [
            'display' => 'Kodjo Amegashie',
            'email' => 'kodjo.amegashie@example.com',
            'trust_level' => 1,
            'package_slug' => null,
            'kyc_status' => 'draft',
            'onboarding_complete' => 0,
            'require_webauthn' => 0,
            'vault_active_slot' => 1,
        ],
        [
            'display' => 'Sena Adjorlolo',
            'email' => 'sena.adjorlolo@example.com',
            'trust_level' => 1,
            'package_slug' => null,
            'kyc_status' => 'draft',
            'onboarding_complete' => 0,
            'require_webauthn' => 0,
            'vault_active_slot' => 1,
        ],
        [
            'display' => 'Komla Afi',
            'email' => 'komla.afi@example.com',
            'trust_level' => 2,
            'package_slug' => 'controle_plus',
            'kyc_status' => 'submitted',
            'onboarding_complete' => 1,
            'require_webauthn' => 1,
            'vault_active_slot' => 1,
        ],
        [
            'display' => 'Mawuli Kponton',
            'email' => 'mawuli.kponton@example.com',
            'trust_level' => 3,
            'package_slug' => 'control_max',
            'kyc_status' => 'approved',
            'onboarding_complete' => 1,
            'restricted' => 1,
            'require_webauthn' => 0,
            'vault_active_slot' => 1,
        ],
        [
            'display' => 'Yaovi Tchalla',
            'email' => 'yaovi.tchalla@example.com',
            'trust_level' => 2,
            'package_slug' => null,
            'kyc_status' => 'rejected',
            'onboarding_complete' => 1,
            'require_webauthn' => 0,
            'vault_active_slot' => 1,
        ],
        [
            'display' => 'Efui Koffi',
            'email' => 'efui.koffi@example.com',
            'trust_level' => 1,
            'package_slug' => null,
            'kyc_status' => 'draft',
            'onboarding_complete' => 0,
            'require_webauthn' => 0,
            'vault_active_slot' => 1,
        ],
        [
            'display' => 'Sessi Atakpama',
            'email' => 'sessi.atakpama@example.com',
            'trust_level' => 2,
            'package_slug' => 'controle_plus',
            'kyc_status' => 'draft',
            'onboarding_complete' => 1,
            'require_webauthn' => 0,
            'vault_active_slot' => 1,
        ],
        [
            'display' => 'Dela Tété',
            'email' => 'dela.tete@example.com',
            'trust_level' => 3,
            'package_slug' => null,
            'kyc_status' => 'approved',
            'onboarding_complete' => 1,
            'vault_rotate' => 1,
            'require_webauthn' => 0,
            'vault_active_slot' => 2,
        ],
    ];

    $userCols = ['email', 'login_hash', 'vault_verifier', 'vault_verifier_salt', 'is_admin'];
    if ($has('users', 'email_verified_at')) $userCols[] = 'email_verified_at';
    if ($has('users', 'room_display_name')) $userCols[] = 'room_display_name';
    if ($has('users', 'profile_image_url')) $userCols[] = 'profile_image_url';
    if ($has('users', 'require_webauthn')) $userCols[] = 'require_webauthn';
    if ($has('users', 'vault_active_slot')) $userCols[] = 'vault_active_slot';

    $hasVaultAlt = $has('users', 'vault_verifier_alt') && $has('users', 'vault_verifier_alt_salt');
    if ($hasVaultAlt) {
        $userCols[] = 'vault_verifier_alt';
        $userCols[] = 'vault_verifier_alt_salt';
        if ($has('users', 'vault_verifier_alt_set_at')) $userCols[] = 'vault_verifier_alt_set_at';
    }

    if ($has('users', 'onboarding_completed_at')) $userCols[] = 'onboarding_completed_at';

    $addrCols = ['address_line1','address_line2','address_city','address_region','address_postal_code','address_country'];
    foreach ($addrCols as $c) {
        if ($has('users', $c)) $userCols[] = $c;
    }

    $userSql = 'INSERT INTO users (' . implode(', ', $userCols) . ') VALUES (' . implode(', ', array_fill(0, count($userCols), '?')) . ')';
    $insUser = $db->prepare($userSql);

    $insTrust = null;
    $trustCols = [];
    $trustValsFor = null;
    if ($has('user_trust')) {
        $trustRequired = ['user_id', 'trust_level'];
        $trustOk = true;
        foreach ($trustRequired as $c) {
            if (!$has('user_trust', $c)) { $trustOk = false; break; }
        }

        if ($trustOk) {
            $trustCols = $trustRequired;
            if ($has('user_trust', 'completed_reveals_count')) $trustCols[] = 'completed_reveals_count';
            if ($has('user_trust', 'last_level_change_at')) $trustCols[] = 'last_level_change_at';

            $trustSql = 'INSERT IGNORE INTO user_trust (' . implode(', ', $trustCols) . ') VALUES (' . implode(', ', array_fill(0, count($trustCols), '?')) . ')';
            $insTrust = $db->prepare($trustSql);

            $trustValsFor = function(int $userId, int $trustLevel, int $completedRevealsCount) use ($trustCols): array {
                $vals = [];
                foreach ($trustCols as $c) {
                    if ($c === 'user_id') $vals[] = $userId;
                    else if ($c === 'trust_level') $vals[] = $trustLevel;
                    else if ($c === 'completed_reveals_count') $vals[] = $completedRevealsCount;
                    else if ($c === 'last_level_change_at') $vals[] = demoSeedNow('now');
                    else $vals[] = null;
                }
                return $vals;
            };
        }
    }

    $insPrefs = null;
    $prefCols = [];
    $prefValsFor = null;
    if ($has('notification_preferences')) {
        $prefRequired = ['user_id'];
        $prefOk = true;
        foreach ($prefRequired as $c) {
            if (!$has('notification_preferences', $c)) { $prefOk = false; break; }
        }

        if ($prefOk) {
            $prefCols = ['user_id'];
            if ($has('notification_preferences', 'important_json')) $prefCols[] = 'important_json';
            if ($has('notification_preferences', 'informational_json')) $prefCols[] = 'informational_json';
            if ($has('notification_preferences', 'created_at')) $prefCols[] = 'created_at';
            if ($has('notification_preferences', 'updated_at')) $prefCols[] = 'updated_at';

            $prefSql = 'INSERT INTO notification_preferences (' . implode(', ', $prefCols) . ') VALUES (' . implode(', ', array_fill(0, count($prefCols), '?')) . ')';
            $insPrefs = $db->prepare($prefSql);

            $prefValsFor = function(int $userId, ?string $importantJson, ?string $informationalJson) use ($prefCols): array {
                $vals = [];
                foreach ($prefCols as $c) {
                    if ($c === 'user_id') $vals[] = $userId;
                    else if ($c === 'important_json') $vals[] = $importantJson;
                    else if ($c === 'informational_json') $vals[] = $informationalJson;
                    else if ($c === 'created_at') $vals[] = demoSeedNow('now');
                    else if ($c === 'updated_at') $vals[] = demoSeedNow('now');
                    else $vals[] = null;
                }
                return $vals;
            };
        }
    }

    $insRestriction = null;
    $restrictionCols = [];
    $restrictionValsFor = null;
    if ($has('user_restrictions')) {
        $restrictionRequired = ['user_id', 'restricted_until'];
        $restrictionOk = true;
        foreach ($restrictionRequired as $c) {
            if (!$has('user_restrictions', $c)) { $restrictionOk = false; break; }
        }

        if ($restrictionOk) {
            $restrictionCols = $restrictionRequired;
            if ($has('user_restrictions', 'reason')) $restrictionCols[] = 'reason';
            if ($has('user_restrictions', 'created_at')) $restrictionCols[] = 'created_at';
            if ($has('user_restrictions', 'updated_at')) $restrictionCols[] = 'updated_at';

            $restrictionSql = 'INSERT INTO user_restrictions (' . implode(', ', $restrictionCols) . ') VALUES (' . implode(', ', array_fill(0, count($restrictionCols), '?')) . ')';
            $insRestriction = $db->prepare($restrictionSql);

            $restrictionValsFor = function(int $userId, string $restrictedUntil, ?string $reason) use ($restrictionCols): array {
                $vals = [];
                foreach ($restrictionCols as $c) {
                    if ($c === 'user_id') $vals[] = $userId;
                    else if ($c === 'restricted_until') $vals[] = $restrictedUntil;
                    else if ($c === 'reason') $vals[] = $reason;
                    else if ($c === 'created_at') $vals[] = demoSeedNow('now');
                    else if ($c === 'updated_at') $vals[] = demoSeedNow('now');
                    else $vals[] = null;
                }
                return $vals;
            };
        }
    }

    $insUserPkg = null;
    $userPkgCols = [];
    $userPkgValsFor = null;
    if ($has('user_packages') && $has('packages')) {
        $userPkgRequired = ['user_id', 'package_id'];
        $userPkgOk = true;
        foreach ($userPkgRequired as $c) {
            if (!$has('user_packages', $c)) { $userPkgOk = false; break; }
        }

        if ($userPkgOk) {
            $userPkgCols = $userPkgRequired;
            if ($has('user_packages', 'assigned_by_user_id')) $userPkgCols[] = 'assigned_by_user_id';
            if ($has('user_packages', 'is_active')) $userPkgCols[] = 'is_active';
            if ($has('user_packages', 'assigned_at')) $userPkgCols[] = 'assigned_at';
            if ($has('user_packages', 'updated_at')) $userPkgCols[] = 'updated_at';

            $userPkgSql = 'INSERT INTO user_packages (' . implode(', ', $userPkgCols) . ') VALUES (' . implode(', ', array_fill(0, count($userPkgCols), '?')) . ')';

            $userPkgUpd = ['package_id=VALUES(package_id)'];
            if ($has('user_packages', 'assigned_by_user_id')) $userPkgUpd[] = 'assigned_by_user_id=VALUES(assigned_by_user_id)';
            if ($has('user_packages', 'is_active')) $userPkgUpd[] = 'is_active=1';
            if ($has('user_packages', 'updated_at')) $userPkgUpd[] = 'updated_at=NOW()';

            if ($userPkgUpd) {
                $userPkgSql .= ' ON DUPLICATE KEY UPDATE ' . implode(', ', $userPkgUpd);
            }

            $insUserPkg = $db->prepare($userPkgSql);

            $userPkgValsFor = function(int $userId, int $packageId, int $assignedByUserId) use ($userPkgCols): array {
                $vals = [];
                foreach ($userPkgCols as $c) {
                    if ($c === 'user_id') $vals[] = $userId;
                    else if ($c === 'package_id') $vals[] = $packageId;
                    else if ($c === 'assigned_by_user_id') $vals[] = $assignedByUserId;
                    else if ($c === 'is_active') $vals[] = 1;
                    else if ($c === 'assigned_at') $vals[] = demoSeedNow('now');
                    else if ($c === 'updated_at') $vals[] = demoSeedNow('now');
                    else $vals[] = null;
                }
                return $vals;
            };
        }
    }

    $insPurchase = null;
    $purchaseCols = [];
    $purchaseValsFor = null;
    if ($has('package_purchases') && $has('packages')) {
        $purchaseRequired = ['user_id', 'package_id', 'status'];
        $purchaseOk = true;
        foreach ($purchaseRequired as $c) {
            if (!$has('package_purchases', $c)) { $purchaseOk = false; break; }
        }

        if ($purchaseOk) {
            $purchaseCols = $purchaseRequired;
            if ($has('package_purchases', 'created_at')) $purchaseCols[] = 'created_at';
            if ($has('package_purchases', 'decided_at')) $purchaseCols[] = 'decided_at';
            if ($has('package_purchases', 'decided_by_user_id')) $purchaseCols[] = 'decided_by_user_id';
            if ($has('package_purchases', 'note')) $purchaseCols[] = 'note';

            $purchaseSql = 'INSERT INTO package_purchases (' . implode(', ', $purchaseCols) . ') VALUES (' . implode(', ', array_fill(0, count($purchaseCols), '?')) . ')';
            $insPurchase = $db->prepare($purchaseSql);

            $purchaseValsFor = function(int $userId, int $packageId, string $status, ?string $createdAt, ?string $decidedAt, ?int $decidedByUserId, ?string $note) use ($purchaseCols): array {
                $vals = [];
                foreach ($purchaseCols as $c) {
                    if ($c === 'user_id') $vals[] = $userId;
                    else if ($c === 'package_id') $vals[] = $packageId;
                    else if ($c === 'status') $vals[] = $status;
                    else if ($c === 'created_at') $vals[] = $createdAt;
                    else if ($c === 'decided_at') $vals[] = $decidedAt;
                    else if ($c === 'decided_by_user_id') $vals[] = $decidedByUserId;
                    else if ($c === 'note') $vals[] = $note;
                    else $vals[] = null;
                }
                return $vals;
            };
        }
    }

    $insKyc = null;
    $kycCols = [];
    $kycValsFor = null;
    if ($has('kyc_submissions')) {
        $kycRequired = ['user_id', 'status'];
        $kycOk = true;
        foreach ($kycRequired as $c) {
            if (!$has('kyc_submissions', $c)) { $kycOk = false; break; }
        }

        if ($kycOk) {
            $kycCols = $kycRequired;
            if ($has('kyc_submissions', 'admin_note')) $kycCols[] = 'admin_note';
            if ($has('kyc_submissions', 'created_at')) $kycCols[] = 'created_at';
            if ($has('kyc_submissions', 'submitted_at')) $kycCols[] = 'submitted_at';
            if ($has('kyc_submissions', 'decided_at')) $kycCols[] = 'decided_at';
            if ($has('kyc_submissions', 'decided_by_user_id')) $kycCols[] = 'decided_by_user_id';

            $kycSql = 'INSERT INTO kyc_submissions (' . implode(', ', $kycCols) . ') VALUES (' . implode(', ', array_fill(0, count($kycCols), '?')) . ')';

            $kycUpd = ['status=VALUES(status)'];
            if ($has('kyc_submissions', 'admin_note')) $kycUpd[] = 'admin_note=VALUES(admin_note)';
            if ($has('kyc_submissions', 'submitted_at')) $kycUpd[] = 'submitted_at=VALUES(submitted_at)';
            if ($has('kyc_submissions', 'decided_at')) $kycUpd[] = 'decided_at=VALUES(decided_at)';
            if ($has('kyc_submissions', 'decided_by_user_id')) $kycUpd[] = 'decided_by_user_id=VALUES(decided_by_user_id)';
            if ($has('kyc_submissions', 'updated_at')) $kycUpd[] = 'updated_at=NOW()';

            $kycSql .= ' ON DUPLICATE KEY UPDATE ' . implode(', ', $kycUpd);

            $insKyc = $db->prepare($kycSql);

            $kycValsFor = function(int $userId, string $status, ?string $adminNote, ?string $submittedAt, ?string $decidedAt, ?int $decidedByUserId) use ($kycCols): array {
                $vals = [];
                foreach ($kycCols as $c) {
                    if ($c === 'user_id') $vals[] = $userId;
                    else if ($c === 'status') $vals[] = $status;
                    else if ($c === 'admin_note') $vals[] = $adminNote;
                    else if ($c === 'created_at') $vals[] = demoSeedNow('now');
                    else if ($c === 'submitted_at') $vals[] = $submittedAt;
                    else if ($c === 'decided_at') $vals[] = $decidedAt;
                    else if ($c === 'decided_by_user_id') $vals[] = $decidedByUserId;
                    else $vals[] = null;
                }
                return $vals;
            };
        }
    }

    $insNotif = null;
    $notifCols = [];
    $notifValsFor = null;
    if ($has('notifications')) {
        $notifRequired = ['user_id', 'tier', 'channel_mask', 'title', 'body', 'data_json'];
        $notifOk = true;
        foreach ($notifRequired as $c) {
            if (!$has('notifications', $c)) { $notifOk = false; break; }
        }

        if ($notifOk) {
            $notifCols = $notifRequired;
            if ($has('notifications', 'created_at')) $notifCols[] = 'created_at';
            if ($has('notifications', 'updated_at')) $notifCols[] = 'updated_at';

            $notifSql = 'INSERT INTO notifications (' . implode(', ', $notifCols) . ') VALUES (' . implode(', ', array_fill(0, count($notifCols), '?')) . ')';
            $insNotif = $db->prepare($notifSql);

            $notifValsFor = function(int $userId, string $tier, string $channelMask, string $title, string $body, ?string $dataJson) use ($notifCols): array {
                $vals = [];
                foreach ($notifCols as $c) {
                    if ($c === 'user_id') $vals[] = $userId;
                    else if ($c === 'tier') $vals[] = $tier;
                    else if ($c === 'channel_mask') $vals[] = $channelMask;
                    else if ($c === 'title') $vals[] = $title;
                    else if ($c === 'body') $vals[] = $body;
                    else if ($c === 'data_json') $vals[] = $dataJson;
                    else if ($c === 'created_at') $vals[] = demoSeedNow('now');
                    else if ($c === 'updated_at') $vals[] = demoSeedNow('now');
                    else $vals[] = null;
                }
                return $vals;
            };
        }
    }

    $createdUsers = [];

    $db->beginTransaction();

    // Ensure admin trust row exists for rooms features.
    if ($insTrust && $trustValsFor) {
        $insTrust->execute($trustValsFor((int)$adminUserId, 3, 0));
    }

    foreach ($users as $u) {
        $email = strtolower(trim((string)$u['email']));

        $vaultSalt = bin2hex(random_bytes(32));
        $vaultVerifier = demoSeedHashVaultVerifier(bin2hex(random_bytes(32)) . $vaultSalt);

        $altHash = null;
        $altSalt = null;
        if ($hasVaultAlt && !empty($u['vault_rotate'])) {
            $altSalt = bin2hex(random_bytes(32));
            $altHash = demoSeedHashVaultVerifier(bin2hex(random_bytes(32)) . $altSalt);
        }

        $vals = [];
        foreach ($userCols as $col) {
            if ($col === 'email') $vals[] = $email;
            else if ($col === 'login_hash') $vals[] = demoSeedHashLoginPassword($demoPassword);
            else if ($col === 'vault_verifier') $vals[] = $vaultVerifier;
            else if ($col === 'vault_verifier_salt') $vals[] = $vaultSalt;
            else if ($col === 'is_admin') $vals[] = 0;
            else if ($col === 'email_verified_at') $vals[] = demoSeedNow('now');
            else if ($col === 'room_display_name') $vals[] = (string)$u['display'];
            else if ($col === 'profile_image_url') $vals[] = null;
            else if ($col === 'require_webauthn') $vals[] = !empty($u['require_webauthn']) ? 1 : 0;
            else if ($col === 'vault_active_slot') {
                $slot = !empty($u['vault_active_slot']) ? (int)$u['vault_active_slot'] : 1;
                if ($slot === 2 && !$hasVaultAlt) $slot = 1;
                $vals[] = in_array($slot, [1, 2], true) ? $slot : 1;
            }
            else if ($col === 'onboarding_completed_at') $vals[] = !empty($u['onboarding_complete']) ? demoSeedNow('-2 days') : null;
            else if ($col === 'vault_verifier_alt') $vals[] = $altHash;
            else if ($col === 'vault_verifier_alt_salt') $vals[] = $altSalt;
            else if ($col === 'vault_verifier_alt_set_at') $vals[] = $altHash ? demoSeedNow('-1 day') : null;
            else if ($col === 'address_line1') $vals[] = 'Rue du Marché';
            else if ($col === 'address_line2') $vals[] = null;
            else if ($col === 'address_city') $vals[] = 'Lomé';
            else if ($col === 'address_region') $vals[] = 'Maritime';
            else if ($col === 'address_postal_code') $vals[] = 'BP 100';
            else if ($col === 'address_country') $vals[] = 'Togo';
            else $vals[] = null;
        }

        $insUser->execute($vals);
        $userId = (int)$db->lastInsertId();

        $createdUsers[] = [
            'id' => $userId,
            'email' => $email,
            'display' => (string)$u['display'],
            'trust_level' => (int)$u['trust_level'],
        ];

        if ($insTrust && $trustValsFor) {
            $insTrust->execute($trustValsFor($userId, (int)$u['trust_level'], 0));
        }

        if ($insPrefs && $prefValsFor) {
            $important = json_encode([
                'email_time_lock_reminders' => 0,
            ], JSON_UNESCAPED_UNICODE);
            $informational = json_encode([
                'skip_setup' => !empty($u['onboarding_complete']) ? 1 : 0,
            ], JSON_UNESCAPED_UNICODE);
            $insPrefs->execute($prefValsFor($userId, $important, $informational));
        }

        if ($insRestriction && $restrictionValsFor && !empty($u['restricted'])) {
            $insRestriction->execute($restrictionValsFor($userId, demoSeedNow('+10 days'), 'Demo restriction period'));
        }

        if ($insUserPkg && $userPkgValsFor && !empty($u['package_slug']) && isset($pkgId[(string)$u['package_slug']])) {
            $insUserPkg->execute($userPkgValsFor($userId, $pkgId[(string)$u['package_slug']], $adminUserId));
        }

        if ($insPurchase && $purchaseValsFor) {
            if ($email === 'sena.adjorlolo@example.com' && isset($pkgId['controle_plus'])) {
                $insPurchase->execute($purchaseValsFor($userId, $pkgId['controle_plus'], 'pending', demoSeedNow('-1 day'), null, null, 'Demo pending purchase'));
            }
            if ($email === 'yaovi.tchalla@example.com' && isset($pkgId['control_max'])) {
                $insPurchase->execute($purchaseValsFor($userId, $pkgId['control_max'], 'rejected', demoSeedNow('-8 days'), demoSeedNow('-7 days'), $adminUserId, 'Demo rejected purchase'));
            }
        }

        if ($insKyc && $kycValsFor) {
            $st = (string)($u['kyc_status'] ?? 'draft');
            $submittedAt = null;
            $decidedAt = null;
            $decidedBy = null;
            $note = null;

            if ($st === 'submitted') {
                $submittedAt = demoSeedNow('-3 days');
                $note = null;
            } else if ($st === 'approved') {
                $submittedAt = demoSeedNow('-10 days');
                $decidedAt = demoSeedNow('-7 days');
                $decidedBy = $adminUserId;
                $note = 'Approved (demo)';
            } else if ($st === 'rejected') {
                $submittedAt = demoSeedNow('-10 days');
                $decidedAt = demoSeedNow('-6 days');
                $decidedBy = $adminUserId;
                $note = 'Rejected (demo)';
            }

            $insKyc->execute($kycValsFor($userId, $st, $note, $submittedAt, $decidedAt, $decidedBy));
        }

        if ($insNotif && $notifValsFor) {
            $insNotif->execute($notifValsFor(
                $userId,
                'informational',
                'inapp',
                'Welcome (demo)',
                'This is a demo account created during installation for testing purposes.',
                json_encode(['demo' => 1], JSON_UNESCAPED_UNICODE)
            ));
        }
    }

    $out['users'] = $createdUsers;

    // Destination accounts (optional, used by saving rooms)
    $destinationAccountIds = [];
    if ($has('platform_destination_accounts')) {
        $carrierMixx = null;
        if ($has('carriers')) {
            $st = $db->prepare('SELECT id FROM carriers WHERE name = ? LIMIT 1');
            $st->execute(['Mixx by YAS']);
            $carrierMixx = (int)$st->fetchColumn();
            if ($carrierMixx <= 0) {
                $st->execute(['Moov Money']);
                $carrierMixx = (int)$st->fetchColumn();
            }
        }

        $findOrCreateAccount = function(string $type, array $match, array $data) use ($db, $has): int {
            $where = ["account_type = ?"];
            $params = [$type];

            foreach ($match as $col => $val) {
                if ($has('platform_destination_accounts', $col)) {
                    $where[] = "{$col} = ?";
                    $params[] = $val;
                }
            }

            $sel = $db->prepare('SELECT id FROM platform_destination_accounts WHERE ' . implode(' AND ', $where) . ' LIMIT 1');
            $sel->execute($params);
            $existingId = (int)$sel->fetchColumn();
            $sel->closeCursor();
            if ($existingId > 0) return $existingId;

            $cols = ['account_type'];
            $vals = [$type];

            foreach ($data as $col => $val) {
                if ($has('platform_destination_accounts', $col)) {
                    $cols[] = $col;
                    $vals[] = $val;
                }
            }

            if ($has('platform_destination_accounts', 'is_active')) {
                $cols[] = 'is_active';
                $vals[] = 1;
            }
            if ($has('platform_destination_accounts', 'created_at')) {
                $cols[] = 'created_at';
                $vals[] = demoSeedNow('now');
            }
            if ($has('platform_destination_accounts', 'updated_at')) {
                $cols[] = 'updated_at';
                $vals[] = demoSeedNow('now');
            }

            $sql = 'INSERT INTO platform_destination_accounts (' . implode(', ', $cols) . ') VALUES (' . implode(', ', array_fill(0, count($cols), '?')) . ')';
            $db->prepare($sql)->execute($vals);
            return (int)$db->lastInsertId();
        };

        // Mobile money (Mixx)
        $destinationAccountIds['mixx'] = $findOrCreateAccount(
            'mobile_money',
            ['mobile_money_number' => '+228 90 00 00 00'],
            [
                'display_label' => 'Mixx (demo)',
                'carrier_id' => $carrierMixx ?: null,
                'mobile_money_number' => '+228 90 00 00 00',
                // Legacy schema support (010): unlock code stored on platform_destination_accounts
                'unlock_code_enc' => demoSeedEncryptForDb('1122'),
                'code_rotated_at' => demoSeedNow('-2 days'),
                'code_rotation_version' => 1,
            ]
        );

        // Bank
        $destinationAccountIds['bank'] = $findOrCreateAccount(
            'bank',
            ['bank_account_number' => 'TG1234567890'],
            [
                'display_label' => 'Ecobank Togo (demo)',
                'bank_name' => 'Ecobank Togo',
                'bank_account_name' => 'Controle Demo',
                'bank_account_number' => 'TG1234567890',
                'bank_routing_number' => null,
                'bank_swift' => null,
                'bank_iban' => null,
                // Legacy schema support (010): unlock code stored on platform_destination_accounts
                'unlock_code_enc' => demoSeedEncryptForDb('DEMO-BANK-CODE'),
                'code_rotated_at' => demoSeedNow('-2 days'),
                'code_rotation_version' => 1,
            ]
        );

        // Crypto wallet (optional; schema 029+)
        if ($has('platform_destination_accounts', 'crypto_network') && $has('platform_destination_accounts', 'crypto_address')) {
            $destinationAccountIds['crypto'] = $findOrCreateAccount(
                'crypto_wallet',
                ['crypto_address' => 'TQn9Y2Xb1cYvRzJm9bq9bYqYd1c9rY9bQy'],
                [
                    'display_label' => 'USDT TRC20 (demo)',
                    'crypto_network' => 'TRON',
                    'crypto_address' => 'TQn9Y2Xb1cYvRzJm9bq9bYqYd1c9rY9bQy',
                ]
            );
        }
    }

    // Saving rooms + participants
    if ($has('saving_rooms') && $has('saving_room_participants')) {
        $idByEmail = [];
        foreach ($createdUsers as $r) {
            $idByEmail[(string)$r['email']] = (int)$r['id'];
        }

        $requiredRoomCols = [
            'id',
            'maker_user_id',
            'saving_type',
            'visibility',
            'min_participants',
            'max_participants',
            'participation_amount',
            'periodicity',
            'start_at',
            'reveal_at',
            'lobby_state',
            'room_state',
        ];

        $canSeedRooms = true;
        foreach ($requiredRoomCols as $c) {
            if (!$has('saving_rooms', $c)) { $canSeedRooms = false; break; }
        }

        if ($canSeedRooms) {
            $roomCols = [];
            $roomColsAll = [
                'id',
                'maker_user_id',
                'purpose_category',
                'goal_text',
                'saving_type',
                'visibility',
                'required_trust_level',
                'min_participants',
                'max_participants',
                'participation_amount',
                'periodicity',
                'start_at',
                'reveal_at',
                'lobby_state',
                'room_state',
                'privacy_mode',
                'escrow_policy',
                'extensions_used',
                'created_at',
                'updated_at',
            ];

            foreach ($roomColsAll as $c) {
                if ($has('saving_rooms', $c)) $roomCols[] = $c;
            }

            $roomSql = 'INSERT INTO saving_rooms (' . implode(', ', $roomCols) . ') VALUES (' . implode(', ', array_fill(0, count($roomCols), '?')) . ')';
            $insRoom = $db->prepare($roomSql);

            $roomValsFor = function(array $data) use ($roomCols): array {
                $vals = [];
                foreach ($roomCols as $c) {
                    if (array_key_exists($c, $data)) $vals[] = $data[$c];
                    else if ($c === 'created_at' || $c === 'updated_at') $vals[] = demoSeedNow('now');
                    else $vals[] = null;
                }
                return $vals;
            };

            $partColsBase = ['room_id', 'user_id', 'status'];
            $partCols = $partColsBase;
            if ($has('saving_room_participants', 'joined_at')) $partCols[] = 'joined_at';
            if ($has('saving_room_participants', 'approved_at')) $partCols[] = 'approved_at';
            if ($has('saving_room_participants', 'slot_position')) $partCols[] = 'slot_position';
            $partSql = 'INSERT INTO saving_room_participants (' . implode(', ', $partCols) . ') VALUES (' . implode(', ', array_fill(0, count($partCols), '?')) . ')';
            $insPart = $db->prepare($partSql);

        $insJoinReq = null;
        if ($has('saving_room_join_requests')) {
            $insJoinReq = $db->prepare('INSERT INTO saving_room_join_requests (room_id, user_id, status, snapshot_level, snapshot_strikes_6m, snapshot_restricted_until, created_at)
                                        VALUES (?, ?, ?, ?, ?, ?, NOW())');
        }

        $insInvite = null;
        if ($has('saving_room_invites')) {
            $insInvite = $db->prepare('INSERT INTO saving_room_invites (room_id, invite_mode, invite_token_hash, invited_user_id, invited_email, status, expires_at, created_at)
                                       VALUES (?, ?, ?, ?, ?, ?, ?, NOW())');
        }

        $insRoomAccount = null;
        if ($has('saving_room_accounts') && $destinationAccountIds) {
            $sraCols = ['room_id', 'account_id'];
            if ($has('saving_room_accounts', 'unlock_code_enc')) $sraCols[] = 'unlock_code_enc';
            if ($has('saving_room_accounts', 'code_rotated_at')) $sraCols[] = 'code_rotated_at';
            if ($has('saving_room_accounts', 'code_rotation_version')) $sraCols[] = 'code_rotation_version';
            if ($has('saving_room_accounts', 'created_at')) $sraCols[] = 'created_at';
            if ($has('saving_room_accounts', 'updated_at')) $sraCols[] = 'updated_at';

            $sql = 'INSERT INTO saving_room_accounts (' . implode(', ', $sraCols) . ') VALUES (' . implode(', ', array_fill(0, count($sraCols), '?')) . ')';
            $insRoomAccount = $db->prepare($sql);
        }

        $roomSwap = null;
        $roomUnlockA = null;

        // Room A (public, lobby)
        $roomA = demoSeedGenerateUuid();
        $makerA = $idByEmail['kossi.mensah@example.com'];
        $insRoom->execute($roomValsFor([
            'id' => $roomA,
            'maker_user_id' => $makerA,
            'purpose_category' => 'business',
            'goal_text' => 'Démarrage d’un petit commerce à Lomé (démo)',
            'saving_type' => 'A',
            'visibility' => 'public',
            'required_trust_level' => 1,
            'min_participants' => 3,
            'max_participants' => 5,
            'participation_amount' => '10000.00',
            'periodicity' => 'weekly',
            'start_at' => demoSeedNow('+10 days'),
            'reveal_at' => demoSeedNow('+60 days'),
            'lobby_state' => 'open',
            'room_state' => 'lobby',
            'privacy_mode' => 1,
            'escrow_policy' => 'redistribute',
            'extensions_used' => 0,
        ]));

        $participantsA = [
            [$makerA, 'approved'],
            [$idByEmail['akossiwa.dossa@example.com'], 'approved'],
            [$idByEmail['efui.koffi@example.com'], 'approved'],
            [$idByEmail['kodjo.amegashie@example.com'], 'pending'],
        ];
        $slot = 1;
        foreach ($participantsA as $p) {
            $vals = [];
            foreach ($partCols as $col) {
                if ($col === 'room_id') $vals[] = $roomA;
                else if ($col === 'user_id') $vals[] = (int)$p[0];
                else if ($col === 'status') $vals[] = (string)$p[1];
                else if ($col === 'joined_at') $vals[] = demoSeedNow('-1 day');
                else if ($col === 'approved_at') $vals[] = ($p[1] === 'approved') ? demoSeedNow('-1 day') : null;
                else if ($col === 'slot_position') $vals[] = $slot;
                else $vals[] = null;
            }
            $insPart->execute($vals);
            $slot++;
        }

        if ($insJoinReq) {
            $lvl = 1;
            if ($insTrust) {
                $st = $db->prepare('SELECT trust_level FROM user_trust WHERE user_id = ?');
                $st->execute([(int)$idByEmail['kodjo.amegashie@example.com']]);
                $lvl = (int)($st->fetchColumn() ?: 1);
            }
            $insJoinReq->execute([$roomA, (int)$idByEmail['kodjo.amegashie@example.com'], 'pending', $lvl, 0, null]);
        }

        

        // Room B (public, active Type B)
        $roomB = demoSeedGenerateUuid();
        $makerB = $idByEmail['akossiwa.dossa@example.com'];
        $insRoom->execute($roomValsFor([
            'id' => $roomB,
            'maker_user_id' => $makerB,
            'purpose_category' => 'community',
            'goal_text' => 'Tontine de quartier (démo)',
            'saving_type' => 'B',
            'visibility' => 'public',
            'required_trust_level' => 2,
            'min_participants' => 4,
            'max_participants' => 6,
            'participation_amount' => '5000.00',
            'periodicity' => 'weekly',
            'start_at' => demoSeedNow('-7 days'),
            'reveal_at' => demoSeedNow('+45 days'),
            'lobby_state' => 'locked',
            'room_state' => 'active',
            'privacy_mode' => 0,
            'escrow_policy' => 'redistribute',
            'extensions_used' => 0,
        ]));

        $participantsB = [
            [$makerB, 'active'],
            [$idByEmail['komla.afi@example.com'], 'active'],
            [$idByEmail['yaovi.tchalla@example.com'], 'active'],
            [$idByEmail['sessi.atakpama@example.com'], 'active'],
            [$idByEmail['dela.tete@example.com'], 'active'],
        ];
        $slot = 1;
        foreach ($participantsB as $p) {
            $vals = [];
            foreach ($partCols as $col) {
                if ($col === 'room_id') $vals[] = $roomB;
                else if ($col === 'user_id') $vals[] = (int)$p[0];
                else if ($col === 'status') $vals[] = (string)$p[1];
                else if ($col === 'joined_at') $vals[] = demoSeedNow('-12 days');
                else if ($col === 'approved_at') $vals[] = demoSeedNow('-12 days');
                else if ($col === 'slot_position') $vals[] = $slot;
                else $vals[] = null;
            }
            $insPart->execute($vals);
            $slot++;
        }

        // Room C (private, lobby)
        $roomC = demoSeedGenerateUuid();
        $makerC = $idByEmail['mawuli.kponton@example.com'];
        $insRoom->execute($roomValsFor([
            'id' => $roomC,
            'maker_user_id' => $makerC,
            'purpose_category' => 'education',
            'goal_text' => 'Frais de scolarité (démo)',
            'saving_type' => 'A',
            'visibility' => 'private',
            'required_trust_level' => 3,
            'min_participants' => 2,
            'max_participants' => 3,
            'participation_amount' => '15000.00',
            'periodicity' => 'monthly',
            'start_at' => demoSeedNow('+20 days'),
            'reveal_at' => demoSeedNow('+110 days'),
            'lobby_state' => 'open',
            'room_state' => 'lobby',
            'privacy_mode' => 1,
            'escrow_policy' => 'refund_minus_fee',
            'extensions_used' => 0,
        ]));

        $vals = [];
        foreach ($partCols as $col) {
            if ($col === 'room_id') $vals[] = $roomC;
            else if ($col === 'user_id') $vals[] = (int)$makerC;
            else if ($col === 'status') $vals[] = 'approved';
            else if ($col === 'joined_at') $vals[] = demoSeedNow('-1 day');
            else if ($col === 'approved_at') $vals[] = demoSeedNow('-1 day');
            else if ($col === 'slot_position') $vals[] = 1;
            else $vals[] = null;
        }
        $insPart->execute($vals);

        $inviteToken = bin2hex(random_bytes(16));
        if ($insInvite) {
            $insInvite->execute([
                $roomC,
                'private_user',
                hash('sha256', $inviteToken),
                (int)$idByEmail['kossi.mensah@example.com'],
                null,
                'active',
                demoSeedNow('+30 days'),
            ]);
            $out['invites'][] = [
                'room_id' => $roomC,
                'invite_mode' => 'private_user',
                'token' => $inviteToken,
                'invited_email' => 'kossi.mensah@example.com',
            ];
        }

        // Room D (closed, to populate trust passport)
        $roomD = demoSeedGenerateUuid();
        $makerD = $makerA;
        $insRoom->execute($roomValsFor([
            'id' => $roomD,
            'maker_user_id' => $makerD,
            'purpose_category' => 'emergency',
            'goal_text' => 'Caisse urgence (démo)',
            'saving_type' => 'A',
            'visibility' => 'unlisted',
            'required_trust_level' => 1,
            'min_participants' => 2,
            'max_participants' => 4,
            'participation_amount' => '3000.00',
            'periodicity' => 'weekly',
            'start_at' => demoSeedNow('-50 days'),
            'reveal_at' => demoSeedNow('-5 days'),
            'lobby_state' => 'locked',
            'room_state' => 'closed',
            'privacy_mode' => 1,
            'escrow_policy' => 'redistribute',
            'extensions_used' => 0,
        ]));

        $completed = [
            $makerD,
            $idByEmail['efui.koffi@example.com'],
            $idByEmail['akossiwa.dossa@example.com'],
        ];
        $slot = 1;
        foreach ($completed as $uid) {
            $vals = [];
            foreach ($partCols as $col) {
                if ($col === 'room_id') $vals[] = $roomD;
                else if ($col === 'user_id') $vals[] = (int)$uid;
                else if ($col === 'status') $vals[] = 'completed';
                else if ($col === 'joined_at') $vals[] = demoSeedNow('-52 days');
                else if ($col === 'approved_at') $vals[] = demoSeedNow('-52 days');
                else if ($col === 'slot_position') $vals[] = $slot;
                else $vals[] = null;
            }
            $insPart->execute($vals);
            $slot++;
        }

        if ($has('user_completed_reveals')) {
            $insComp = $db->prepare('INSERT INTO user_completed_reveals (user_id, room_id, started_at, unlocked_at, duration_days, qualified_for_level, created_at)
                                     VALUES (?, ?, ?, ?, ?, 1, NOW())');
            foreach ($completed as $uid) {
                $insComp->execute([(int)$uid, $roomD, demoSeedNow('-50 days'), demoSeedNow('-5 days'), 45]);
            }

            if ($insTrust && $has('user_trust', 'completed_reveals_count')) {
                $db->prepare('UPDATE user_trust SET completed_reveals_count = completed_reveals_count + 1 WHERE user_id IN (' . implode(',', array_fill(0, count($completed), '?')) . ')')
                   ->execute(array_values(array_map('intval', $completed)));
            }
        }

        // Room Swap (public, swap window Type B)
        $hasSwapWindowCols = (
            $has('saving_rooms', 'swap_window_ends_at')
            || $has('saving_rooms', 'swap_window_closes_at')
            || $has('saving_rooms', 'swap_window_end_at')
        );

        if ($hasSwapWindowCols && $has('saving_room_slot_swaps')) {
            $roomSwap = demoSeedGenerateUuid();
            $makerSwap = $idByEmail['komla.afi@example.com'];
            $insRoom->execute($roomValsFor([
                'id' => $roomSwap,
                'maker_user_id' => $makerSwap,
                'purpose_category' => 'community',
                'goal_text' => 'Fenêtre d’échange des positions (démo)',
                'saving_type' => 'B',
                'visibility' => 'public',
                'required_trust_level' => 2,
                'min_participants' => 4,
                'max_participants' => 6,
                'participation_amount' => '6000.00',
                'periodicity' => 'weekly',
                'start_at' => demoSeedNow('-2 hours'),
                'reveal_at' => demoSeedNow('+40 days'),
                'lobby_state' => 'locked',
                'room_state' => 'swap_window',
                'privacy_mode' => 0,
                'escrow_policy' => 'redistribute',
                'extensions_used' => 0,
            ]));

            // Keep the swap window open so request/accept flows can be tested.
            $swapEndsAt = demoSeedNow('+8 hours');
            foreach (['swap_window_closes_at', 'swap_window_ends_at', 'swap_window_end_at'] as $c) {
                if ($has('saving_rooms', $c)) {
                    $db->prepare("UPDATE saving_rooms SET {$c} = ? WHERE id = ?")->execute([$swapEndsAt, $roomSwap]);
                    break;
                }
            }

            $participantsSwap = [
                [$makerSwap, 'approved'],
                [$idByEmail['dela.tete@example.com'], 'approved'],
                [$idByEmail['yaovi.tchalla@example.com'], 'approved'],
                [$idByEmail['sessi.atakpama@example.com'], 'approved'],
                [$idByEmail['kossi.mensah@example.com'], 'approved'],
            ];

            $slot = 1;
            foreach ($participantsSwap as $p) {
                $vals = [];
                foreach ($partCols as $col) {
                    if ($col === 'room_id') $vals[] = $roomSwap;
                    else if ($col === 'user_id') $vals[] = (int)$p[0];
                    else if ($col === 'status') $vals[] = (string)$p[1];
                    else if ($col === 'joined_at') $vals[] = demoSeedNow('-2 days');
                    else if ($col === 'approved_at') $vals[] = demoSeedNow('-2 days');
                    else if ($col === 'slot_position') $vals[] = $slot;
                    else $vals[] = null;
                }
                $insPart->execute($vals);
                $slot++;
            }

            // Populate rotation queue so the UI renders stable slot positions and swap accepts
            // will exercise the rotation_queue swap path.
            if ($has('saving_room_rotation_queue')) {
                $queueCols = ['room_id','user_id','position','status'];
                if ($has('saving_room_rotation_queue', 'slot_locked_at')) $queueCols[] = 'slot_locked_at';
                if ($has('saving_room_rotation_queue', 'created_at')) $queueCols[] = 'created_at';

                $queueSql = 'INSERT IGNORE INTO saving_room_rotation_queue (' . implode(', ', $queueCols) . ') VALUES (' . implode(', ', array_fill(0, count($queueCols), '?')) . ')';
                $queue = $db->prepare($queueSql);

                $pos = 1;
                foreach ($participantsSwap as $p) {
                    $vals = [];
                    foreach ($queueCols as $c) {
                        if ($c === 'room_id') $vals[] = $roomSwap;
                        else if ($c === 'user_id') $vals[] = (int)$p[0];
                        else if ($c === 'position') $vals[] = $pos;
                        else if ($c === 'status') $vals[] = 'queued';
                        else if ($c === 'slot_locked_at') $vals[] = null;
                        else if ($c === 'created_at') $vals[] = demoSeedNow('-2 days');
                        else $vals[] = null;
                    }
                    $queue->execute($vals);
                    $pos++;
                }
            }

            $pendingSwapId = null;
            if ($has('saving_room_slot_swaps', 'expires_at')) {
                $swapCols = ['room_id','from_user_id','to_user_id','status','expires_at'];
                if ($has('saving_room_slot_swaps', 'responded_at')) $swapCols[] = 'responded_at';
                if ($has('saving_room_slot_swaps', 'updated_at')) $swapCols[] = 'updated_at';

                $swapSql = 'INSERT INTO saving_room_slot_swaps (' . implode(', ', $swapCols) . ') VALUES (' . implode(', ', array_fill(0, count($swapCols), '?')) . ')';
                $insSwap = $db->prepare($swapSql);

                // One pending swap request so accept/decline flows can be tested.
                $vals = [];
                foreach ($swapCols as $c) {
                    if ($c === 'room_id') $vals[] = $roomSwap;
                    else if ($c === 'from_user_id') $vals[] = (int)$participantsSwap[0][0];
                    else if ($c === 'to_user_id') $vals[] = (int)$participantsSwap[1][0];
                    else if ($c === 'status') $vals[] = 'pending';
                    else if ($c === 'expires_at') $vals[] = $swapEndsAt;
                    else if ($c === 'responded_at') $vals[] = null;
                    else if ($c === 'updated_at') $vals[] = null;
                    else $vals[] = null;
                }
                $insSwap->execute($vals);
                $pendingSwapId = (int)$db->lastInsertId();
            }

            if ($has('saving_room_activity')) {
                $act = $db->prepare('INSERT INTO saving_room_activity (room_id, event_type, public_payload_json, created_at) VALUES (?, ?, ?, NOW())');
                $act->execute([$roomSwap, 'swap_window_started', json_encode(['swap_window_ends_at' => $swapEndsAt], JSON_UNESCAPED_UNICODE)]);
                $act->execute([$roomSwap, 'slot_swap_requested', json_encode(['swap_id' => $pendingSwapId, 'demo' => 1], JSON_UNESCAPED_UNICODE)]);
            }
        }

        // Room Unlock A (public, active Type A near unlock/reveal)
        if ($has('saving_room_unlock_events') && $has('saving_room_unlock_votes')) {
            $roomUnlockA = demoSeedGenerateUuid();
            $makerU = $makerA;
            $insRoom->execute($roomValsFor([
                'id' => $roomUnlockA,
                'maker_user_id' => $makerU,
                'purpose_category' => 'business',
                'goal_text' => 'Déverrouillage Type A (votes) (démo)',
                'saving_type' => 'A',
                'visibility' => 'public',
                'required_trust_level' => 1,
                'min_participants' => 3,
                'max_participants' => 5,
                'participation_amount' => '8000.00',
                'periodicity' => 'weekly',
                'start_at' => demoSeedNow('-20 days'),
                'reveal_at' => demoSeedNow('-1 day'),
                'lobby_state' => 'locked',
                'room_state' => 'active',
                'privacy_mode' => 1,
                'escrow_policy' => 'redistribute',
                'extensions_used' => 0,
            ]));

            $participantsU = [
                [$makerU, 'active'],
                [$idByEmail['akossiwa.dossa@example.com'], 'active'],
                [$idByEmail['efui.koffi@example.com'], 'active'],
            ];
            $slot = 1;
            foreach ($participantsU as $p) {
                $vals = [];
                foreach ($partCols as $col) {
                    if ($col === 'room_id') $vals[] = $roomUnlockA;
                    else if ($col === 'user_id') $vals[] = (int)$p[0];
                    else if ($col === 'status') $vals[] = (string)$p[1];
                    else if ($col === 'joined_at') $vals[] = demoSeedNow('-21 days');
                    else if ($col === 'approved_at') $vals[] = demoSeedNow('-21 days');
                    else if ($col === 'slot_position') $vals[] = $slot;
                    else $vals[] = null;
                }
                $insPart->execute($vals);
                $slot++;
            }

            $ueCols = ['room_id','status'];
            if ($has('saving_room_unlock_events', 'revealed_at')) $ueCols[] = 'revealed_at';
            if ($has('saving_room_unlock_events', 'expires_at')) $ueCols[] = 'expires_at';
            if ($has('saving_room_unlock_events', 'created_at')) $ueCols[] = 'created_at';

            $ueSql = 'INSERT IGNORE INTO saving_room_unlock_events (' . implode(', ', $ueCols) . ') VALUES (' . implode(', ', array_fill(0, count($ueCols), '?')) . ')';
            $insUE = $db->prepare($ueSql);
            $ueVals = [];
            foreach ($ueCols as $c) {
                if ($c === 'room_id') $ueVals[] = $roomUnlockA;
                else if ($c === 'status') $ueVals[] = 'pending';
                else if ($c === 'revealed_at') $ueVals[] = null;
                else if ($c === 'expires_at') $ueVals[] = null;
                else if ($c === 'created_at') $ueVals[] = demoSeedNow('-2 days');
                else $ueVals[] = null;
            }
            $insUE->execute($ueVals);

            $voteCols = ['room_id','user_id','scope','target_rotation_index','vote'];
            if ($has('saving_room_unlock_votes', 'created_at')) $voteCols[] = 'created_at';
            if ($has('saving_room_unlock_votes', 'updated_at')) $voteCols[] = 'updated_at';
            $voteSql = 'INSERT IGNORE INTO saving_room_unlock_votes (' . implode(', ', $voteCols) . ') VALUES (' . implode(', ', array_fill(0, count($voteCols), '?')) . ')';
            $insVote = $db->prepare($voteSql);

            $presetVotes = [
                [$participantsU[0][0], 'approve'],
                [$participantsU[1][0], 'approve'],
                [$participantsU[2][0], 'reject'],
            ];
            foreach ($presetVotes as $pv) {
                $vals = [];
                foreach ($voteCols as $c) {
                    if ($c === 'room_id') $vals[] = $roomUnlockA;
                    else if ($c === 'user_id') $vals[] = (int)$pv[0];
                    else if ($c === 'scope') $vals[] = 'typeA_room_unlock';
                    else if ($c === 'target_rotation_index') $vals[] = 0;
                    else if ($c === 'vote') $vals[] = (string)$pv[1];
                    else if ($c === 'created_at') $vals[] = demoSeedNow('-3 hours');
                    else if ($c === 'updated_at') $vals[] = null;
                    else $vals[] = null;
                }
                $insVote->execute($vals);
            }
        }

        // Type B rotation scaffolding + disputes/exit requests (optional)
        $roomBRotationIndex = 1;
        $roomBActiveUser = (int)$participantsB[1][0];

        if ($has('saving_room_rotation_queue') && $has('saving_room_rotation_windows')) {
            $queueCols = ['room_id','user_id','position','status'];
            if ($has('saving_room_rotation_queue', 'slot_locked_at')) $queueCols[] = 'slot_locked_at';
            if ($has('saving_room_rotation_queue', 'created_at')) $queueCols[] = 'created_at';

            $queueSql = 'INSERT IGNORE INTO saving_room_rotation_queue (' . implode(', ', $queueCols) . ') VALUES (' . implode(', ', array_fill(0, count($queueCols), '?')) . ')';
            $queue = $db->prepare($queueSql);

            $winCols = ['room_id','user_id','rotation_index','status'];
            if ($has('saving_room_rotation_windows', 'delegate_user_id')) $winCols[] = 'delegate_user_id';
            if ($has('saving_room_rotation_windows', 'delegate_set_at')) $winCols[] = 'delegate_set_at';
            if ($has('saving_room_rotation_windows', 'approve_opens_at')) $winCols[] = 'approve_opens_at';
            if ($has('saving_room_rotation_windows', 'approve_due_at')) $winCols[] = 'approve_due_at';
            if ($has('saving_room_rotation_windows', 'revealed_at')) $winCols[] = 'revealed_at';
            if ($has('saving_room_rotation_windows', 'expires_at')) $winCols[] = 'expires_at';
            if ($has('saving_room_rotation_windows', 'withdrawal_confirmed_at')) $winCols[] = 'withdrawal_confirmed_at';
            if ($has('saving_room_rotation_windows', 'withdrawal_confirmed_by_user_id')) $winCols[] = 'withdrawal_confirmed_by_user_id';
            if ($has('saving_room_rotation_windows', 'withdrawal_reference')) $winCols[] = 'withdrawal_reference';
            if ($has('saving_room_rotation_windows', 'withdrawal_confirmed_role')) $winCols[] = 'withdrawal_confirmed_role';
            if ($has('saving_room_rotation_windows', 'dispute_window_ends_at')) $winCols[] = 'dispute_window_ends_at';
            if ($has('saving_room_rotation_windows', 'created_at')) $winCols[] = 'created_at';

            $winSql = 'INSERT IGNORE INTO saving_room_rotation_windows (' . implode(', ', $winCols) . ') VALUES (' . implode(', ', array_fill(0, count($winCols), '?')) . ')';
            $window = $db->prepare($winSql);

            $pos = 1;
            foreach ($participantsB as $p) {
                $vals = [];
                foreach ($queueCols as $c) {
                    if ($c === 'room_id') $vals[] = $roomB;
                    else if ($c === 'user_id') $vals[] = (int)$p[0];
                    else if ($c === 'position') $vals[] = $pos;
                    else if ($c === 'status') $vals[] = ($pos === 2 ? 'active_window' : 'queued');
                    else if ($c === 'slot_locked_at') $vals[] = ($pos === 2 ? demoSeedNow('-2 hours') : null);
                    else if ($c === 'created_at') $vals[] = demoSeedNow('-12 days');
                    else $vals[] = null;
                }
                $queue->execute($vals);
                $pos++;
            }

            $delegateUserId = (int)$makerB;
            $delegateSetAt = demoSeedNow('-90 minutes');

            // Type B "approbation" window (035) + withdrawal confirmation (030).
            // These columns are optional across installs; values are only inserted when the columns exist.
            $approveOpensAt = demoSeedNow('-30 minutes');
            $approveDueAt = demoSeedNow('+6 hours');

            $withdrawConfirmedAt = demoSeedNow('-25 minutes');
            $withdrawConfirmedByUserId = (int)$makerB;
            $withdrawReference = 'DEMO-WD-0001';
            $withdrawConfirmedRole = 'maker';

            $vals = [];
            foreach ($winCols as $c) {
                if ($c === 'room_id') $vals[] = $roomB;
                else if ($c === 'user_id') $vals[] = $roomBActiveUser;
                else if ($c === 'rotation_index') $vals[] = $roomBRotationIndex;
                else if ($c === 'status') $vals[] = 'revealed';
                else if ($c === 'delegate_user_id') $vals[] = $delegateUserId;
                else if ($c === 'delegate_set_at') $vals[] = $delegateSetAt;
                else if ($c === 'approve_opens_at') $vals[] = $approveOpensAt;
                else if ($c === 'approve_due_at') $vals[] = $approveDueAt;
                else if ($c === 'revealed_at') $vals[] = demoSeedNow('-3 hours');
                else if ($c === 'expires_at') $vals[] = demoSeedNow('+60 hours');
                else if ($c === 'withdrawal_confirmed_at') $vals[] = $withdrawConfirmedAt;
                else if ($c === 'withdrawal_confirmed_by_user_id') $vals[] = $withdrawConfirmedByUserId;
                else if ($c === 'withdrawal_reference') $vals[] = $withdrawReference;
                else if ($c === 'withdrawal_confirmed_role') $vals[] = $withdrawConfirmedRole;
                else if ($c === 'dispute_window_ends_at') $vals[] = demoSeedNow('+21 hours');
                else if ($c === 'created_at') $vals[] = demoSeedNow('-7 days');
                else $vals[] = null;
            }
            $window->execute($vals);

            if ($has('saving_room_activity')) {
                $act = $db->prepare('INSERT INTO saving_room_activity (room_id, event_type, public_payload_json, created_at) VALUES (?, ?, ?, NOW())');
                $act->execute([$roomB, 'typeB_delegate_set', json_encode(['rotation_index' => $roomBRotationIndex, 'delegate_user_id' => $delegateUserId, 'demo' => 1], JSON_UNESCAPED_UNICODE)]);
                $act->execute([$roomB, 'typeB_withdrawal_confirmed', json_encode(['rotation_index' => $roomBRotationIndex, 'withdrawal_reference' => $withdrawReference, 'withdrawal_confirmed_role' => $withdrawConfirmedRole, 'demo' => 1], JSON_UNESCAPED_UNICODE)]);
            }

            if ($has('saving_room_turn_code_views')) {
                $viewCols = ['room_id','rotation_index','viewer_user_id','viewer_role'];
                if ($has('saving_room_turn_code_views', 'viewed_at')) $viewCols[] = 'viewed_at';

                $viewSql = 'INSERT IGNORE INTO saving_room_turn_code_views (' . implode(', ', $viewCols) . ') VALUES (' . implode(', ', array_fill(0, count($viewCols), '?')) . ')';
                $insView = $db->prepare($viewSql);

                $vals = [];
                foreach ($viewCols as $c) {
                    if ($c === 'room_id') $vals[] = $roomB;
                    else if ($c === 'rotation_index') $vals[] = $roomBRotationIndex;
                    else if ($c === 'viewer_user_id') $vals[] = $delegateUserId;
                    else if ($c === 'viewer_role') $vals[] = 'delegate';
                    else if ($c === 'viewed_at') $vals[] = demoSeedNow('-55 minutes');
                    else $vals[] = null;
                }
                $insView->execute($vals);

                if ($has('saving_room_activity')) {
                    $act = $db->prepare('INSERT INTO saving_room_activity (room_id, event_type, public_payload_json, created_at) VALUES (?, ?, ?, NOW())');
                    $act->execute([$roomB, 'typeB_code_accessed', json_encode(['rotation_index' => $roomBRotationIndex, 'viewer_user_id' => $delegateUserId, 'viewer_role' => 'delegate', 'demo' => 1], JSON_UNESCAPED_UNICODE)]);
                }
            }
        }

        if ($has('saving_room_unlock_votes')) {
            $voteCols = ['room_id','user_id','scope','target_rotation_index','vote'];
            if ($has('saving_room_unlock_votes', 'created_at')) $voteCols[] = 'created_at';
            if ($has('saving_room_unlock_votes', 'updated_at')) $voteCols[] = 'updated_at';
            $voteSql = 'INSERT IGNORE INTO saving_room_unlock_votes (' . implode(', ', $voteCols) . ') VALUES (' . implode(', ', array_fill(0, count($voteCols), '?')) . ')';
            $insVote = $db->prepare($voteSql);

            $approveCount = 0;
            $rejectCount = 0;

            foreach ($participantsB as $i => $p) {
                $vote = ($i === 2) ? 'reject' : 'approve';
                if ($vote === 'approve') $approveCount++; else $rejectCount++;

                $vals = [];
                foreach ($voteCols as $c) {
                    if ($c === 'room_id') $vals[] = $roomB;
                    else if ($c === 'user_id') $vals[] = (int)$p[0];
                    else if ($c === 'scope') $vals[] = 'typeB_turn_unlock';
                    else if ($c === 'target_rotation_index') $vals[] = $roomBRotationIndex;
                    else if ($c === 'vote') $vals[] = $vote;
                    else if ($c === 'created_at') $vals[] = demoSeedNow('-2 hours');
                    else if ($c === 'updated_at') $vals[] = null;
                    else $vals[] = null;
                }
                $insVote->execute($vals);
            }

            if ($has('saving_room_activity')) {
                $act = $db->prepare('INSERT INTO saving_room_activity (room_id, event_type, public_payload_json, created_at) VALUES (?, ?, ?, NOW())');
                $act->execute([$roomB, 'rotation_vote_updated', json_encode(['rotation_index' => $roomBRotationIndex, 'approve_count' => $approveCount, 'reject_count' => $rejectCount, 'required' => 3, 'demo' => 1], JSON_UNESCAPED_UNICODE)]);
            }
        }

        if ($has('saving_room_disputes')) {
            $dispCols = ['room_id','rotation_index','raised_by_user_id','reason','status','threshold_count_required'];
            if ($has('saving_room_disputes', 'created_at')) $dispCols[] = 'created_at';
            if ($has('saving_room_disputes', 'updated_at')) $dispCols[] = 'updated_at';

            $dispSql = 'INSERT INTO saving_room_disputes (' . implode(', ', $dispCols) . ') VALUES (' . implode(', ', array_fill(0, count($dispCols), '?')) . ')';
            $insDisp = $db->prepare($dispSql);

            $raiser = (int)$participantsB[2][0];
            $required = 2;

            $dVals = [];
            foreach ($dispCols as $c) {
                if ($c === 'room_id') $dVals[] = $roomB;
                else if ($c === 'rotation_index') $dVals[] = $roomBRotationIndex;
                else if ($c === 'raised_by_user_id') $dVals[] = $raiser;
                else if ($c === 'reason') $dVals[] = 'Demo dispute (rotation eligibility)';
                else if ($c === 'status') $dVals[] = 'open';
                else if ($c === 'threshold_count_required') $dVals[] = $required;
                else if ($c === 'created_at') $dVals[] = demoSeedNow('-90 minutes');
                else if ($c === 'updated_at') $dVals[] = null;
                else $dVals[] = null;
            }
            $insDisp->execute($dVals);
            $disputeId = (int)$db->lastInsertId();

            $ackCount = 0;
            if ($disputeId > 0 && $has('saving_room_dispute_ack')) {
                $db->prepare('INSERT IGNORE INTO saving_room_dispute_ack (dispute_id, user_id) VALUES (?, ?)')->execute([$disputeId, $raiser]);
                $ackCount = 1;
            }

            if ($disputeId > 0 && $has('saving_room_activity')) {
                $act = $db->prepare('INSERT INTO saving_room_activity (room_id, event_type, public_payload_json, created_at) VALUES (?, ?, ?, NOW())');
                $act->execute([$roomB, 'dispute_raised', json_encode(['rotation_index' => $roomBRotationIndex, 'ack_count' => $ackCount, 'required' => $required, 'demo' => 1], JSON_UNESCAPED_UNICODE)]);
                if ($ackCount > 0) {
                    $act->execute([$roomB, 'dispute_ack_updated', json_encode(['rotation_index' => $roomBRotationIndex, 'ack_count' => $ackCount, 'required' => $required, 'demo' => 1], JSON_UNESCAPED_UNICODE)]);
                }
            }
        }

        if ($has('saving_room_exit_requests')) {
            $exCols = ['room_id','requested_by_user_id','status'];
            if ($has('saving_room_exit_requests', 'reason')) $exCols[] = 'reason';
            if ($has('saving_room_exit_requests', 'created_at')) $exCols[] = 'created_at';

            $exSql = 'INSERT INTO saving_room_exit_requests (' . implode(', ', $exCols) . ') VALUES (' . implode(', ', array_fill(0, count($exCols), '?')) . ')';
            $insEx = $db->prepare($exSql);

            $exVals = [];
            foreach ($exCols as $c) {
                if ($c === 'room_id') $exVals[] = $roomB;
                else if ($c === 'requested_by_user_id') $exVals[] = (int)$participantsB[3][0];
                else if ($c === 'status') $exVals[] = 'open';
                else if ($c === 'reason') $exVals[] = 'Demo exit request (needs cashflow)';
                else if ($c === 'created_at') $exVals[] = demoSeedNow('-45 minutes');
                else $exVals[] = null;
            }

            $insEx->execute($exVals);
            $exitReqId = (int)$db->lastInsertId();

            if ($exitReqId > 0 && $has('saving_room_unlock_votes')) {
                $voteCols = ['room_id','user_id','scope','target_rotation_index','vote'];
                if ($has('saving_room_unlock_votes', 'created_at')) $voteCols[] = 'created_at';
                if ($has('saving_room_unlock_votes', 'updated_at')) $voteCols[] = 'updated_at';
                $voteSql = 'INSERT IGNORE INTO saving_room_unlock_votes (' . implode(', ', $voteCols) . ') VALUES (' . implode(', ', array_fill(0, count($voteCols), '?')) . ')';
                $insVote = $db->prepare($voteSql);

                $approveCount = 0;
                $rejectCount = 0;

                foreach ($participantsB as $i => $p) {
                    $vote = ($i === 1) ? 'reject' : 'approve';
                    if ($vote === 'approve') $approveCount++; else $rejectCount++;

                    $vals = [];
                    foreach ($voteCols as $c) {
                        if ($c === 'room_id') $vals[] = $roomB;
                        else if ($c === 'user_id') $vals[] = (int)$p[0];
                        else if ($c === 'scope') $vals[] = 'typeB_exit_request';
                        else if ($c === 'target_rotation_index') $vals[] = $exitReqId;
                        else if ($c === 'vote') $vals[] = $vote;
                        else if ($c === 'created_at') $vals[] = demoSeedNow('-40 minutes');
                        else if ($c === 'updated_at') $vals[] = null;
                        else $vals[] = null;
                    }
                    $insVote->execute($vals);
                }

                if ($has('saving_room_activity')) {
                    $act = $db->prepare('INSERT INTO saving_room_activity (room_id, event_type, public_payload_json, created_at) VALUES (?, ?, ?, NOW())');
                    $act->execute([$roomB, 'exit_requested', json_encode(['exit_request_id' => $exitReqId, 'demo' => 1], JSON_UNESCAPED_UNICODE)]);
                    $act->execute([$roomB, 'exit_vote_updated', json_encode(['exit_request_id' => $exitReqId, 'approve_count' => $approveCount, 'reject_count' => $rejectCount, 'required' => 3, 'demo' => 1], JSON_UNESCAPED_UNICODE)]);
                }
            }
        }

        $roomBCycle1 = 0;
        if ($has('saving_room_contribution_cycles') && $has('saving_room_contributions')) {
            $insCycle = $db->prepare('INSERT IGNORE INTO saving_room_contribution_cycles (room_id, cycle_index, due_at, grace_ends_at, status, created_at)
                                      VALUES (?, ?, ?, ?, ?, NOW())');
            $insCycle->execute([$roomB, 1, demoSeedNow('-1 day'), demoSeedNow('+2 days'), 'grace']);
            $insCycle->execute([$roomB, 2, demoSeedNow('+6 days'), demoSeedNow('+9 days'), 'open']);

            $cycleIdStmt = $db->prepare('SELECT id FROM saving_room_contribution_cycles WHERE room_id = ? AND cycle_index = ?');
            $cycleIdStmt->execute([$roomB, 1]);
            $roomBCycle1 = (int)$cycleIdStmt->fetchColumn();

            if ($roomBCycle1 > 0) {
                $insContrib = $db->prepare("INSERT INTO saving_room_contributions (room_id, user_id, cycle_id, amount, status, reference, confirmed_at, created_at)
                                            VALUES (?, ?, ?, ?, ?, ?, ?, NOW())
                                            ON DUPLICATE KEY UPDATE amount=VALUES(amount), status=VALUES(status), reference=VALUES(reference), confirmed_at=VALUES(confirmed_at)");

                // Mix of paid / missed
                $insContrib->execute([$roomB, (int)$makerB, $roomBCycle1, '5000.00', 'paid', 'DEMO-PAID-001', demoSeedNow('-12 hours')]);
                $insContrib->execute([$roomB, (int)$participantsB[1][0], $roomBCycle1, '5000.00', 'paid_in_grace', 'DEMO-PAID-002', demoSeedNow('-2 hours')]);
                $insContrib->execute([$roomB, (int)$participantsB[2][0], $roomBCycle1, '5000.00', 'unpaid', null, null]);
                $insContrib->execute([$roomB, (int)$participantsB[3][0], $roomBCycle1, '5000.00', 'unpaid', null, null]);
                $insContrib->execute([$roomB, (int)$participantsB[4][0], $roomBCycle1, '5000.00', 'paid', 'DEMO-PAID-003', demoSeedNow('-10 hours')]);
            }
        }

        if ($has('saving_room_account_ledger')) {
            $ledgerCols = ['room_id','entry_seq','entry_type','entry_kind','amount','balance_after','source_type','source_id'];
            if ($has('saving_room_account_ledger', 'created_by_user_id')) $ledgerCols[] = 'created_by_user_id';
            if ($has('saving_room_account_ledger', 'created_at')) $ledgerCols[] = 'created_at';

            $ledgerSql = 'INSERT IGNORE INTO saving_room_account_ledger (' . implode(', ', $ledgerCols) . ') VALUES (' . implode(', ', array_fill(0, count($ledgerCols), '?')) . ')';
            $insLedger = $db->prepare($ledgerSql);

            $entries = [];
            if ($roomBCycle1 > 0 && $has('saving_room_contributions')) {
                $st = $db->prepare("SELECT id, user_id, amount, status, confirmed_at, created_at FROM saving_room_contributions WHERE room_id = ? AND cycle_id = ? ORDER BY id ASC");
                $st->execute([$roomB, $roomBCycle1]);
                $rows = $st->fetchAll();
                $st->closeCursor();

                foreach ($rows as $r) {
                    if (!in_array((string)$r['status'], ['paid', 'paid_in_grace'], true)) continue;
                    $entries[] = [
                        'entry_type' => 'credit',
                        'entry_kind' => 'contribution',
                        'amount' => (string)$r['amount'],
                        'source_type' => 'contribution',
                        'source_id' => (string)$r['id'],
                        'created_by_user_id' => (int)$r['user_id'],
                        'created_at' => (string)($r['confirmed_at'] ?: $r['created_at'] ?: demoSeedNow('-6 hours')),
                    ];
                }
            }

            if (!$entries) {
                $entries[] = [
                    'entry_type' => 'credit',
                    'entry_kind' => 'contribution',
                    'amount' => '20000.00',
                    'source_type' => 'seed',
                    'source_id' => 'DEMO-SEED-CREDIT',
                    'created_by_user_id' => (int)$makerB,
                    'created_at' => demoSeedNow('-6 hours'),
                ];
            }

            $entries[] = [
                'entry_type' => 'debit',
                'entry_kind' => 'withdrawal',
                'amount' => '10000.00',
                'source_type' => 'withdrawal',
                'source_id' => 'DEMO-WITHDRAW-ROOMB-1',
                'created_by_user_id' => $roomBActiveUser,
                'created_at' => demoSeedNow('-30 minutes'),
            ];

            $balance = 0.0;
            $seq = 1;
            foreach ($entries as $e) {
                $amt = (float)$e['amount'];
                if ($e['entry_type'] === 'credit') $balance += $amt;
                else $balance -= $amt;

                $vals = [];
                foreach ($ledgerCols as $c) {
                    if ($c === 'room_id') $vals[] = $roomB;
                    else if ($c === 'entry_seq') $vals[] = $seq;
                    else if ($c === 'entry_type') $vals[] = (string)$e['entry_type'];
                    else if ($c === 'entry_kind') $vals[] = (string)$e['entry_kind'];
                    else if ($c === 'amount') $vals[] = (string)$e['amount'];
                    else if ($c === 'balance_after') $vals[] = sprintf('%.2f', $balance);
                    else if ($c === 'source_type') $vals[] = (string)$e['source_type'];
                    else if ($c === 'source_id') $vals[] = (string)$e['source_id'];
                    else if ($c === 'created_by_user_id') $vals[] = (int)$e['created_by_user_id'];
                    else if ($c === 'created_at') $vals[] = (string)$e['created_at'];
                    else $vals[] = null;
                }
                $insLedger->execute($vals);
                $seq++;
            }
        }

        if ($has('saving_room_activity')) {
            $act = $db->prepare('INSERT INTO saving_room_activity (room_id, event_type, public_payload_json, created_at) VALUES (?, ?, ?, NOW())');
            $act->execute([$roomA, 'room_seeded', json_encode(['demo' => 1], JSON_UNESCAPED_UNICODE)]);
            $act->execute([$roomB, 'room_seeded', json_encode(['demo' => 1], JSON_UNESCAPED_UNICODE)]);
            if (!empty($roomSwap)) $act->execute([$roomSwap, 'room_seeded', json_encode(['demo' => 1], JSON_UNESCAPED_UNICODE)]);
            if (!empty($roomUnlockA)) $act->execute([$roomUnlockA, 'room_seeded', json_encode(['demo' => 1], JSON_UNESCAPED_UNICODE)]);
            $act->execute([$roomC, 'room_seeded', json_encode(['demo' => 1], JSON_UNESCAPED_UNICODE)]);
            $act->execute([$roomD, 'room_seeded', json_encode(['demo' => 1], JSON_UNESCAPED_UNICODE)]);
        }

        // Saving room accounts mapping (if available)
        if ($insRoomAccount && $destinationAccountIds) {
            $sraCols = [];
            // Recompute $sraCols the same way we did above.
            $sraCols = ['room_id', 'account_id'];
            if ($has('saving_room_accounts', 'unlock_code_enc')) $sraCols[] = 'unlock_code_enc';
            if ($has('saving_room_accounts', 'code_rotated_at')) $sraCols[] = 'code_rotated_at';
            if ($has('saving_room_accounts', 'code_rotation_version')) $sraCols[] = 'code_rotation_version';
            if ($has('saving_room_accounts', 'created_at')) $sraCols[] = 'created_at';
            if ($has('saving_room_accounts', 'updated_at')) $sraCols[] = 'updated_at';

            $insertRoomAccount = function(string $roomId, int $accountId) use ($db, $sraCols): void {
                $vals = [];
                foreach ($sraCols as $c) {
                    if ($c === 'room_id') $vals[] = $roomId;
                    else if ($c === 'account_id') $vals[] = $accountId;
                    else if ($c === 'unlock_code_enc') $vals[] = demoSeedEncryptForDb('DEMO-UNLOCK-' . substr($roomId, 0, 8));
                    else if ($c === 'code_rotated_at') $vals[] = demoSeedNow('-2 days');
                    else if ($c === 'code_rotation_version') $vals[] = 1;
                    else if ($c === 'created_at') $vals[] = demoSeedNow('now');
                    else if ($c === 'updated_at') $vals[] = demoSeedNow('now');
                    else $vals[] = null;
                }

                $sql = 'INSERT IGNORE INTO saving_room_accounts (' . implode(', ', $sraCols) . ') VALUES (' . implode(', ', array_fill(0, count($sraCols), '?')) . ')';
                $db->prepare($sql)->execute($vals);
            };

            if (!empty($destinationAccountIds['mixx'])) $insertRoomAccount($roomA, (int)$destinationAccountIds['mixx']);
            if (!empty($destinationAccountIds['bank'])) $insertRoomAccount($roomB, (int)$destinationAccountIds['bank']);
            if (!empty($roomSwap) && !empty($destinationAccountIds['bank'])) $insertRoomAccount($roomSwap, (int)$destinationAccountIds['bank']);
            if (!empty($roomUnlockA) && !empty($destinationAccountIds['mixx'])) $insertRoomAccount($roomUnlockA, (int)$destinationAccountIds['mixx']);
            if (!empty($destinationAccountIds['crypto'])) $insertRoomAccount($roomC, (int)$destinationAccountIds['crypto']);
        }

        $roomsOut = [
            ['id' => $roomA, 'visibility' => 'public', 'saving_type' => 'A'],
            ['id' => $roomB, 'visibility' => 'public', 'saving_type' => 'B'],
            ['id' => $roomC, 'visibility' => 'private', 'saving_type' => 'A'],
            ['id' => $roomD, 'visibility' => 'unlisted', 'saving_type' => 'A'],
        ];
        if (!empty($roomSwap)) $roomsOut[] = ['id' => $roomSwap, 'visibility' => 'public', 'saving_type' => 'B'];
        if (!empty($roomUnlockA)) $roomsOut[] = ['id' => $roomUnlockA, 'visibility' => 'public', 'saving_type' => 'A'];
        $out['rooms'] = $roomsOut;
        }
    }

    $db->commit();

    $out['seeded'] = 1;
    return $out;
}
