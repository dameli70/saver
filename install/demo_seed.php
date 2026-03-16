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
    if ($has('user_trust')) {
        $insTrust = $db->prepare('INSERT IGNORE INTO user_trust (user_id, trust_level, completed_reveals_count, last_level_change_at) VALUES (?, ?, ?, NOW())');
    }

    $insPrefs = null;
    if ($has('notification_preferences')) {
        $insPrefs = $db->prepare('INSERT INTO notification_preferences (user_id, important_json, informational_json, created_at, updated_at) VALUES (?, ?, ?, NOW(), NOW())');
    }

    $insRestriction = null;
    if ($has('user_restrictions')) {
        $insRestriction = $db->prepare('INSERT INTO user_restrictions (user_id, restricted_until, reason, created_at, updated_at) VALUES (?, ?, ?, NOW(), NOW())');
    }

    $insUserPkg = null;
    if ($has('user_packages') && $has('packages')) {
        $insUserPkg = $db->prepare('INSERT INTO user_packages (user_id, package_id, assigned_by_user_id, is_active, assigned_at, updated_at)
                                    VALUES (?, ?, ?, 1, NOW(), NOW())
                                    ON DUPLICATE KEY UPDATE package_id=VALUES(package_id), assigned_by_user_id=VALUES(assigned_by_user_id), is_active=1, updated_at=NOW()');
    }

    $insPurchase = null;
    if ($has('package_purchases') && $has('packages')) {
        $insPurchase = $db->prepare('INSERT INTO package_purchases (user_id, package_id, status, created_at, decided_at, decided_by_user_id, note)
                                     VALUES (?, ?, ?, ?, ?, ?, ?)');
    }

    $insKyc = null;
    if ($has('kyc_submissions')) {
        $insKyc = $db->prepare("INSERT INTO kyc_submissions (user_id, status, admin_note, created_at, submitted_at, decided_at, decided_by_user_id)
                                VALUES (?, ?, ?, NOW(), ?, ?, ?)
                                ON DUPLICATE KEY UPDATE status=VALUES(status), admin_note=VALUES(admin_note), submitted_at=VALUES(submitted_at), decided_at=VALUES(decided_at), decided_by_user_id=VALUES(decided_by_user_id), updated_at=NOW()");
    }

    $insNotif = null;
    if ($has('notifications')) {
        $insNotif = $db->prepare('INSERT INTO notifications (user_id, tier, channel_mask, title, body, data_json, created_at) VALUES (?, ?, ?, ?, ?, ?, NOW())');
    }

    $createdUsers = [];

    $db->beginTransaction();

    // Ensure admin trust row exists for rooms features.
    if ($insTrust) {
        $insTrust->execute([(int)$adminUserId, 3, 0]);
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

        if ($insTrust) {
            $insTrust->execute([$userId, (int)$u['trust_level'], 0]);
        }

        if ($insPrefs) {
            $important = json_encode([
                'email_time_lock_reminders' => 0,
            ], JSON_UNESCAPED_UNICODE);
            $informational = json_encode([
                'skip_setup' => !empty($u['onboarding_complete']) ? 1 : 0,
            ], JSON_UNESCAPED_UNICODE);
            $insPrefs->execute([$userId, $important, $informational]);
        }

        if ($insRestriction && !empty($u['restricted'])) {
            $insRestriction->execute([$userId, demoSeedNow('+10 days'), 'Demo restriction period']);
        }

        if ($insUserPkg && !empty($u['package_slug']) && isset($pkgId[(string)$u['package_slug']])) {
            $insUserPkg->execute([$userId, $pkgId[(string)$u['package_slug']], $adminUserId]);
        }

        if ($insPurchase && $has('package_purchases') && $has('packages')) {
            if ($email === 'sena.adjorlolo@example.com' && isset($pkgId['controle_plus'])) {
                $insPurchase->execute([$userId, $pkgId['controle_plus'], 'pending', demoSeedNow('-1 day'), null, null, 'Demo pending purchase']);
            }
            if ($email === 'yaovi.tchalla@example.com' && isset($pkgId['control_max'])) {
                $insPurchase->execute([$userId, $pkgId['control_max'], 'rejected', demoSeedNow('-8 days'), demoSeedNow('-7 days'), $adminUserId, 'Demo rejected purchase']);
            }
        }

        if ($insKyc) {
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

            $insKyc->execute([$userId, $st, $note, $submittedAt, $decidedAt, $decidedBy]);
        }

        if ($insNotif) {
            $insNotif->execute([
                $userId,
                'informational',
                'inapp',
                'Welcome (demo)',
                'This is a demo account created during installation for testing purposes.',
                json_encode(['demo' => 1], JSON_UNESCAPED_UNICODE),
            ]);
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

        $insAcc = $db->prepare("INSERT INTO platform_destination_accounts
            (account_type, display_label, carrier_id, mobile_money_number, bank_name, bank_account_name, bank_account_number, bank_routing_number, bank_swift, bank_iban, crypto_network, crypto_address, is_active, created_at, updated_at)
            VALUES
            (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, NOW(), NOW())");

        // Mobile money (Mixx)
        $insAcc->execute(['mobile_money', 'Mixx (demo)', $carrierMixx ?: null, '+228 90 00 00 00', null, null, null, null, null, null, null, null]);
        $destinationAccountIds['mixx'] = (int)$db->lastInsertId();

        // Bank
        $insAcc->execute(['bank', 'Ecobank Togo (demo)', null, null, 'Ecobank Togo', 'Controle Demo', 'TG1234567890', null, null, null, null, null]);
        $destinationAccountIds['bank'] = (int)$db->lastInsertId();

        // Crypto wallet (USDT TRC20)
        $insAcc->execute(['crypto_wallet', 'USDT TRC20 (demo)', null, null, null, null, null, null, null, null, 'TRON', 'TQn9Y2Xb1cYvRzJm9bq9bYqYd1c9rY9bQy']);
        $destinationAccountIds['crypto'] = (int)$db->lastInsertId();
    }

    // Saving rooms + participants
    if ($has('saving_rooms') && $has('saving_room_participants')) {
        $idByEmail = [];
        foreach ($createdUsers as $r) {
            $idByEmail[(string)$r['email']] = (int)$r['id'];
        }

        $roomCols = [
            'id', 'maker_user_id', 'purpose_category', 'goal_text', 'saving_type', 'visibility',
            'required_trust_level', 'min_participants', 'max_participants', 'participation_amount',
            'periodicity', 'start_at', 'reveal_at', 'lobby_state', 'room_state', 'privacy_mode',
            'escrow_policy', 'extensions_used',
        ];
        $roomSql = 'INSERT INTO saving_rooms (' . implode(', ', $roomCols) . ') VALUES (' . implode(', ', array_fill(0, count($roomCols), '?')) . ')';
        $insRoom = $db->prepare($roomSql);

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
        $insRoom->execute([
            $roomA,
            $makerA,
            'business',
            'Démarrage d’un petit commerce à Lomé (démo)',
            'A',
            'public',
            1,
            3,
            5,
            '10000.00',
            'weekly',
            demoSeedNow('+10 days'),
            demoSeedNow('+60 days'),
            'open',
            'lobby',
            1,
            'redistribute',
            0,
        ]);

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
        $insRoom->execute([
            $roomB,
            $makerB,
            'community',
            'Tontine de quartier (démo)',
            'B',
            'public',
            2,
            4,
            6,
            '5000.00',
            'weekly',
            demoSeedNow('-7 days'),
            demoSeedNow('+45 days'),
            'locked',
            'active',
            0,
            'redistribute',
            0,
        ]);

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
        $insRoom->execute([
            $roomC,
            $makerC,
            'education',
            'Frais de scolarité (démo)',
            'A',
            'private',
            3,
            2,
            3,
            '15000.00',
            'monthly',
            demoSeedNow('+20 days'),
            demoSeedNow('+110 days'),
            'open',
            'lobby',
            1,
            'refund_minus_fee',
            0,
        ]);

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
        $insRoom->execute([
            $roomD,
            $makerD,
            'emergency',
            'Caisse urgence (démo)',
            'A',
            'unlisted',
            1,
            2,
            4,
            '3000.00',
            'weekly',
            demoSeedNow('-50 days'),
            demoSeedNow('-5 days'),
            'locked',
            'closed',
            1,
            'redistribute',
            0,
        ]);

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

            if ($insTrust) {
                $db->prepare('UPDATE user_trust SET completed_reveals_count = completed_reveals_count + 1 WHERE user_id IN (' . implode(',', array_fill(0, count($completed), '?')) . ')')
                   ->execute(array_values(array_map('intval', $completed)));
            }
        }

        // Room Swap (public, swap window Type B)
        if ($has('saving_rooms', 'swap_window_ends_at') && $has('saving_room_slot_swaps')) {
            $roomSwap = demoSeedGenerateUuid();
            $makerSwap = $idByEmail['komla.afi@example.com'];
            $insRoom->execute([
                $roomSwap,
                $makerSwap,
                'community',
                'Fenêtre d’échange des positions (démo)',
                'B',
                'public',
                2,
                4,
                6,
                '6000.00',
                'weekly',
                demoSeedNow('-2 hours'),
                demoSeedNow('+40 days'),
                'locked',
                'swap_window',
                0,
                'redistribute',
                0,
            ]);

            $db->prepare('UPDATE saving_rooms SET swap_window_ends_at = ? WHERE id = ?')->execute([demoSeedNow('+8 hours'), $roomSwap]);

            $participantsSwap = [
                [$makerSwap, 'active'],
                [$idByEmail['dela.tete@example.com'], 'active'],
                [$idByEmail['yaovi.tchalla@example.com'], 'active'],
                [$idByEmail['sessi.atakpama@example.com'], 'active'],
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

            if ($has('saving_room_slot_swaps', 'expires_at')) {
                $swapCols = ['room_id','from_user_id','to_user_id','status','expires_at'];
                if ($has('saving_room_slot_swaps', 'responded_at')) $swapCols[] = 'responded_at';
                if ($has('saving_room_slot_swaps', 'updated_at')) $swapCols[] = 'updated_at';

                $swapSql = 'INSERT INTO saving_room_slot_swaps (' . implode(', ', $swapCols) . ') VALUES (' . implode(', ', array_fill(0, count($swapCols), '?')) . ')';
                $insSwap = $db->prepare($swapSql);

                $insertSwap = function(int $fromId, int $toId, string $status, string $expiresAt, ?string $respondedAt) use ($insSwap, $swapCols, $roomSwap): void {
                    $vals = [];
                    foreach ($swapCols as $c) {
                        if ($c === 'room_id') $vals[] = $roomSwap;
                        else if ($c === 'from_user_id') $vals[] = $fromId;
                        else if ($c === 'to_user_id') $vals[] = $toId;
                        else if ($c === 'status') $vals[] = $status;
                        else if ($c === 'expires_at') $vals[] = $expiresAt;
                        else if ($c === 'responded_at') $vals[] = $respondedAt;
                        else if ($c === 'updated_at') $vals[] = $respondedAt;
                        else $vals[] = null;
                    }
                    $insSwap->execute($vals);
                };

                // Pending + decided + expired swap requests
                $insertSwap((int)$participantsSwap[0][0], (int)$participantsSwap[1][0], 'pending', demoSeedNow('+6 hours'), null);
                $insertSwap((int)$participantsSwap[2][0], (int)$participantsSwap[3][0], 'accepted', demoSeedNow('+6 hours'), demoSeedNow('-1 hour'));
                $insertSwap((int)$participantsSwap[1][0], (int)$participantsSwap[2][0], 'declined', demoSeedNow('+6 hours'), demoSeedNow('-2 hours'));
                $insertSwap((int)$participantsSwap[3][0], (int)$participantsSwap[0][0], 'expired', demoSeedNow('-1 hour'), null);
            }

            if ($has('saving_room_activity')) {
                $act = $db->prepare('INSERT INTO saving_room_activity (room_id, event_type, public_payload_json, created_at) VALUES (?, ?, ?, NOW())');
                $act->execute([$roomSwap, 'swap_window_started', json_encode(['demo' => 1], JSON_UNESCAPED_UNICODE)]);
                $act->execute([$roomSwap, 'slot_swap_requested', json_encode(['demo' => 1], JSON_UNESCAPED_UNICODE)]);
            }
        }

        // Room Unlock A (public, active Type A near unlock/reveal)
        if ($has('saving_room_unlock_events') && $has('saving_room_unlock_votes')) {
            $roomUnlockA = demoSeedGenerateUuid();
            $makerU = $makerA;
            $insRoom->execute([
                $roomUnlockA,
                $makerU,
                'business',
                'Déverrouillage Type A (votes) (démo)',
                'A',
                'public',
                1,
                3,
                5,
                '8000.00',
                'weekly',
                demoSeedNow('-20 days'),
                demoSeedNow('-1 day'),
                'locked',
                'active',
                1,
                'redistribute',
                0,
            ]);

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
                    else if ($c === 'target_rotation_index') $vals[] = null;
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
            if ($has('saving_room_rotation_windows', 'revealed_at')) $winCols[] = 'revealed_at';
            if ($has('saving_room_rotation_windows', 'expires_at')) $winCols[] = 'expires_at';
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

            $vals = [];
            foreach ($winCols as $c) {
                if ($c === 'room_id') $vals[] = $roomB;
                else if ($c === 'user_id') $vals[] = $roomBActiveUser;
                else if ($c === 'rotation_index') $vals[] = $roomBRotationIndex;
                else if ($c === 'status') $vals[] = 'revealed';
                else if ($c === 'revealed_at') $vals[] = demoSeedNow('-3 hours');
                else if ($c === 'expires_at') $vals[] = demoSeedNow('+60 hours');
                else if ($c === 'dispute_window_ends_at') $vals[] = demoSeedNow('+21 hours');
                else if ($c === 'created_at') $vals[] = demoSeedNow('-7 days');
                else $vals[] = null;
            }
            $window->execute($vals);
        }

        if ($has('saving_room_unlock_votes')) {
            $voteCols = ['room_id','user_id','scope','target_rotation_index','vote'];
            if ($has('saving_room_unlock_votes', 'created_at')) $voteCols[] = 'created_at';
            if ($has('saving_room_unlock_votes', 'updated_at')) $voteCols[] = 'updated_at';
            $voteSql = 'INSERT IGNORE INTO saving_room_unlock_votes (' . implode(', ', $voteCols) . ') VALUES (' . implode(', ', array_fill(0, count($voteCols), '?')) . ')';
            $insVote = $db->prepare($voteSql);

            foreach ($participantsB as $i => $p) {
                $vote = ($i === 2) ? 'reject' : 'approve';
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
        }

        if ($has('saving_room_disputes') && $has('saving_room_dispute_ack') && $has('saving_room_rotation_windows')) {
            $dispCols = ['room_id','rotation_index','raised_by_user_id','reason','status','threshold_count_required'];
            if ($has('saving_room_disputes', 'created_at')) $dispCols[] = 'created_at';
            if ($has('saving_room_disputes', 'updated_at')) $dispCols[] = 'updated_at';

            $dispSql = 'INSERT INTO saving_room_disputes (' . implode(', ', $dispCols) . ') VALUES (' . implode(', ', array_fill(0, count($dispCols), '?')) . ')';
            $insDisp = $db->prepare($dispSql);

            $raiser = (int)$participantsB[2][0];
            $dVals = [];
            foreach ($dispCols as $c) {
                if ($c === 'room_id') $dVals[] = $roomB;
                else if ($c === 'rotation_index') $dVals[] = $roomBRotationIndex;
                else if ($c === 'raised_by_user_id') $dVals[] = $raiser;
                else if ($c === 'reason') $dVals[] = 'Demo dispute (rotation eligibility)';
                else if ($c === 'status') $dVals[] = 'escalated_admin';
                else if ($c === 'threshold_count_required') $dVals[] = 2;
                else if ($c === 'created_at') $dVals[] = demoSeedNow('-90 minutes');
                else if ($c === 'updated_at') $dVals[] = demoSeedNow('-60 minutes');
                else $dVals[] = null;
            }
            $insDisp->execute($dVals);
            $disputeId = (int)$db->lastInsertId();

            if ($disputeId > 0) {
                $db->prepare('INSERT IGNORE INTO saving_room_dispute_ack (dispute_id, user_id) VALUES (?, ?)')->execute([$disputeId, $raiser]);
                $db->prepare('INSERT IGNORE INTO saving_room_dispute_ack (dispute_id, user_id) VALUES (?, ?)')->execute([$disputeId, (int)$participantsB[3][0]]);

                $db->prepare("UPDATE saving_room_rotation_windows SET status='blocked_dispute' WHERE room_id = ? AND rotation_index = ? AND status IN ('revealed','pending_votes','blocked_dispute')")
                   ->execute([$roomB, $roomBRotationIndex]);

                if ($has('saving_room_activity')) {
                    $act = $db->prepare('INSERT INTO saving_room_activity (room_id, event_type, public_payload_json, created_at) VALUES (?, ?, ?, NOW())');
                    $act->execute([$roomB, 'dispute_raised', json_encode(['dispute_id' => $disputeId, 'rotation_index' => $roomBRotationIndex, 'demo' => 1], JSON_UNESCAPED_UNICODE)]);
                    $act->execute([$roomB, 'rotation_blocked_dispute', json_encode(['rotation_index' => $roomBRotationIndex, 'demo' => 1], JSON_UNESCAPED_UNICODE)]);
                }
            }
        }

        if ($has('saving_room_exit_requests')) {
            $exCols = ['room_id','requested_by_user_id','status'];
            if ($has('saving_room_exit_requests', 'created_at')) $exCols[] = 'created_at';

            $exSql = 'INSERT INTO saving_room_exit_requests (' . implode(', ', $exCols) . ') VALUES (' . implode(', ', array_fill(0, count($exCols), '?')) . ')';
            $insEx = $db->prepare($exSql);

            $exVals = [];
            foreach ($exCols as $c) {
                if ($c === 'room_id') $exVals[] = $roomB;
                else if ($c === 'requested_by_user_id') $exVals[] = (int)$participantsB[3][0];
                else if ($c === 'status') $exVals[] = 'open';
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

                foreach ($participantsB as $i => $p) {
                    $vote = ($i === 1) ? 'reject' : 'approve';
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
                }
            }
        }

        if ($has('saving_room_contribution_cycles') && $has('saving_room_contributions')) {
            $insCycle = $db->prepare('INSERT IGNORE INTO saving_room_contribution_cycles (room_id, cycle_index, due_at, grace_ends_at, status, created_at)
                                      VALUES (?, ?, ?, ?, ?, NOW())');
            $insCycle->execute([$roomB, 1, demoSeedNow('-1 day'), demoSeedNow('+2 days'), 'grace']);
            $insCycle->execute([$roomB, 2, demoSeedNow('+6 days'), demoSeedNow('+9 days'), 'open']);

            $cycleIdStmt = $db->prepare('SELECT id FROM saving_room_contribution_cycles WHERE room_id = ? AND cycle_index = ?');
            $cycleIdStmt->execute([$roomB, 1]);
            $cycle1 = (int)$cycleIdStmt->fetchColumn();

            if ($cycle1 > 0) {
                $insContrib = $db->prepare("INSERT INTO saving_room_contributions (room_id, user_id, cycle_id, amount, status, reference, confirmed_at, created_at)
                                            VALUES (?, ?, ?, ?, ?, ?, ?, NOW())
                                            ON DUPLICATE KEY UPDATE amount=VALUES(amount), status=VALUES(status), reference=VALUES(reference), confirmed_at=VALUES(confirmed_at)");

                // Mix of paid / missed
                $insContrib->execute([$roomB, (int)$makerB, $cycle1, '5000.00', 'paid', 'DEMO-PAID-001', demoSeedNow('-12 hours')]);
                $insContrib->execute([$roomB, (int)$participantsB[1][0], $cycle1, '5000.00', 'paid_in_grace', 'DEMO-PAID-002', demoSeedNow('-2 hours')]);
                $insContrib->execute([$roomB, (int)$participantsB[2][0], $cycle1, '5000.00', 'unpaid', null, null]);
                $insContrib->execute([$roomB, (int)$participantsB[3][0], $cycle1, '5000.00', 'unpaid', null, null]);
                $insContrib->execute([$roomB, (int)$participantsB[4][0], $cycle1, '5000.00', 'paid', 'DEMO-PAID-003', demoSeedNow('-10 hours')]);
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
                    else if ($c === 'unlock_code_enc') $vals[] = 'demo_enc_' . bin2hex(random_bytes(18));
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

    $db->commit();

    $out['seeded'] = 1;
    return $out;
}
