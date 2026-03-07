<?php
// ============================================================
//  API: /api/notifications.php
//  In-app notifications inbox.
//   - GET  ?action=list
//   - POST {action: mark_read}
// ============================================================

require_once __DIR__ . '/../includes/install_guard.php';
requireInstalledForApi();

require_once __DIR__ . '/../includes/helpers.php';
header('Content-Type: application/json; charset=utf-8');
registerApiErrorHandling();
startSecureSession();

requireLogin();
requireVerifiedEmail();

$db = getDB();
$userId = (int)(getCurrentUserId() ?? 0);
if ($userId < 1) jsonResponse(['error' => 'Unauthorized'], 401);

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $action = (string)($_GET['action'] ?? '');
    if ($action !== 'list') jsonResponse(['error' => 'Unknown action'], 400);

    $beforeId = (int)($_GET['before_id'] ?? 0);
    $limit = (int)($_GET['limit'] ?? 50);
    if ($limit < 1) $limit = 1;
    if ($limit > 200) $limit = 200;

    // Unread count
    $u = $db->prepare("SELECT COUNT(*) FROM notifications WHERE user_id = ? AND read_at IS NULL");
    $u->execute([$userId]);
    $unreadCount = (int)$u->fetchColumn();

    $sql = "SELECT id, tier, title, body, data_json, created_at, read_at
            FROM notifications
            WHERE user_id = ?";
    $params = [$userId];

    if ($beforeId > 0) {
        $sql .= " AND id < ?";
        $params[] = $beforeId;
    }

    $sql .= " ORDER BY id DESC LIMIT ?";

    $stmt = $db->prepare($sql);
    $stmt->bindValue(1, $userId, PDO::PARAM_INT);
    $bindIdx = 2;
    if ($beforeId > 0) {
        $stmt->bindValue($bindIdx, $beforeId, PDO::PARAM_INT);
        $bindIdx++;
    }
    $stmt->bindValue($bindIdx, $limit, PDO::PARAM_INT);

    $stmt->execute();

    $rows = [];
    foreach ($stmt->fetchAll() as $r) {
        $rows[] = [
            'id' => (int)$r['id'],
            'tier' => $r['tier'],
            'title' => $r['title'],
            'body' => $r['body'],
            'data' => $r['data_json'] ? json_decode((string)$r['data_json'], true) : null,
            'created_at' => $r['created_at'],
            'read_at' => $r['read_at'],
        ];
    }

    jsonResponse(['success' => true, 'unread_count' => $unreadCount, 'notifications' => $rows]);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    requireCsrf();

    $body = json_decode(file_get_contents('php://input'), true);
    $action = (string)($body['action'] ?? '');

    if ($action === 'mark_read') {
        $ids = $body['ids'] ?? [];
        $all = !empty($body['all']);

        if ($all) {
            $db->prepare('UPDATE notifications SET read_at = NOW() WHERE user_id = ? AND read_at IS NULL')
               ->execute([$userId]);
            jsonResponse(['success' => true]);
        }

        if (!is_array($ids) || count($ids) < 1) jsonResponse(['error' => 'ids required'], 400);
        if (count($ids) > 200) jsonResponse(['error' => 'Too many ids'], 400);

        $clean = [];
        foreach ($ids as $id) {
            $n = (int)$id;
            if ($n > 0) $clean[] = $n;
        }
        if (!$clean) jsonResponse(['error' => 'ids required'], 400);

        $placeholders = implode(',', array_fill(0, count($clean), '?'));
        $params = array_merge([$userId], $clean);

        $db->prepare("UPDATE notifications SET read_at = NOW()
                      WHERE user_id = ?
                        AND id IN ({$placeholders})")
           ->execute($params);

        jsonResponse(['success' => true]);
    }

    jsonResponse(['error' => 'Unknown action'], 400);
}

jsonResponse(['error' => 'Method not allowed'], 405);
