<?php
require_once __DIR__ . '/includes/install_guard.php';
requireInstalledForPage();

require_once __DIR__ . '/includes/helpers.php';
startSecureSession();

if (!isLoggedIn()) {
    header('Location: login.php');
    exit;
}

if (!isEmailVerified()) {
    header('Location: account.php');
    exit;
}

if (!isAdmin()) {
    header('Location: dashboard.php');
    exit;
}

$userEmail = getCurrentUserEmail() ?? '';
$csrf      = getCsrfToken();

header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none';");
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: no-referrer");
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Admin — LOCKSMITH</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@300;400;500&family=Unbounded:wght@400;700;900&display=swap" rel="stylesheet">
<link rel="stylesheet" href="assets/base.css">
<link rel="stylesheet" href="assets/panel.css">
<link rel="stylesheet" href="assets/panel_components.css">
<style>
.orb{filter:blur(120px);}
.orb1{width:520px;height:520px;top:-170px;right:-120px;}
.orb2{width:360px;height:360px;bottom:40px;left:-90px;}

.pill{font-size:10px;color:var(--muted);letter-spacing:1px;border:1px solid rgba(255,255,255,.13);padding:6px 10px;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.badge{font-size:10px;letter-spacing:2px;text-transform:uppercase;border:1px solid rgba(232,255,71,.25);color:var(--accent);padding:6px 10px;}

.wrap{max-width:1200px;}
.h{font-size:18px;} 
.chk{display:flex;align-items:center;gap:10px;color:var(--muted);font-size:12px;line-height:1.4;margin:12px 0;}
.chk input{width:16px;height:16px;}
 
.table-wrap{overflow:auto;border:1px solid var(--b1);background:rgba(0,0,0,.2);}
.table{width:100%;border-collapse:collapse;min-width:980px;}
.table th,.table td{padding:10px 12px;border-bottom:1px solid rgba(255,255,255,.06);text-align:left;font-size:12px;white-space:nowrap;}
.table th{color:var(--muted);font-size:10px;letter-spacing:2px;text-transform:uppercase;background:rgba(0,0,0,.25);}
.k{color:var(--muted);} 
hr{border:none;border-top:1px solid var(--b1);margin:16px 0;}
.modal{position:fixed;inset:0;background:rgba(0,0,0,.92);display:none;align-items:center;justify-content:center;z-index:999;padding:24px;}
.modal.show{display:flex;}
.sheet{width:100%;max-width:980px;background:var(--s1);border:1px solid var(--b2);padding:18px;max-height:85vh;overflow:auto;}
.sheet h3{font-family:var(--display);font-size:14px;margin-bottom:10px;}
pre{white-space:pre-wrap;word-break:break-word;background:#000;border:1px solid rgba(255,255,255,.08);padding:12px;color:rgba(255,255,255,.82);font-size:12px;line-height:1.6;}
</style>
</head>
<body>
<div class="orb orb1"></div><div class="orb orb2"></div>

<div class="nav">
  <a class="logo" href="index.php">LOCK<span>SMITH</span></a>
  <div class="nav-r">
    <span class="badge">SUPER ADMIN</span>
    <span class="pill"><?= htmlspecialchars($userEmail) ?></span>
    <a class="btn btn-ghost btn-sm" href="dashboard.php">Dashboard</a>
    <a class="btn btn-ghost btn-sm" href="notifications.php">Notifications</a>
    <a class="btn btn-ghost btn-sm" href="account.php">Account</a>
    <a class="btn btn-ghost btn-sm" href="logout.php">Logout</a>
  </div>
</div>

<div class="wrap">
  <div class="h">Admin Dashboard</div>
  <div class="p">Manage users and all codes (encrypted blobs + metadata). Decryption is still impossible without a user’s vault passphrase.</div>

  <div class="grid">
    <div class="card">
      <div class="card-title">Users</div>
      <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px;">
        <button class="btn btn-ghost btn-sm" onclick="loadUsers()">↻ Refresh</button>
      </div>
      <div class="table-wrap">
        <table class="table" id="users-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Email</th>
              <th>Verified</th>
              <th>Admin</th>
              <th>Codes</th>
              <th>Created</th>
              <th>Last login</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody></tbody>
        </table>
      </div>
      <div id="users-msg" class="msg"></div>
    </div>

    <div class="card">
      <div class="card-title">Add user</div>
      <div class="field"><label>Email</label><input id="nu-email" type="email" placeholder="user@example.com" autocomplete="off"></div>
      <div class="field"><label>Login password</label><input id="nu-login" type="password" placeholder="min 8 chars" autocomplete="new-password"></div>
      

      <label class="chk"><input type="checkbox" id="nu-verified"> <span>Mark email as verified (skip email verification)</span></label>
      <label class="chk"><input type="checkbox" id="nu-admin"> <span>Make this user an admin</span></label>

      <button class="btn btn-primary" onclick="createUser()">Create user</button>
      <div id="nu-msg" class="msg"></div>
      <div id="nu-dev" class="msg" style="display:none;background:rgba(255,170,0,.06);border:1px solid rgba(255,170,0,.25);color:var(--muted);"></div>

      <hr>
      <div class="p" style="margin:0;">
        For zero-knowledge integrity, the user should choose their own vault passphrase.
        In strong security mode, vault passphrases are never sent to the server.
      </div>
    </div>
  </div>

  <div class="card" style="margin-top:14px;">
    <div class="card-title">Codes</div>

    <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:12px;">
      <div class="field" style="margin:0;min-width:240px;flex:1;">
        <label>Search (email or label)</label>
        <input id="codes-q" placeholder="e.g. alice@ / bank" onkeydown="if(event.key==='Enter')loadCodes()">
      </div>
      <label class="chk" style="margin:0;"><input type="checkbox" id="codes-inactive"> <span>Include inactive</span></label>
      <button class="btn btn-ghost btn-sm" onclick="loadCodes()">↻ Refresh</button>
    </div>

    <div class="table-wrap">
      <table class="table" id="codes-table">
        <thead>
          <tr>
            <th>ID</th>
            <th>User</th>
            <th>Label</th>
            <th>Status</th>
            <th>Reveal</th>
            <th>Created</th>
            <th>Copied</th>
            <th>Confirmed</th>
            <th>Revealed</th>
            <th>Active</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody></tbody>
      </table>
    </div>
    <div id="codes-msg" class="msg"></div>
  </div>

  <div class="card" style="margin-top:14px;">
    <div class="card-title">Carriers (Mobile Money)</div>

    <div class="p">Define carrier PIN policy and USSD templates. Placeholders: <code>{old_pin}</code>, <code>{new_pin}</code>.</div>

    <div style="display:grid;grid-template-columns:1fr;gap:12px;margin-bottom:12px;">
      <div class="field"><label>Name</label><input id="car-name" placeholder="e.g. MTN MoMo"></div>
      <div class="field"><label>Country (optional)</label><input id="car-country" placeholder="e.g. GH"></div>
      <div class="field"><label>PIN type</label><input id="car-pin-type" placeholder="numeric or alphanumeric" value="numeric"></div>
      <div class="field"><label>PIN length</label><input id="car-pin-len" placeholder="e.g. 4" value="4"></div>
      <div class="field"><label>USSD: Change PIN template</label><input id="car-ussd-change" placeholder="e.g. *170*00*{old_pin}*{new_pin}#"></div>
      <div class="field"><label>USSD: Balance template</label><input id="car-ussd-balance" placeholder="e.g. *170#"></div>
      <label class="chk" style="margin:0;"><input type="checkbox" id="car-active" checked> <span>Active</span></label>
      <button class="btn btn-primary" onclick="createCarrier()">Add carrier</button>
      <div id="car-msg" class="msg"></div>
    </div>

    <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px;">
      <button class="btn btn-ghost btn-sm" onclick="loadCarriers()">↻ Refresh</button>
    </div>

    <div class="table-wrap">
      <table class="table" id="carriers-table" style="min-width:1100px;">
        <thead>
          <tr>
            <th>ID</th>
            <th>Name</th>
            <th>Country</th>
            <th>PIN</th>
            <th>Active</th>
            <th>Balance USSD</th>
            <th>Change PIN USSD</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody></tbody>
      </table>
    </div>
    <div id="carriers-msg" class="msg"></div>
  </div>

  <div class="card" style="margin-top:14px;">
    <div class="card-title">Destination accounts (Saving Rooms)</div>
    <div class="p">These accounts receive deposits for saving rooms. Unlock codes are stored encrypted and are only revealed to participants after consensus.</div>

    <div style="display:grid;grid-template-columns:1fr;gap:12px;margin-bottom:12px;">
      <div class="field">
        <label>Account type</label>
        <input id="da-type" placeholder="mobile_money or bank" value="mobile_money">
      </div>

      <div class="field">
        <label>Carrier ID (mobile money)</label>
        <input id="da-carrier" placeholder="e.g. 1">
      </div>
      <div class="field">
        <label>Mobile money number</label>
        <input id="da-mm" placeholder="e.g. +233...">
      </div>

      <div class="field">
        <label>Bank name</label>
        <input id="da-bank" placeholder="e.g. ABC Bank">
      </div>
      <div class="field">
        <label>Bank account name (optional)</label>
        <input id="da-bank-name" placeholder="e.g. LOCKSMITH ESCROW">
      </div>
      <div class="field">
        <label>Bank account number</label>
        <input id="da-bank-num" placeholder="e.g. 1234567890">
      </div>

      <div class="field">
        <label>Unlock code</label>
        <input id="da-code" placeholder="PIN / password / passphrase">
      </div>

      <label class="chk" style="margin:0;"><input type="checkbox" id="da-active" checked> <span>Active</span></label>

      <div style="display:flex;gap:10px;flex-wrap:wrap;">
        <button class="btn btn-primary" onclick="createDestinationAccount()">Create destination account</button>
        <button class="btn btn-ghost btn-sm" onclick="loadDestinationAccounts()">↻ Refresh</button>
      </div>
      <div id="da-msg" class="msg"></div>
    </div>

    <div class="table-wrap">
      <table class="table" id="da-table" style="min-width:1100px;">
        <thead>
          <tr>
            <th>ID</th>
            <th>Type</th>
            <th>Details</th>
            <th>Rotated</th>
            <th>Version</th>
            <th>Active</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody></tbody>
      </table>
    </div>
  </div>

  <div class="card" style="margin-top:14px;">
    <div class="card-title">Escrow settlements (Saving Rooms)</div>
    <div class="p">Operational queue for refunds / redistribution after removals (strikes) or approved exits. Settlements are recorded automatically; mark them processed after handling them off-platform.</div>

    <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:12px;">
      <label class="chk" style="margin:0;"><input type="checkbox" id="esc-inc"> <span>Include processed</span></label>
      <button class="btn btn-ghost btn-sm" onclick="loadEscrowSettlements()">↻ Refresh</button>
    </div>

    <div class="table-wrap">
      <table class="table" id="esc-table" style="min-width:1200px;">
        <thead>
          <tr>
            <th>ID</th>
            <th>Room</th>
            <th>Removed user</th>
            <th>Policy</th>
            <th>Total</th>
            <th>Fee</th>
            <th>Refund</th>
            <th>Status</th>
            <th>Created</th>
            <th>Processed</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody></tbody>
      </table>
    </div>
    <div id="esc-msg" class="msg"></div>
  </div>

  <div class="card" style="margin-top:14px;">
    <div class="card-title">Disputes (Saving Rooms)</div>
    <div class="p">Type B disputes that reached a review state (or are open). Validated disputes advance the rotation; dismissed disputes apply a false-dispute strike.</div>

    <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:12px;">
      <label class="chk" style="margin:0;"><input type="checkbox" id="disp-inc"> <span>Include resolved</span></label>
      <button class="btn btn-ghost btn-sm" onclick="loadDisputes()">↻ Refresh</button>
    </div>

    <div class="table-wrap">
      <table class="table" id="disp-table" style="min-width:1100px;">
        <thead>
          <tr>
            <th>ID</th>
            <th>Room</th>
            <th>Rotation</th>
            <th>Status</th>
            <th>Acks</th>
            <th>Raised by</th>
            <th>Created</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody></tbody>
      </table>
    </div>
    <div id="disp-msg" class="msg"></div>
  </div>

  <div class="card" style="margin-top:14px;">
    <div class="card-title">Audit log</div>

    <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:12px;">
      <div class="field" style="margin:0;min-width:240px;flex:1;">
        <label>Search (email / action / lock id)</label>
        <input id="audit-q" placeholder="e.g. login / admin_delete" onkeydown="if(event.key==='Enter')loadAudit()">
      </div>
      <button class="btn btn-ghost btn-sm" onclick="loadAudit()">↻ Refresh</button>
    </div>

    <div class="table-wrap">
      <table class="table" id="audit-table">
        <thead>
          <tr>
            <th>When</th>
            <th>User</th>
            <th>Action</th>
            <th>Lock</th>
            <th>IP</th>
            <th>User agent</th>
          </tr>
        </thead>
        <tbody></tbody>
      </table>
    </div>
    <div id="audit-msg" class="msg"></div>
  </div>
</div>

<div class="modal" id="detail-modal" onclick="closeDetail(event)">
  <div class="sheet">
    <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:10px;">
      <h3 style="margin:0;">Code detail</h3>
      <button class="btn btn-ghost btn-sm" onclick="closeDetail()">Close</button>
    </div>
    <pre id="detail-pre"></pre>
  </div>
</div>

<div class="modal" id="escrow-modal" onclick="closeEscrowDetail(event)">
  <div class="sheet">
    <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:10px;">
      <h3 style="margin:0;">Escrow settlement detail</h3>
      <button class="btn btn-ghost btn-sm" onclick="closeEscrowDetail()">Close</button>
    </div>
    <pre id="escrow-pre"></pre>
  </div>
</div>

<div class="modal" id="carrier-modal" onclick="closeCarrierModal(event)">
  <div class="sheet">
    <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:10px;">
      <h3 style="margin:0;">Edit carrier</h3>
      <button class="btn btn-ghost btn-sm" onclick="closeCarrierModal()">Close</button>
    </div>

    <input type="hidden" id="car-edit-id">
    <div class="field"><label>Name</label><input id="car-edit-name"></div>
    <div class="field"><label>Country (optional)</label><input id="car-edit-country"></div>
    <div class="field"><label>PIN type</label><input id="car-edit-pin-type" placeholder="numeric or alphanumeric"></div>
    <div class="field"><label>PIN length</label><input id="car-edit-pin-len"></div>
    <div class="field"><label>USSD: Change PIN template</label><input id="car-edit-ussd-change"></div>
    <div class="field"><label>USSD: Balance template</label><input id="car-edit-ussd-balance"></div>
    <label class="chk" style="margin:0;"><input type="checkbox" id="car-edit-active"> <span>Active</span></label>

    <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:14px;">
      <button class="btn btn-primary" onclick="saveCarrierEdit()">Save</button>
      <button class="btn btn-ghost" onclick="closeCarrierModal()">Cancel</button>
    </div>
    <div id="car-edit-msg" class="msg"></div>
  </div>
</div>

<script>
const CSRF = <?= json_encode($csrf) ?>;

function apiUrl(url){
  return url.startsWith('/') ? url.slice(1) : url;
}
async function get(url){
  const r = await fetch(apiUrl(url), { credentials: 'same-origin' });
  return r.json();
}
async function postCsrf(url, body){
  const r = await fetch(apiUrl(url), {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': CSRF },
    body: JSON.stringify(body),
  });
  return r.json();
}

function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function fmt(ts){
  if(!ts) return '';
  try{ return new Date(ts).toLocaleString(); }catch{ return String(ts); }
}
function setMsg(id, text, ok){
  const el = document.getElementById(id);
  if(!el) return;
  el.className = 'msg ' + (ok ? 'msg-ok' : 'msg-err') + ' show';
  el.textContent = text;
}

let usersCache = [];
let carriersCache = [];
let destAccountsCache = [];

async function loadUsers(){
  const tbody = document.querySelector('#users-table tbody');
  tbody.innerHTML = '<tr><td colspan="8" class="k">Loading…</td></tr>';

  try{
    const r = await get('/api/admin.php?action=users');
    if(!r.success) throw new Error(r.error||'Failed');
    usersCache = r.users || [];

    if(!usersCache.length){
      tbody.innerHTML = '<tr><td colspan="8" class="k">No users.</td></tr>';
      return;
    }

    tbody.innerHTML = '';
    usersCache.forEach(u => {
      const tr = document.createElement('tr');
      const verified = u.email_verified_at ? '✓' : '—';
      const admin = u.is_admin ? '✓' : '—';
      const codes = `${u.codes_active||0}/${u.codes_total||0}`;

      tr.innerHTML = `
        <td>${u.id}</td>
        <td>${esc(u.email)}</td>
        <td>${verified}</td>
        <td>${admin}</td>
        <td>${codes}</td>
        <td>${fmt(u.created_at)}</td>
        <td>${fmt(u.last_login)}</td>
        <td>
          <button class="btn btn-blue btn-sm" onclick="toggleVerified(${u.id}, ${u.email_verified_at?1:0})">Verify</button>
          <button class="btn btn-blue btn-sm" onclick="toggleAdmin(${u.id}, ${u.is_admin?1:0})">Admin</button>
          <button class="btn btn-red btn-sm" onclick="deleteUser(${u.id}, ${JSON.stringify(u.email)})">Delete</button>
        </td>
      `;
      tbody.appendChild(tr);
    });

  }catch(e){
    tbody.innerHTML = '<tr><td colspan="8" class="k">Failed to load users.</td></tr>';
    setMsg('users-msg', e.message||'Failed', false);
  }
}

async function createUser(){
  const email = document.getElementById('nu-email').value.trim();
  const login = document.getElementById('nu-login').value;
  const markVerified = document.getElementById('nu-verified').checked;
  const isAdmin = document.getElementById('nu-admin').checked;

  document.getElementById('nu-msg').className = 'msg';
  document.getElementById('nu-dev').style.display = 'none';

  try{
    const r = await postCsrf('/api/admin.php', {
      action: 'create_user',
      email,
      login_password: login,
      mark_verified: markVerified ? 1 : 0,
      is_admin: isAdmin ? 1 : 0,
    });
    if(!r.success) throw new Error(r.error||'Failed');

    setMsg('nu-msg', 'User created.', true);
    document.getElementById('nu-email').value='';
    document.getElementById('nu-login').value='';

    if(r.dev_verify_url){
      const d = document.getElementById('nu-dev');
      d.style.display = 'block';
      d.className = 'msg show';
      d.innerHTML = `DEV verify URL: <a href="${esc(r.dev_verify_url)}">${esc(r.dev_verify_url)}</a>`;
    }

    loadUsers();

  }catch(e){
    setMsg('nu-msg', e.message||'Failed', false);
  }
}

async function toggleAdmin(userId, cur){
  const next = cur ? 0 : 1;
  const ok = confirm(next ? 'Grant admin access?' : 'Remove admin access?');
  if(!ok) return;

  const r = await postCsrf('/api/admin.php', { action: 'set_admin', user_id: userId, is_admin: next });
  if(!r.success){ setMsg('users-msg', r.error||'Failed', false); return; }
  loadUsers();
}

async function toggleVerified(userId, cur){
  const next = cur ? 0 : 1;
  const ok = confirm(next ? 'Mark this email as verified?' : 'Mark this email as unverified?');
  if(!ok) return;

  const r = await postCsrf('/api/admin.php', { action: 'set_verified', user_id: userId, verified: next });
  if(!r.success){ setMsg('users-msg', r.error||'Failed', false); return; }
  loadUsers();
}

async function deleteUser(userId, email){
  const ok = confirm(`Delete user ${email}? This will delete all their codes.`);
  if(!ok) return;

  const r = await postCsrf('/api/admin.php', { action: 'delete_user', user_id: userId });
  if(!r.success){ setMsg('users-msg', r.error||'Failed', false); return; }
  loadUsers();
  loadCodes();
}

async function loadCodes(){
  const q = document.getElementById('codes-q').value.trim();
  const includeInactive = document.getElementById('codes-inactive').checked ? 1 : 0;

  const tbody = document.querySelector('#codes-table tbody');
  tbody.innerHTML = '<tr><td colspan="11" class="k">Loading…</td></tr>';

  try{
    const qs = new URLSearchParams({ action:'codes', limit:'200', q, include_inactive: includeInactive ? '1' : '' });
    const r = await get('/api/admin.php?' + qs.toString());
    if(!r.success) throw new Error(r.error||'Failed');

    const codes = r.codes || [];
    if(!codes.length){
      tbody.innerHTML = '<tr><td colspan="11" class="k">No codes.</td></tr>';
      return;
    }

    tbody.innerHTML='';
    codes.forEach(c => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${esc(c.id)}</td>
        <td>${esc(c.user_email)}</td>
        <td>${esc(c.label)}</td>
        <td>${esc(c.confirmation_status)}</td>
        <td>${fmt(c.reveal_date)}</td>
        <td>${fmt(c.created_at)}</td>
        <td>${fmt(c.copied_at)}</td>
        <td>${fmt(c.confirmed_at)}</td>
        <td>${fmt(c.revealed_at)}</td>
        <td>${c.is_active ? '✓' : '—'}</td>
        <td>
          <button class="btn btn-blue btn-sm" onclick="openDetail(${JSON.stringify(c.id)})">Detail</button>
          <button class="btn btn-red btn-sm" onclick="deleteCode(${JSON.stringify(c.id)})">Delete</button>
        </td>
      `;
      tbody.appendChild(tr);
    });

  }catch(e){
    tbody.innerHTML = '<tr><td colspan="11" class="k">Failed to load codes.</td></tr>';
    setMsg('codes-msg', e.message||'Failed', false);
  }
}

async function deleteCode(lockId){
  const ok = confirm('Deactivate this code? It will disappear from the user dashboard.');
  if(!ok) return;
  const r = await postCsrf('/api/admin.php', { action: 'delete_code', lock_id: lockId });
  if(!r.success){ setMsg('codes-msg', r.error||'Failed', false); return; }
  loadCodes();
  loadUsers();
}

async function openDetail(lockId){
  const r = await get('/api/admin.php?action=code_detail&lock_id=' + encodeURIComponent(lockId));
  if(!r.success){ setMsg('codes-msg', r.error||'Failed', false); return; }
  document.getElementById('detail-pre').textContent = JSON.stringify(r.code, null, 2);
  document.getElementById('detail-modal').classList.add('show');
}

function closeDetail(e){
  if(e && e.target !== document.getElementById('detail-modal')) return;
  document.getElementById('detail-modal').classList.remove('show');
}

async function loadCarriers(){
  const tbody = document.querySelector('#carriers-table tbody');
  tbody.innerHTML = '<tr><td colspan="8" class="k">Loading…</td></tr>';

  try{
    const r = await get('/api/admin.php?action=carriers');
    if(!r.success) throw new Error(r.error||'Failed');
    carriersCache = r.carriers || [];

    if(!carriersCache.length){
      tbody.innerHTML = '<tr><td colspan="8" class="k">No carriers.</td></tr>';
      return;
    }

    tbody.innerHTML='';
    carriersCache.forEach(c => {
      const tr = document.createElement('tr');
      const pin = `${c.pin_type}/${c.pin_length}`;
      tr.innerHTML = `
        <td>${c.id}</td>
        <td>${esc(c.name)}</td>
        <td>${esc(c.country||'')}</td>
        <td>${esc(pin)}</td>
        <td>${c.is_active ? '✓' : '—'}</td>
        <td>${esc(c.ussd_balance_template||'')}</td>
        <td>${esc(c.ussd_change_pin_template||'')}</td>
        <td>
          <button class="btn btn-blue btn-sm" onclick="openCarrierEdit(${c.id})">Edit</button>
          <button class="btn btn-blue btn-sm" onclick="toggleCarrierActive(${c.id}, ${c.is_active?1:0})">Active</button>
        </td>
      `;
      tbody.appendChild(tr);
    });

  }catch(e){
    tbody.innerHTML = '<tr><td colspan="8" class="k">Failed to load carriers.</td></tr>';
    setMsg('carriers-msg', e.message||'Failed', false);
  }
}

async function createCarrier(){
  const name = document.getElementById('car-name').value.trim();
  const country = document.getElementById('car-country').value.trim();
  const pinType = document.getElementById('car-pin-type').value.trim() || 'numeric';
  const pinLen = parseInt(document.getElementById('car-pin-len').value || '0', 10);
  const ussdChange = document.getElementById('car-ussd-change').value.trim();
  const ussdBalance = document.getElementById('car-ussd-balance').value.trim();
  const isActive = document.getElementById('car-active').checked ? 1 : 0;

  document.getElementById('car-msg').className = 'msg';

  try{
    const r = await postCsrf('/api/admin.php', {
      action:'carrier_create',
      name,
      country,
      pin_type: pinType,
      pin_length: pinLen,
      ussd_change_pin_template: ussdChange,
      ussd_balance_template: ussdBalance,
      is_active: isActive,
    });
    if(!r.success) throw new Error(r.error||'Failed');

    setMsg('car-msg', 'Carrier added.', true);
    document.getElementById('car-name').value='';
    document.getElementById('car-country').value='';
    document.getElementById('car-ussd-change').value='';
    document.getElementById('car-ussd-balance').value='';

    loadCarriers();

  }catch(e){
    setMsg('car-msg', e.message||'Failed', false);
  }
}

function openCarrierEdit(id){
  const c = carriersCache.find(x => String(x.id) === String(id));
  if(!c) return;

  document.getElementById('car-edit-id').value = c.id;
  document.getElementById('car-edit-name').value = c.name || '';
  document.getElementById('car-edit-country').value = c.country || '';
  document.getElementById('car-edit-pin-type').value = c.pin_type || 'numeric';
  document.getElementById('car-edit-pin-len').value = c.pin_length || 4;
  document.getElementById('car-edit-ussd-change').value = c.ussd_change_pin_template || '';
  document.getElementById('car-edit-ussd-balance').value = c.ussd_balance_template || '';
  document.getElementById('car-edit-active').checked = !!c.is_active;

  document.getElementById('car-edit-msg').className = 'msg';
  document.getElementById('carrier-modal').classList.add('show');
}

function closeCarrierModal(e){
  if(e && e.target !== document.getElementById('carrier-modal')) return;
  document.getElementById('carrier-modal').classList.remove('show');
}

async function saveCarrierEdit(){
  const carrierId = parseInt(document.getElementById('car-edit-id').value || '0', 10);
  const name = document.getElementById('car-edit-name').value.trim();
  const country = document.getElementById('car-edit-country').value.trim();
  const pinType = document.getElementById('car-edit-pin-type').value.trim() || 'numeric';
  const pinLen = parseInt(document.getElementById('car-edit-pin-len').value || '0', 10);
  const ussdChange = document.getElementById('car-edit-ussd-change').value.trim();
  const ussdBalance = document.getElementById('car-edit-ussd-balance').value.trim();
  const isActive = document.getElementById('car-edit-active').checked ? 1 : 0;

  document.getElementById('car-edit-msg').className = 'msg';

  try{
    const r = await postCsrf('/api/admin.php', {
      action:'carrier_update',
      carrier_id: carrierId,
      name,
      country,
      pin_type: pinType,
      pin_length: pinLen,
      ussd_change_pin_template: ussdChange,
      ussd_balance_template: ussdBalance,
      is_active: isActive,
    });
    if(!r.success) throw new Error(r.error||'Failed');
    setMsg('car-edit-msg', 'Saved.', true);
    loadCarriers();
  }catch(e){
    setMsg('car-edit-msg', e.message||'Failed', false);
  }
}

async function toggleCarrierActive(id, cur){
  const next = cur ? 0 : 1;
  const ok = confirm(next ? 'Activate this carrier?' : 'Deactivate this carrier?');
  if(!ok) return;

  const r = await postCsrf('/api/admin.php', { action:'carrier_set_active', carrier_id: id, is_active: next });
  if(!r.success){ setMsg('carriers-msg', r.error||'Failed', false); return; }
  loadCarriers();
}

async function loadDestinationAccounts(){
  const tbody = document.querySelector('#da-table tbody');
  tbody.innerHTML = '<tr><td colspan="7" class="k">Loading…</td></tr>';
  document.getElementById('da-msg').className = 'msg';

  try{
    const r = await get('/api/admin.php?action=destination_accounts');
    if(!r.success) throw new Error(r.error||'Failed');
    destAccountsCache = r.accounts || [];

    if(!destAccountsCache.length){
      tbody.innerHTML = '<tr><td colspan="7" class="k">No destination accounts.</td></tr>';
      return;
    }

    tbody.innerHTML='';
    destAccountsCache.forEach(a => {
      const tr = document.createElement('tr');
      const details = (a.account_type === 'mobile_money')
        ? `carrier ${a.carrier_id||''} · ${a.mobile_money_number||''}`
        : `${a.bank_name||''} · ${a.bank_account_number||''}`;

      tr.innerHTML = `
        <td>${a.id}</td>
        <td>${esc(a.account_type)}</td>
        <td>${esc(details)}</td>
        <td>${fmt(a.code_rotated_at)}</td>
        <td>${esc(a.code_rotation_version||'')}</td>
        <td>${a.is_active ? '✓' : '—'}</td>
        <td>
          <button class="btn btn-blue btn-sm" onclick="rotateDestinationAccount(${a.id})">Rotate code</button>
          <button class="btn btn-blue btn-sm" onclick="toggleDestinationAccountActive(${a.id}, ${a.is_active?1:0})">Active</button>
        </td>
      `;
      tbody.appendChild(tr);
    });

  }catch(e){
    tbody.innerHTML = '<tr><td colspan="7" class="k">Failed to load destination accounts.</td></tr>';
    setMsg('da-msg', e.message||'Failed', false);
  }
}

let escrowCache = [];

async function loadEscrowSettlements(){
  const tbody = document.querySelector('#esc-table tbody');
  tbody.innerHTML = '<tr><td colspan="11" class="k">Loading…</td></tr>';
  document.getElementById('esc-msg').className = 'msg';

  try{
    const includeProcessed = document.getElementById('esc-inc').checked ? 1 : 0;
    const qs = new URLSearchParams({ action:'escrow_settlements', limit:'200', include_processed: includeProcessed ? '1' : '' });
    const r = await get('/api/admin.php?' + qs.toString());
    if(!r.success) throw new Error(r.error||'Failed');

    const rows = r.settlements || [];
    escrowCache = rows;

    if(!rows.length){
      tbody.innerHTML = '<tr><td colspan="11" class="k">No escrow settlements.</td></tr>';
      return;
    }

    tbody.innerHTML='';
    rows.forEach(s => {
      const tr = document.createElement('tr');
      const roomShort = (s.goal_text||'').slice(0,40) + ((s.goal_text||'').length>40?'…':'');
      const canProcess = (s.status === 'recorded');

      tr.innerHTML = `
        <td>${s.id}</td>
        <td title="${esc(s.goal_text||'')}">${esc(roomShort)}<div class="k" style="font-size:10px;">${esc(s.room_id)}</div></td>
        <td>${esc(s.removed_user_email||('User ' + s.removed_user_id))}</td>
        <td>${esc(s.policy)}</td>
        <td>${esc(s.total_contributed||'0.00')}</td>
        <td>${esc(s.platform_fee_amount||'0.00')}</td>
        <td>${esc(s.policy==='refund_minus_fee' ? (s.refund_amount||'0.00') : '—')}</td>
        <td>${esc(s.status||'')}</td>
        <td>${fmt(s.created_at)}</td>
        <td>${fmt(s.processed_at)}</td>
        <td>
          <button class="btn btn-blue btn-sm" onclick="openEscrowDetail(${s.id})">Detail</button>
          <button class="btn btn-primary btn-sm" onclick="markEscrowProcessed(${s.id})" ${canProcess?'':'disabled'}>Mark processed</button>
        </td>
      `;

      tbody.appendChild(tr);
    });

  }catch(e){
    tbody.innerHTML = '<tr><td colspan="11" class="k">Failed to load settlements.</td></tr>';
    setMsg('esc-msg', e.message||'Failed', false);
  }
}

function openEscrowDetail(id){
  const row = escrowCache.find(x => String(x.id) === String(id));
  if(!row) return;
  document.getElementById('escrow-pre').textContent = JSON.stringify(row, null, 2);
  document.getElementById('escrow-modal').classList.add('show');
}

function closeEscrowDetail(e){
  if(e && e.target !== document.getElementById('escrow-modal')) return;
  document.getElementById('escrow-modal').classList.remove('show');
}

async function markEscrowProcessed(id){
  document.getElementById('esc-msg').className = 'msg';

  const ok = confirm('Mark this escrow settlement as processed?');
  if(!ok) return;

  try{
    const r = await postCsrf('/api/admin.php', { action:'escrow_settlement_processed', settlement_id: id });
    if(!r.success) throw new Error(r.error||'Failed');

    setMsg('esc-msg', r.already_processed ? 'Already processed.' : 'Marked processed.', true);
    await loadEscrowSettlements();

  }catch(e){
    setMsg('esc-msg', e.message||'Failed', false);
  }
}

async function loadDisputes(){
  const tbody = document.querySelector('#disp-table tbody');
  tbody.innerHTML = '<tr><td colspan="8" class="k">Loading…</td></tr>';
  document.getElementById('disp-msg').className = 'msg';

  try{
    const includeResolved = document.getElementById('disp-inc').checked ? 1 : 0;
    const qs = new URLSearchParams({ action:'disputes', limit:'200', include_resolved: includeResolved ? '1' : '' });
    const r = await get('/api/admin.php?' + qs.toString());
    if(!r.success) throw new Error(r.error||'Failed');

    const rows = r.disputes || [];
    if(!rows.length){
      tbody.innerHTML = '<tr><td colspan="8" class="k">No disputes.</td></tr>';
      return;
    }

    tbody.innerHTML='';
    rows.forEach(d => {
      const tr = document.createElement('tr');
      const roomShort = (d.goal_text||'').slice(0,40) + ((d.goal_text||'').length>40?'…':'');
      const acks = `${d.ack_count||0}/${d.threshold_count_required||0}`;

      const canResolve = (d.status === 'open' || d.status === 'threshold_met' || d.status === 'escalated_admin');

      tr.innerHTML = `
        <td>${d.id}</td>
        <td title="${esc(d.goal_text||'')}">${esc(roomShort)}<div class="k" style="font-size:10px;">${esc(d.room_id)}</div></td>
        <td>#${esc(d.rotation_index)}</td>
        <td>${esc(d.status)}</td>
        <td>${esc(acks)}</td>
        <td>${esc(d.raised_by_email||'')}</td>
        <td>${fmt(d.created_at)}</td>
        <td>
          <button class="btn btn-blue btn-sm" onclick="resolveDispute(${d.id}, 'validated')" ${canResolve?'':'disabled'}>Validate</button>
          <button class="btn btn-red btn-sm" onclick="resolveDispute(${d.id}, 'dismissed')" ${canResolve?'':'disabled'}>Dismiss</button>
        </td>
      `;

      tbody.appendChild(tr);
    });

  }catch(e){
    tbody.innerHTML = '<tr><td colspan="8" class="k">Failed to load disputes.</td></tr>';
    setMsg('disp-msg', e.message||'Failed', false);
  }
}

async function resolveDispute(disputeId, decision){
  document.getElementById('disp-msg').className = 'msg';

  const ok = confirm(decision === 'validated' ? 'Validate this dispute? This will strike the turn user and advance the rotation.' : 'Dismiss this dispute? This will strike the raiser as a false dispute.');
  if(!ok) return;

  try{
    const r = await postCsrf('/api/admin.php', { action:'dispute_resolve', dispute_id: disputeId, decision });
    if(!r.success) throw new Error(r.error||'Failed');
    setMsg('disp-msg','Saved.', true);
    await loadDisputes();
  }catch(e){
    setMsg('disp-msg', e.message||'Failed', false);
  }
}

async function createDestinationAccount(){
  document.getElementById('da-msg').className = 'msg';

  const account_type = document.getElementById('da-type').value.trim();
  const carrier_id = parseInt(document.getElementById('da-carrier').value||'0',10);
  const mobile_money_number = document.getElementById('da-mm').value.trim();
  const bank_name = document.getElementById('da-bank').value.trim();
  const bank_account_name = document.getElementById('da-bank-name').value.trim();
  const bank_account_number = document.getElementById('da-bank-num').value.trim();
  const unlock_code = document.getElementById('da-code').value;
  const is_active = document.getElementById('da-active').checked ? 1 : 0;

  try{
    const r = await postCsrf('/api/admin.php', {
      action:'destination_account_create',
      account_type,
      carrier_id,
      mobile_money_number,
      bank_name,
      bank_account_name,
      bank_account_number,
      unlock_code,
      is_active,
    });

    if(!r.success) throw new Error(r.error||'Failed');

    setMsg('da-msg','Destination account created.', true);
    document.getElementById('da-code').value='';
    await loadDestinationAccounts();

  }catch(e){
    setMsg('da-msg', e.message||'Failed', false);
  }
}

async function rotateDestinationAccount(id){
  document.getElementById('da-msg').className = 'msg';

  const unlock_code = prompt('Enter new unlock code');
  if(!unlock_code) return;

  try{
    const r = await postCsrf('/api/admin.php', {action:'destination_account_rotate', account_id:id, unlock_code});
    if(!r.success) throw new Error(r.error||'Failed');

    setMsg('da-msg','Unlock code rotated.', true);
    await loadDestinationAccounts();

  }catch(e){
    setMsg('da-msg', e.message||'Failed', false);
  }
}

async function toggleDestinationAccountActive(id, cur){
  document.getElementById('da-msg').className = 'msg';

  try{
    const r = await postCsrf('/api/admin.php', {action:'destination_account_set_active', account_id:id, is_active: cur?0:1});
    if(!r.success) throw new Error(r.error||'Failed');

    await loadDestinationAccounts();

  }catch(e){
    setMsg('da-msg', e.message||'Failed', false);
  }
}

async function loadAudit(){
  const q = document.getElementById('audit-q').value.trim();

  const tbody = document.querySelector('#audit-table tbody');
  tbody.innerHTML = '<tr><td colspan="6" class="k">Loading…</td></tr>';

  try{
    const qs = new URLSearchParams({ action:'audit', limit:'200', q });
    const r = await get('/api/admin.php?' + qs.toString());
    if(!r.success) throw new Error(r.error||'Failed');

    const rows = r.audit || [];
    if(!rows.length){
      tbody.innerHTML = '<tr><td colspan="6" class="k">No audit events.</td></tr>';
      return;
    }

    tbody.innerHTML='';
    rows.forEach(a => {
      const tr = document.createElement('tr');
      const ua = (a.user_agent||'');
      const uaShort = ua.length > 80 ? ua.slice(0,80) + '…' : ua;
      tr.innerHTML = `
        <td>${fmt(a.created_at)}</td>
        <td>${esc(a.user_email||'')}</td>
        <td>${esc(a.action)}</td>
        <td>${esc(a.lock_id||'')}</td>
        <td>${esc(a.ip_address||'')}</td>
        <td title="${esc(ua)}">${esc(uaShort)}</td>
      `;
      tbody.appendChild(tr);
    });

  }catch(e){
    tbody.innerHTML = '<tr><td colspan="6" class="k">Failed to load audit log.</td></tr>';
    setMsg('audit-msg', e.message||'Failed', false);
  }
}

loadUsers();
loadCodes();
loadCarriers();
loadDestinationAccounts();
loadDisputes();
loadAudit();
</script>
</body>
</html>
