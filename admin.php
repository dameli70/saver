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
<style>
:root{
  --bg:#06070a;--s1:#0d0f14;--s2:#13161d;--s3:#1a1d27;
  --b1:rgba(255,255,255,.07);--b2:rgba(255,255,255,.13);
  --accent:#e8ff47;--red:#ff4757;--green:#47ffb0;--orange:#ffaa00;--blue:#47b8ff;
  --text:#dde1ec;--muted:#525970;
  --mono:'DM Mono',monospace;--display:'Unbounded',sans-serif;
  --sat:env(safe-area-inset-top,0px);--sab:env(safe-area-inset-bottom,0px);
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:var(--mono);min-height:100vh;overflow-x:hidden;}
.orb{position:fixed;border-radius:50%;filter:blur(120px);pointer-events:none;z-index:0;}
.orb1{width:520px;height:520px;background:rgba(232,255,71,.035);top:-170px;right:-120px;}
.orb2{width:360px;height:360px;background:rgba(71,184,255,.03);bottom:40px;left:-90px;}
.nav{position:sticky;top:0;z-index:10;display:flex;align-items:center;justify-content:space-between;
  padding:max(16px,var(--sat)) 20px 16px;border-bottom:1px solid var(--b1);background:rgba(6,7,10,.92);backdrop-filter:blur(14px);}
.logo{font-family:var(--display);font-weight:900;letter-spacing:-1px;font-size:18px;text-decoration:none;color:inherit;}
.logo span{color:var(--accent);} 
.nav-r{display:flex;align-items:center;gap:10px;flex-wrap:wrap;justify-content:flex-end;}
.pill{font-size:10px;color:var(--muted);letter-spacing:1px;border:1px solid rgba(255,255,255,.13);padding:6px 10px;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.badge{font-size:10px;letter-spacing:2px;text-transform:uppercase;border:1px solid rgba(232,255,71,.25);color:var(--accent);padding:6px 10px;}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;
  padding:12px 18px;font-family:var(--mono);font-size:11px;letter-spacing:2px;
  text-transform:uppercase;cursor:pointer;border:none;transition:all .15s;border-radius:0;
  -webkit-appearance:none;min-height:42px;text-decoration:none;}
.btn-primary{background:var(--accent);color:#000;font-weight:600;}
.btn-ghost{background:transparent;border:1px solid var(--b2);color:var(--text);} 
.btn-ghost:hover{border-color:var(--text);} 
.btn-red{background:rgba(255,71,87,.1);border:1px solid rgba(255,71,87,.3);color:var(--red);} 
.btn-red:hover{background:rgba(255,71,87,.18);} 
.btn-blue{background:rgba(71,184,255,.12);border:1px solid rgba(71,184,255,.25);color:var(--blue);} 
.btn-blue:hover{background:rgba(71,184,255,.18);} 
.btn-sm{padding:10px 14px;min-height:38px;font-size:10px;}
.wrap{position:relative;z-index:1;max-width:1200px;margin:0 auto;padding:26px 18px 60px;}
.h{font-family:var(--display);font-weight:900;font-size:18px;letter-spacing:1px;margin-bottom:8px;}
.p{color:var(--muted);font-size:12px;line-height:1.7;margin-bottom:16px;}
.grid{display:grid;grid-template-columns:1fr;gap:14px;}
@media(min-width:980px){.grid{grid-template-columns:1fr 1fr;}}
.card{background:rgba(13,15,20,.9);border:1px solid var(--b1);padding:18px;}
.card-title{font-family:var(--display);font-size:11px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:var(--accent);margin-bottom:14px;}
.field{margin-bottom:12px;}
.field label{display:block;font-size:10px;letter-spacing:2px;text-transform:uppercase;color:var(--muted);margin-bottom:6px;}
.field input{width:100%;background:var(--s2);border:1px solid var(--b1);color:var(--text);
  font-family:var(--mono);font-size:14px;padding:12px;outline:none;border-radius:0;-webkit-appearance:none;}
.field input:focus{border-color:var(--accent);} 
.chk{display:flex;align-items:center;gap:10px;color:var(--muted);font-size:12px;line-height:1.4;margin:12px 0;}
.chk input{width:16px;height:16px;}
.msg{display:none;margin-top:12px;padding:12px 14px;font-size:12px;line-height:1.6;letter-spacing:.4px;}
.msg.show{display:block;}
.msg-err{background:rgba(255,71,87,.08);border:1px solid rgba(255,71,87,.2);color:var(--red);} 
.msg-ok{background:rgba(71,255,176,.08);border:1px solid rgba(71,255,176,.2);color:var(--green);} 
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
      <div class="field"><label>Vault passphrase</label><input id="nu-vault" type="password" placeholder="min 10 chars" autocomplete="new-password"></div>

      <label class="chk"><input type="checkbox" id="nu-verified"> <span>Mark email as verified (skip email verification)</span></label>
      <label class="chk"><input type="checkbox" id="nu-admin"> <span>Make this user an admin</span></label>

      <button class="btn btn-primary" onclick="createUser()">Create user</button>
      <div id="nu-msg" class="msg"></div>
      <div id="nu-dev" class="msg" style="display:none;background:rgba(255,170,0,.06);border:1px solid rgba(255,170,0,.25);color:var(--muted);"></div>

      <hr>
      <div class="p" style="margin:0;">
        For zero-knowledge integrity, the user should choose their own vault passphrase.
        If you create accounts on their behalf, you will know that passphrase.
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
  const vault = document.getElementById('nu-vault').value;
  const markVerified = document.getElementById('nu-verified').checked;
  const isAdmin = document.getElementById('nu-admin').checked;

  document.getElementById('nu-msg').className = 'msg';
  document.getElementById('nu-dev').style.display = 'none';

  try{
    const r = await postCsrf('/api/admin.php', {
      action: 'create_user',
      email,
      login_password: login,
      vault_passphrase: vault,
      mark_verified: markVerified ? 1 : 0,
      is_admin: isAdmin ? 1 : 0,
    });
    if(!r.success) throw new Error(r.error||'Failed');

    setMsg('nu-msg', 'User created.', true);
    document.getElementById('nu-email').value='';
    document.getElementById('nu-login').value='';
    document.getElementById('nu-vault').value='';

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
          <button class="btn btn-blue btn-sm" onclick="openDetail(${JSON.stringify(c.id)})">Deta</
 button>
         <lbutton class="btn btn-red btn-sm" onclick="deleteCode(${JSON.stringify(c.id)})>
        </td>
      `;
      tbody.appendChild(tr);
    });

  }catch(e){
    tbody.innerHTML = '<tr><td colspan="11" class="k">Failed to load codes.</td></tr>';
    setMsg('codes-msg', e.message||'Failed', false);
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
  document.getElementById('detail-modal').classLis</old_code><new_code>loadUsers();
loadCodes();
</script>
</body>
</html>
