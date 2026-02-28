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

$isAdmin = isAdmin();
$csrf    = getCsrfToken();

header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none';");
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: no-referrer");
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Backups — LOCKSMITH</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@300;400;500&family=Unbounded:wght@400;700;900&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#06070a;--s1:#0d0f14;--s2:#13161d;--s3:#1a1d27;
  --b1:rgba(255,255,255,.07);--b2:rgba(255,255,255,.13);
  --accent:#e8ff47;--red:#ff4757;--green:#47ffb0;--orange:#ffaa00;--text:#dde1ec;--muted:#525970;
  --mono:'DM Mono',monospace;--display:'Unbounded',sans-serif;
  --sat:env(safe-area-inset-top,0px);--sab:env(safe-area-inset-bottom,0px);
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:var(--mono);min-height:100vh;overflow-x:hidden;}
.nav{display:flex;align-items:center;justify-content:space-between;padding:max(16px,var(--sat)) 20px 16px;border-bottom:1px solid var(--b1);background:rgba(6,7,10,.92);backdrop-filter:blur(14px);position:sticky;top:0;}
.logo{font-family:var(--display);font-weight:900;letter-spacing:-1px;font-size:18px;text-decoration:none;color:var(--text);}
.logo span{color:var(--accent);} 
.nav-r{display:flex;align-items:center;gap:10px;flex-wrap:wrap;justify-content:flex-end;}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;
  padding:12px 18px;font-family:var(--mono);font-size:11px;letter-spacing:2px;
  text-transform:uppercase;cursor:pointer;border:none;transition:all .15s;border-radius:0;
  -webkit-appearance:none;min-height:42px;text-decoration:none;}
.btn-primary{background:var(--accent);color:#000;font-weight:600;}
.btn-primary:disabled{opacity:.45;pointer-events:none;}
.btn-ghost{background:transparent;border:1px solid var(--b2);color:var(--text);} 
.btn-ghost:hover{border-color:var(--text);} 
.btn-red{background:rgba(255,71,87,.08);border:1px solid rgba(255,71,87,.2);color:var(--red);} 
.wrap{max-width:860px;margin:0 auto;padding:26px 18px 60px;}
.h{font-family:var(--display);font-weight:900;font-size:18px;letter-spacing:1px;margin-bottom:8px;}
.p{color:var(--muted);font-size:12px;line-height:1.7;margin-bottom:16px;}
.card{background:rgba(13,15,20,.9);border:1px solid var(--b1);padding:18px;margin-bottom:14px;}
.card-title{font-family:var(--display);font-size:11px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:var(--accent);margin-bottom:12px;}
.row{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;}
.field{margin-bottom:12px;}
.field label{display:block;font-size:10px;letter-spacing:2px;text-transform:uppercase;color:var(--muted);margin-bottom:6px;}
.field input{width:100%;background:var(--s2);border:1px solid var(--b1);color:var(--text);
  font-family:var(--mono);font-size:14px;padding:12px;outline:none;border-radius:0;-webkit-appearance:none;}
.field input:focus{border-color:var(--accent);} 
.small{font-size:11px;color:var(--muted);line-height:1.6;}
.msg{display:none;margin-top:12px;padding:12px 14px;font-size:12px;line-height:1.6;letter-spacing:.4px;}
.msg.show{display:block;}
.msg-err{background:rgba(255,71,87,.08);border:1px solid rgba(255,71,87,.2);color:var(--red);} 
.msg-ok{background:rgba(71,255,176,.08);border:1px solid rgba(71,255,176,.2);color:var(--green);} 
.spin{display:inline-block;width:14px;height:14px;border:2px solid rgba(0,0,0,.35);border-top-color:#000;border-radius:50%;animation:spin .5s linear infinite;}
@keyframes spin{to{transform:rotate(360deg);}}
.list{display:flex;flex-direction:column;gap:10px;}
.item{border:1px solid var(--b1);background:rgba(19,22,29,.6);padding:14px;}
.item-top{display:flex;align-items:flex-start;justify-content:space-between;gap:10px;flex-wrap:wrap;}
.item-title{font-family:var(--display);font-size:12px;font-weight:700;}
.item-meta{font-size:11px;color:var(--muted);line-height:1.6;}
.item-actions{display:flex;gap:8px;flex-wrap:wrap;}
</style>
</head>
<body>
  <div class="nav">
    <a class="logo" href="index.php">LOCK<span>SMITH</span></a>
    <div class="nav-r">
      <a class="btn btn-ghost" href="dashboard.php">Dashboard</a>
      <a class="btn btn-ghost" href="account.php">Account</a>
      <?php if ($isAdmin): ?>
        <a class="btn btn-ghost" href="admin.php">Admin</a>
      <?php endif; ?>
      <a class="btn btn-ghost" href="logout.php">Logout</a>
    </div>
  </div>

  <div class="wrap">
    <div class="h">Backups</div>
    <div class="p">Backups contain only encrypted ciphertext blobs and metadata (labels, dates, status). Your plaintext codes are never stored by the server.</div>

    <div class="card">
      <div class="card-title">Local backup</div>
      <div class="row" style="align-items:flex-end;">
        <div style="flex:1;min-width:240px;">
          <div class="small">Download a JSON file. You can import it later on the same or a new installation.</div>
        </div>
        <button class="btn btn-primary" id="btn-export"><span id="btn-export-txt">Download export</span></button>
      </div>

      <div style="height:14px"></div>

      <div class="card-title" style="color:var(--orange);">Import</div>
      <div class="field">
        <label>Backup file (.json)</label>
        <input type="file" id="import-file" accept="application/json,.json">
      </div>
      <button class="btn btn-ghost" id="btn-import">Import into this account</button>
      <div class="small" style="margin-top:10px;">Importing will create new codes. If an ID collides, it will be remapped.</div>

      <div id="local-ok" class="msg msg-ok"></div>
      <div id="local-err" class="msg msg-err"></div>
    </div>

    <div class="card">
      <div class="card-title">Cloud backups</div>
      <div class="small">Store snapshots on this server (still ciphertext-only). Useful for device loss and quick restores.</div>

      <div style="height:14px"></div>

      <div class="row" style="align-items:flex-end;">
        <div style="flex:1;min-width:240px;">
          <div class="field" style="margin-bottom:0;">
            <label>Label (optional)</label>
            <input id="cloud-label" placeholder="e.g. Before passphrase rotation">
          </div>
        </div>
        <button class="btn btn-primary" id="btn-cloud-save"><span id="btn-cloud-save-txt">Create cloud backup</span></button>
      </div>

      <div id="cloud-ok" class="msg msg-ok"></div>
      <div id="cloud-err" class="msg msg-err"></div>

      <div style="height:14px"></div>
      <div class="list" id="cloud-list"></div>
    </div>
  </div>

<script>
const CSRF = <?= json_encode($csrf) ?>;

const localOk=document.getElementById('local-ok');
const localErr=document.getElementById('local-err');
const cloudOk=document.getElementById('cloud-ok');
const cloudErr=document.getElementById('cloud-err');
const cloudList=document.getElementById('cloud-list');

function show(el,m){el.textContent=m;el.classList.add('show');}
function clearMsgs(){[localOk,localErr,cloudOk,cloudErr].forEach(e=>{e.textContent='';e.classList.remove('show');});}

async function get(url){
  const r=await fetch(url,{credentials:'same-origin'});
  return r.json();
}
async function post(url,body){
  const r=await fetch(url,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF},body:JSON.stringify(body)});
  return r.json();
}

function downloadJson(filename, objOrJsonString){
  const data = (typeof objOrJsonString === 'string') ? objOrJsonString : JSON.stringify(objOrJsonString, null, 2);
  const blob = new Blob([data], {type:'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  URL.revokeObjectURL(a.href);
  document.body.removeChild(a);
}

function esc(s){
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

document.getElementById('btn-export').addEventListener('click', async ()=>{
  clearMsgs();
  const btn=document.getElementById('btn-export');
  const txt=document.getElementById('btn-export-txt');
  btn.disabled=true; txt.innerHTML='<span class="spin"></span>';
  try{
    const j=await get('api/backup.php?action=export');
    if(!j.success){show(localErr,j.error||'Export failed');return;}
    const ts = new Date().toISOString().slice(0,10).replace(/-/g,'');
    downloadJson('locksmith_export_' + ts + '.json', j.export);
    show(localOk,'Export downloaded.');
  }catch{
    show(localErr,'Network error');
  }finally{
    btn.disabled=false; txt.textContent='Download export';
  }
});

document.getElementById('btn-import').addEventListener('click', async ()=>{
  clearMsgs();
  const fileInput=document.getElementById('import-file');
  if(!fileInput.files || !fileInput.files[0]){show(localErr,'Select a backup JSON file.');return;}

  const btn=document.getElementById('btn-import');
  btn.disabled=true; btn.innerHTML='<span class="spin"></span> Importing…';

  try{
    const txt=await fileInput.files[0].text();
    const exportObj=JSON.parse(txt);
    const r=await post('api/backup.php',{action:'import',export:exportObj});
    if(!r.success){show(localErr,r.error||'Import failed');return;}
    show(localOk,'Imported ' + (r.imported||0) + ' codes.');
  }catch(e){
    show(localErr,'Import failed: ' + (e && e.message ? e.message : 'error'));
  }finally{
    btn.disabled=false; btn.textContent='Import into this account';
  }
});

async function refreshCloud(){
  cloudList.innerHTML='';
  const j=await get('api/backup.php?action=cloud_list');
  if(!j.success){show(cloudErr,j.error||'Could not load cloud backups');return;}

  const items=j.backups||[];
  if(items.length===0){
    cloudList.innerHTML='<div class="small" style="padding:6px 2px;">No cloud backups yet.</div>';
    return;
  }

  for(const b of items){
    const el=document.createElement('div');
    el.className='item';

    const label=(b.label && b.label.trim()) ? b.label : ('Backup #' + b.id);
    const size=(b.bytes!==null && b.bytes!==undefined) ? (Math.round((b.bytes/1024)*10)/10 + ' KB') : '';

    el.innerHTML = `
      <div class="item-top">
        <div>
          <div class="item-title">${esc(label)}</div>
          <div class="item-meta">${esc(b.created_at || '')}${size ? ' • ' + esc(size) : ''}</div>
        </div>
        <div class="item-actions">
          <button class="btn btn-ghost" data-act="dl" data-id="${esc(b.id)}">Download</button>
          <button class="btn btn-ghost" data-act="restore" data-id="${esc(b.id)}">Restore</button>
          <button class="btn btn-red" data-act="del" data-id="${esc(b.id)}">Delete</button>
        </div>
      </div>
    `;

    cloudList.appendChild(el);
  }
}

cloudList.addEventListener('click', async (e)=>{
  const btn=e.target.closest('button');
  if(!btn) return;

  const act=btn.getAttribute('data-act');
  const id=parseInt(btn.getAttribute('data-id')||'0',10);
  if(!id) return;

  clearMsgs();

  if(act==='dl'){
    btn.disabled=true; btn.innerHTML='<span class="spin"></span>';
    try{
      const j=await get('api/backup.php?action=cloud_get&id='+encodeURIComponent(id));
      if(!j.success){show(cloudErr,j.error||'Download failed');return;}
      const backup=j.backup;
      const label=(backup.label && backup.label.trim()) ? backup.label : ('backup_'+id);
      const safe=label.replace(/[^a-z0-9_\-]+/gi,'_').slice(0,60);
      downloadJson('locksmith_cloud_' + safe + '_' + id + '.json', backup.backup_blob);
      show(cloudOk,'Downloaded cloud backup.');
    }catch{
      show(cloudErr,'Network error');
    }finally{
      btn.disabled=false; btn.textContent='Download';
    }
  }

  if(act==='restore'){
    if(!confirm('Restore this backup into your account? This will import codes and may create duplicates.')) return;
    btn.disabled=true; btn.innerHTML='<span class="spin"></span>';
    try{
      const r=await post('api/backup.php',{action:'cloud_restore',id});
      if(!r.success){show(cloudErr,r.error||'Restore failed');return;}
      show(cloudOk,'Restored. Imported ' + (r.imported||0) + ' codes.');
    }catch{
      show(cloudErr,'Network error');
    }finally{
      btn.disabled=false; btn.textContent='Restore';
    }
  }

  if(act==='del'){
    if(!confirm('Delete this cloud backup?')) return;
    btn.disabled=true; btn.innerHTML='<span class="spin"></span>';
    try{
      const r=await post('api/backup.php',{action:'cloud_delete',id});
      if(!r.success){show(cloudErr,r.error||'Delete failed');return;}
      show(cloudOk,'Cloud backup deleted.');
      await refreshCloud();
    }catch{
      show(cloudErr,'Network error');
    }
  }
});

document.getElementById('btn-cloud-save').addEventListener('click', async ()=>{
  clearMsgs();
  const btn=document.getElementById('btn-cloud-save');
  const txt=document.getElementById('btn-cloud-save-txt');
  btn.disabled=true; txt.innerHTML='<span class="spin"></span>';
  try{
    const label=document.getElementById('cloud-label').value.trim();
    const r=await post('api/backup.php',{action:'cloud_save',label});
    if(!r.success){show(cloudErr,r.error||'Cloud backup failed');return;}
    document.getElementById('cloud-label').value='';
    show(cloudOk,'Cloud backup saved.');
    await refreshCloud();
  }catch{
    show(cloudErr,'Network error');
  }finally{
    btn.disabled=false; txt.textContent='Create cloud backup';
  }
});

refreshCloud();
</script>
</body>
</html>
