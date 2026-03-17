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

$userId = (int)(getCurrentUserId() ?? 0);
$showSecurityBanner = !userHasTotp($userId) && !userHasPasskeys($userId);

$appSlug = strtolower(preg_replace('/[^a-z0-9]+/i', '_', APP_NAME));
$appSlug = trim($appSlug, '_');
if ($appSlug === '') $appSlug = 'app';

header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none';");
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: no-referrer");
?>
<!DOCTYPE html>
<html <?= htmlLangAttr() ?>>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title><?= htmlspecialchars(APP_NAME) ?> — <?= htmlspecialchars(t('page.backups')) ?></title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;600;700;800;900&family=Syne:wght@400;500;600;700;800&family=JetBrains+Mono:wght@300;400;500;600&display=swap" rel="stylesheet">
<?php emitI18nJsGlobals(); ?>
<script src="assets/theme.js"></script>
<script src="assets/app.js"></script>
<link rel="stylesheet" href="assets/base.css">
<link rel="stylesheet" href="assets/app.css">
<style> 
.btn-red{background:rgba(255,71,87,.08);border:1px solid rgba(255,71,87,.2);color:var(--red);}

/* ── SECURITY BANNER ── */
.sec-banner{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;
  background:rgba(255,170,0,.06);border:1px solid rgba(255,170,0,.22);
  padding:14px 14px;margin:0 0 14px 0;}
.sec-banner-title{font-family:var(--display);font-weight:800;font-size:12px;letter-spacing:1px;color:var(--orange);}
.sec-banner-sub{font-size:11px;color:var(--muted);line-height:1.6;max-width:620px;}

.card{margin-bottom:14px;}
.card-title{margin-bottom:12px;}
.row{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;}
 
.small{font-size:11px;color:var(--muted);line-height:1.6;}

.list{display:flex;flex-direction:column;gap:10px;}
.item{border:1px solid var(--b1);background:rgba(19,22,29,.6);padding:14px;}
.item-top{display:flex;align-items:flex-start;justify-content:space-between;gap:10px;flex-wrap:wrap;}
.item-title{font-family:var(--display);font-size:12px;font-weight:700;}
.item-meta{font-size:11px;color:var(--muted);line-height:1.6;}
.item-actions{display:flex;gap:8px;flex-wrap:wrap;}
</style>
</head>
<body>
<div id="app">
  <?php include __DIR__ . '/includes/topbar.php'; ?>

  <div class="app-body">

    <div class="page-head">
      <div>
        <div class="page-title"><?php e('page.backups'); ?></div>
        <div class="page-sub"><?php e('backup.intro'); ?></div>
      </div>
      <div class="page-actions">
        <a class="btn btn-ghost btn-sm" href="vault_settings.php"><?php e('nav.vault'); ?></a>
      </div>
    </div>

    <?php if ($showSecurityBanner): ?>
    <div class="sec-banner">
      <div>
        <div class="sec-banner-title"><?php e('backup.security_required_title'); ?></div>
        <div class="sec-banner-sub"><?php e('backup.security_required_sub'); ?></div>
      </div>
      <a class="btn btn-ghost" href="security.php"><?php e('backup.open_account'); ?></a>
    </div>
    <?php endif; ?>

    <div class="card">
      <div class="card-title"><?php e('backup.local_title'); ?></div>
      <div class="row" style="align-items:flex-end;">
        <div style="flex:1;min-width:240px;">
          <div class="small"><?php e('backup.local_sub'); ?></div>
        </div>
        <button class="btn btn-primary" id="btn-export"><span id="btn-export-txt"><?php e('backup.download_export'); ?></span></button>
      </div>

      <div style="height:14px"></div>

      <div class="card-title" style="color:var(--orange);"><?php e('backup.import_title'); ?></div>
      <div class="field">
        <label><?php e('backup.backup_file_label'); ?></label>
        <input type="file" id="import-file" accept="application/json,.json">
      </div>
      <button class="btn btn-ghost" id="btn-import"><?php e('backup.import_into_account'); ?></button>
      <div class="small" style="margin-top:10px;"><?php e('backup.import_note'); ?></div>

      <div id="local-ok" class="msg msg-ok"></div>
      <div id="local-err" class="msg msg-err"></div>
    </div>

    <div class="card">
      <div class="card-title"><?php e('backup.cloud_title'); ?></div>
      <div class="small"><?php e('backup.cloud_sub'); ?></div>
      <div class="small" id="cloud-summary" style="margin-top:10px;"></div>

      <div style="height:14px"></div>

      <div class="row" style="align-items:flex-end;">
        <div style="flex:1;min-width:240px;">
          <div class="field" style="margin-bottom:0;">
            <label><?php e('backup.cloud_label_optional'); ?></label>
            <input id="cloud-label" placeholder="<?= htmlspecialchars(t('backup.cloud_label_placeholder'), ENT_QUOTES, 'UTF-8') ?>">
          </div>
        </div>
        <div style="display:flex;gap:10px;flex-wrap:wrap;justify-content:flex-end;">
          <button class="btn btn-ghost" id="btn-cloud-latest"><?php e('backup.download_latest'); ?></button>
          <button class="btn btn-primary" id="btn-cloud-save"><span id="btn-cloud-save-txt"><?php e('backup.create_cloud_backup'); ?></span></button>
        </div>
      </div>

      <div id="cloud-ok" class="msg msg-ok"></div>
      <div id="cloud-err" class="msg msg-err"></div>

      <div style="height:14px"></div>
      <div class="list" id="cloud-list"></div>
    </div>

  </div>

<script>
const CSRF = <?= json_encode($csrf) ?>;
const APP_SLUG = <?= json_encode($appSlug) ?>;

const STR = {
  networkError: <?= json_encode(t('common.network_error')) ?>,
  failed: <?= json_encode(t('common.failed')) ?>,
  enterTotp: <?= json_encode(t('login.enter_totp')) ?>,
  enableTotpOrPasskey: <?= json_encode(t('js.enable_totp_or_passkey')) ?>,

  exportFailed: <?= json_encode(t('backup.export_failed')) ?>,
  exportDownloaded: <?= json_encode(t('backup.export_downloaded')) ?>,
  downloadExport: <?= json_encode(t('backup.download_export')) ?>,

  selectBackupJson: <?= json_encode(t('backup.select_backup_json')) ?>,
  importing: <?= json_encode(t('backup.importing')) ?>,
  importFailed: <?= json_encode(t('backup.import_failed')) ?>,
  importFailedWith: <?= json_encode(t('backup.import_failed_with')) ?>,
  importedCount: <?= json_encode(t('backup.imported_count')) ?>,
  importIntoAccount: <?= json_encode(t('backup.import_into_account')) ?>,

  cloudCouldNotLoad: <?= json_encode(t('backup.cloud_could_not_load')) ?>,
  cloudCount: <?= json_encode(t('backup.cloud_count')) ?>,
  noCloudBackupsYet: <?= json_encode(t('backup.no_cloud_backups_yet')) ?>,
  latest: <?= json_encode(t('backup.latest')) ?>,
  backupNumber: <?= json_encode(t('backup.backup_number')) ?>,

  download: <?= json_encode(t('backup.download')) ?>,
  restore: <?= json_encode(t('backup.restore')) ?>,
  delete: <?= json_encode(t('backup.delete')) ?>,
  downloadFailed: <?= json_encode(t('backup.download_failed')) ?>,
  downloadedCloudBackup: <?= json_encode(t('backup.downloaded_cloud_backup')) ?>,

  confirmRestore: <?= json_encode(t('backup.confirm_restore')) ?>,
  restoreFailed: <?= json_encode(t('backup.restore_failed')) ?>,
  restoredImported: <?= json_encode(t('backup.restored_imported')) ?>,

  confirmDelete: <?= json_encode(t('backup.confirm_delete')) ?>,
  deleteFailed: <?= json_encode(t('backup.delete_failed')) ?>,
  cloudBackupDeleted: <?= json_encode(t('backup.cloud_backup_deleted')) ?>,

  cloudBackupFailed: <?= json_encode(t('backup.cloud_backup_failed')) ?>,
  cloudBackupSaved: <?= json_encode(t('backup.cloud_backup_saved')) ?>,
  createCloudBackup: <?= json_encode(t('backup.create_cloud_backup')) ?>,

  noCloudToDownload: <?= json_encode(t('backup.no_cloud_to_download')) ?>,
  downloadLatest: <?= json_encode(t('backup.download_latest')) ?>,

  ageDays: <?= json_encode(t('backup.age_days')) ?>,
  ageHours: <?= json_encode(t('backup.age_hours')) ?>,
  ageMinutes: <?= json_encode(t('backup.age_minutes')) ?>,
  ageSeconds: <?= json_encode(t('backup.age_seconds')) ?>,
};

const localOk=document.getElementById('local-ok');
const localErr=document.getElementById('local-err');
const cloudOk=document.getElementById('cloud-ok');
const cloudErr=document.getElementById('cloud-err');
const cloudList=document.getElementById('cloud-list');
const cloudSummary=document.getElementById('cloud-summary');

let cloudItemsCache = [];

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

function b64uToBuf(b64url){
  const b64 = String(b64url||'').replace(/-/g,'+').replace(/_/g,'/');
  const pad = b64.length % 4 ? '='.repeat(4 - (b64.length % 4)) : '';
  const bin = atob(b64 + pad);
  const bytes = new Uint8Array(bin.length);
  for(let i=0;i<bin.length;i++) bytes[i]=bin.charCodeAt(i);
  return bytes.buffer;
}
function bufToB64u(buf){
  const bytes = new Uint8Array(buf);
  let s='';
  for(let i=0;i<bytes.length;i++) s+=String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}

async function ensureReauth(methods){
  if(methods && methods.passkey && window.PublicKeyCredential){
    try{
      const begin = await post('api/webauthn.php', {action:'reauth_begin'});
      if(begin.success){
        const pk = begin.publicKey || {};
        const allow = (pk.allowCredentials||[]).map(c => ({type:c.type, id: b64uToBuf(c.id)}));
        const cred = await navigator.credentials.get({publicKey:{
          challenge: b64uToBuf(pk.challenge),
          rpId: pk.rpId,
          timeout: pk.timeout||60000,
          userVerification: pk.userVerification||'required',
          allowCredentials: allow,
        }});

        const a = cred.response;
        const fin = await post('api/webauthn.php', {
          action:'reauth_finish',
          rawId: bufToB64u(cred.rawId),
          response:{
            clientDataJSON: bufToB64u(a.clientDataJSON),
            authenticatorData: bufToB64u(a.authenticatorData),
            signature: bufToB64u(a.signature),
            userHandle: a.userHandle ? bufToB64u(a.userHandle) : null,
          }
        });
        if(fin.success) return true;
      }
    }catch{}
  }

  if(methods && methods.totp){
    const msg = STR.enterTotp;
    let code = null;

    if(window.LS && typeof window.LS.prompt === 'function'){
      code = await window.LS.prompt({
        title: (window.LS && typeof window.LS.t === 'function') ? (window.LS.t('common.confirm') || 'Confirm') : 'Confirm',
        message: msg,
        placeholder: '123456',
        inputMode: 'numeric',
        validate: (v)=> (/^\d{6}$/.test(String(v||'').trim()) ? true : msg),
      });
    } else if (typeof window.uiPrompt === 'function'){
      code = await window.uiPrompt({
        title: (window.LS && typeof window.LS.t === 'function') ? (window.LS.t('common.confirm') || 'Confirm') : 'Confirm',
        message: msg,
        placeholder: '123456',
        inputMode: 'numeric',
        validate: (v)=> (/^\d{6}$/.test(String(v||'').trim()) ? true : msg),
      });
    }

    const c = String(code||'').trim();
    if(!c) return false;
    const r = await post('api/totp.php', {action:'reauth', code: c});
    return !!r.success;
  }

  show(localErr, STR.enableTotpOrPasskey);
  return false;
}

async function getStrong(url){
  let j = await get(url);
  if(!j.success && (j.error_code==='reauth_required' || j.error_code==='security_setup_required')){
    const ok = await ensureReauth(j.methods||{});
    if(!ok) return j;
    j = await get(url);
  }
  return j;
}

async function postStrong(url, body){
  let j = await post(url, body);
  if(!j.success && (j.error_code==='reauth_required' || j.error_code==='security_setup_required')){
    const ok = await ensureReauth(j.methods||{});
    if(!ok) return j;
    j = await post(url, body);
  }
  return j;
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

function parseUtcDate(ts){
  const s = String(ts||'').trim();
  if(!s) return null;

  if(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(s)){
    return new Date(s.replace(' ', 'T') + 'Z');
  }

  const d = new Date(s);
  return isNaN(d.getTime()) ? null : d;
}

function fmtLocal(ts){
  const d = parseUtcDate(ts);
  if(!d) return String(ts||'');
  return d.toLocaleString();
}

function age(ts){
  const d = parseUtcDate(ts);
  if(!d) return '';
  const secs = Math.max(0, Math.floor((Date.now() - d.getTime())/1000));
  const m = Math.floor(secs/60);
  const h = Math.floor(m/60);
  const days = Math.floor(h/24);
  if(days > 0) return STR.ageDays.replace('{count}', String(days));
  if(h > 0) return STR.ageHours.replace('{count}', String(h));
  if(m > 0) return STR.ageMinutes.replace('{count}', String(m));
  return STR.ageSeconds.replace('{count}', String(secs));
}

document.getElementById('btn-export').addEventListener('click', async ()=>{
  clearMsgs();
  const btn=document.getElementById('btn-export');
  const txt=document.getElementById('btn-export-txt');
  btn.disabled=true; txt.innerHTML='<span class="spin"></span>';
  try{
    const j=await getStrong('api/backup.php?action=export');
    if(!j.success){show(localErr,j.error||STR.exportFailed);return;}
    const ts = new Date().toISOString().slice(0,10).replace(/-/g,'');
    downloadJson(APP_SLUG + '_export_' + ts + '.json', j.export);

    show(localOk, STR.exportDownloaded);
  }catch{
    show(localErr, STR.networkError);
  }finally{
    btn.disabled=false; txt.textContent=STR.downloadExport;
  }
});

document.getElementById('btn-import').addEventListener('click', async ()=>{
  clearMsgs();
  const fileInput=document.getElementById('import-file');
  if(!fileInput.files || !fileInput.files[0]){show(localErr, STR.selectBackupJson);return;}

  const btn=document.getElementById('btn-import');
  btn.disabled=true; btn.innerHTML='<span class="spin"></span> ' + STR.importing;

  try{
    const txt=await fileInput.files[0].text();
    const exportObj=JSON.parse(txt);
    const r=await postStrong('api/backup.php',{action:'import',export:exportObj});
    if(!r.success){show(localErr,r.error||STR.importFailed);return;}

    show(localOk, STR.importedCount.replace('{count}', String(r.imported||0)));
  }catch(e){
    const msg = (e && e.message) ? String(e.message) : STR.failed;
    show(localErr, STR.importFailedWith.replace('{error}', msg));
  }finally{
    btn.disabled=false; btn.textContent=STR.importIntoAccount;
  }
});

async function refreshCloud(){
  cloudList.innerHTML='';
  cloudSummary.textContent='';

  const j=await getStrong('api/backup.php?action=cloud_list');
  if(!j.success){show(cloudErr,j.error||STR.cloudCouldNotLoad);return;}

  const items=j.backups||[];
  cloudItemsCache = items;

  if(items.length===0){
    cloudSummary.textContent = STR.cloudCount.replace('{count}', '0');
    cloudList.innerHTML = '<div class="small" style="padding:6px 2px;">' + esc(STR.noCloudBackupsYet) + '</div>';
    return;
  }

  const latest = items[0];
  const latestLocal = fmtLocal(latest.created_at || '');
  const latestAge = age(latest.created_at || '');
  cloudSummary.textContent = `${STR.cloudCount.replace('{count}', String(items.length))} · ${STR.latest}: ${latestLocal} (${latest.created_at} UTC)${latestAge ? ' · ' + latestAge : ''}`;

  for(const b of items){
    const el=document.createElement('div');
    el.className='item';

    const label=(b.label && b.label.trim()) ? b.label : STR.backupNumber.replace('{id}', String(b.id));
    const size=(b.bytes!==null && b.bytes!==undefined) ? (Math.round((b.bytes/1024)*10)/10 + ' KB') : '';

    const local = fmtLocal(b.created_at || '');
    const ago = age(b.created_at || '');
    const metaBits = [
      local ? (local + ' (' + (b.created_at || '') + ' UTC)') : (b.created_at || ''),
      ago || '',
      size || ''
    ].filter(Boolean);

    el.innerHTML = `
      <div class="item-top">
        <div>
          <div class="item-title">${esc(label)}</div>
          <div class="item-meta">${esc(metaBits.join(' • '))}</div>
        </div>
        <div class="item-actions">
          <button class="btn btn-ghost" data-act="dl" data-id="${esc(b.id)}">${esc(STR.download)}</button>
          <button class="btn btn-ghost" data-act="restore" data-id="${esc(b.id)}">${esc(STR.restore)}</button>
          <button class="btn btn-red" data-act="del" data-id="${esc(b.id)}">${esc(STR.delete)}</button>
        </div>
      </div>
    `;

    cloudList.appendChild(el);
  }
}

async function downloadCloudId(id){
  const j=await getStrong('api/backup.php?action=cloud_get&id='+encodeURIComponent(id));
  if(!j.success){show(cloudErr,j.error||STR.downloadFailed);return false;}
  const backup=j.backup;
  const label=(backup.label && backup.label.trim()) ? backup.label : ('backup_'+id);
  const safe=label.replace(/[^a-z0-9_\-]+/gi,'_').slice(0,60);
  downloadJson(APP_SLUG + '_cloud_' + safe + '_' + id + '.json', backup.backup_blob);
  show(cloudOk, STR.downloadedCloudBackup);
  return true;
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
    try{ await downloadCloudId(id); }
    catch{ show(cloudErr, STR.networkError); }
    finally{ btn.disabled=false; btn.textContent=STR.download; }
  }

  if(act==='restore'){
    const ok = (window.LS && typeof window.LS.confirm === 'function')
      ? await window.LS.confirm(STR.confirmRestore, {title: (window.LS && typeof window.LS.t === 'function') ? (window.LS.t('common.confirm') || 'Confirm') : 'Confirm', danger: true})
      : (typeof window.uiConfirm === 'function' ? await window.uiConfirm({title: (window.LS && typeof window.LS.t === 'function') ? (window.LS.t('common.confirm') || 'Confirm') : 'Confirm', message: STR.confirmRestore, danger: true}) : false);
    if(!ok) return;
    btn.disabled=true; btn.innerHTML='<span class="spin"></span>';
    try{
      const r=await postStrong('api/backup.php',{action:'cloud_restore',id});
      if(!r.success){show(cloudErr,r.error||STR.restoreFailed);return;}
      show(cloudOk, STR.restoredImported.replace('{count}', String(r.imported||0)));
    }catch{
      show(cloudErr, STR.networkError);
    }finally{
      btn.disabled=false; btn.textContent=STR.restore;
    }
  }

  if(act==='del'){
    const ok = (window.LS && typeof window.LS.confirm === 'function')
      ? await window.LS.confirm(STR.confirmDelete, {title: (window.LS && typeof window.LS.t === 'function') ? (window.LS.t('common.confirm') || 'Confirm') : 'Confirm', danger: true})
      : (typeof window.uiConfirm === 'function' ? await window.uiConfirm({title: (window.LS && typeof window.LS.t === 'function') ? (window.LS.t('common.confirm') || 'Confirm') : 'Confirm', message: STR.confirmDelete, danger: true}) : false);
    if(!ok) return;
    btn.disabled=true; btn.innerHTML='<span class="spin"></span>';
    try{
      const r=await postStrong('api/backup.php',{action:'cloud_delete',id});
      if(!r.success){show(cloudErr,r.error||STR.deleteFailed);return;}
      show(cloudOk, STR.cloudBackupDeleted);
      await refreshCloud();
    }catch{
      show(cloudErr, STR.networkError);
    }finally{
      btn.disabled=false; btn.textContent=STR.delete;
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
    const r=await postStrong('api/backup.php',{action:'cloud_save',label});
    if(!r.success){show(cloudErr,r.error||STR.cloudBackupFailed);return;}
    document.getElementById('cloud-label').value='';
    show(cloudOk, STR.cloudBackupSaved);
    await refreshCloud();
  }catch{
    show(cloudErr, STR.networkError);
  }finally{
    btn.disabled=false; txt.textContent=STR.createCloudBackup;
  }
});

document.getElementById('btn-cloud-latest').addEventListener('click', async ()=>{
  clearMsgs();

  if(!cloudItemsCache.length){
    await refreshCloud();
  }

  const latest = cloudItemsCache && cloudItemsCache.length ? cloudItemsCache[0] : null;
  if(!latest || !latest.id){
    show(cloudErr, STR.noCloudToDownload);
    return;
  }

  const btn=document.getElementById('btn-cloud-latest');
  btn.disabled=true; btn.innerHTML='<span class="spin"></span>';
  try{ await downloadCloudId(parseInt(latest.id,10)); }
  catch{ show(cloudErr, STR.networkError); }
  finally{ btn.disabled=false; btn.textContent=STR.downloadLatest; }
});

refreshCloud();
</script>
</div>
</body>
</html> 
