<?php
require_once __DIR__ . '/includes/install_guard.php';
requireInstalledForPage();

require_once __DIR__ . '/includes/helpers.php';
startSecureSession();

header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none';");
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: no-referrer");
header("Permissions-Policy: clipboard-write=(self)");

$token = trim((string)($_GET['t'] ?? ''));
?>
<!DOCTYPE html>
<html <?= htmlLangAttr() ?>>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title><?= htmlspecialchars(APP_NAME) ?> — <?= htmlspecialchars(t('page.receive')) ?></title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;600;700;800;900&family=Syne:wght@400;500;600;700;800&family=JetBrains+Mono:wght@300;400;500;600&display=swap" rel="stylesheet">
<?php emitI18nJsGlobals(); ?>
<script src="assets/theme.js"></script>
<script src="assets/app.js"></script>
<link rel="stylesheet" href="assets/base.css">
<link rel="stylesheet" href="assets/app.css">
<link rel="stylesheet" href="assets/share_page.css">
</head>
<body>
<div class="orb orb1"></div><div class="orb orb2"></div>

<div id="app">
  <?php include __DIR__ . '/includes/topbar_public.php'; ?>

  <div class="app-body">

    <div class="page-head">
      <div>
        <div class="page-title"><?php e('page.receive'); ?></div>
        <div class="page-sub"><?php e('receive.page_intro'); ?></div>
      </div>
    </div>

    <div class="card share-card">
      <div class="card-title"><div class="dot"></div><?php e('receive.card_title'); ?></div>

      <?php if ($token === ''): ?>
        <div class="msg msg-err show"><?php e('receive.invalid_link'); ?></div>
      <?php else: ?>
        <div class="share-meta" id="meta"><?php e('common.loading'); ?></div>
        <div class="share-countdown" id="countdown" style="display:none;"></div>

        <div id="missing-secret" class="msg msg-err" style="display:none;"></div>

        <div id="form" style="display:none;margin-top:14px;">
          <div class="field">
            <label><?php e('receive.label_label'); ?></label>
            <input type="text" id="label" maxlength="120" placeholder="<?= htmlspecialchars(t('receive.label_placeholder'), ENT_QUOTES, 'UTF-8') ?>">
          </div>

          <div class="field">
            <label><?php e('receive.secret_label'); ?></label>
            <textarea id="plain" rows="4" placeholder="<?= htmlspecialchars(t('receive.secret_placeholder'), ENT_QUOTES, 'UTF-8') ?>"></textarea>
          </div>

          <div class="field" id="reveal-field" style="display:none;">
            <label><?php e('create_code.reveal_dt_label'); ?></label>
            <input type="datetime-local" id="reveal-date">
          </div>

          <div id="err" class="msg msg-err"></div>

          <button class="btn btn-primary" type="button" id="btn">
            <span class="btn-ico" id="btn-ico" aria-hidden="true">🔒</span>
            <span class="btn-txt" id="btn-txt"><?php e('receive.btn_submit'); ?></span>
          </button>

          <div id="ok" class="msg msg-ok" style="margin-top:12px;"></div>
        </div>
      <?php endif; ?>
    </div>

  </div>
</div>

<script>
const TOKEN = <?= json_encode($token) ?>;
const PBKDF2_ITERS = <?= (int)PBKDF2_ITERATIONS ?>;

const STR = {
  failed: <?= json_encode(t('common.failed')) ?>,
  loading: <?= json_encode(t('common.loading')) ?>,
  network_error: <?= json_encode(t('common.network_error')) ?>,

  crypto_unavailable: <?= json_encode(t('crypto.unavailable')) ?>,
  crypto_webcrypto_unavailable: <?= json_encode(t('crypto.webcrypto_unavailable')) ?>,

  err_missing_secret: <?= json_encode(t('receive.err_missing_secret')) ?>,
  err_label_required: <?= json_encode(t('receive.err_label_required')) ?>,
  err_plain_required: <?= json_encode(t('receive.err_plain_required')) ?>,
  err_reveal_required: <?= json_encode(t('receive.err_reveal_required')) ?>,

  submit: <?= json_encode(t('receive.btn_submit')) ?>,
  submitting: <?= json_encode(t('receive.btn_submitting')) ?>,
  submitted: <?= json_encode(t('receive.msg_submitted')) ?>,

  meta_mode_recipient: <?= json_encode(t('receive.meta_mode_recipient')) ?>,
  meta_mode_sender: <?= json_encode(t('receive.meta_mode_sender')) ?>,
  meta_reveal_fixed: <?= json_encode(t('receive.meta_reveal_fixed')) ?>,
  meta_uses: <?= json_encode(t('receive.meta_uses')) ?>,
  meta_expires: <?= json_encode(t('receive.meta_expires')) ?>,

  countdown_reveals_in: <?= json_encode(t('share.countdown_reveals_in')) ?>,
  countdown_eligible: <?= json_encode(t('share.countdown_eligible')) ?>,
};

function apiUrl(url){return url.startsWith('/') ? url.slice(1) : url;}
async function get(url){const r=await fetch(apiUrl(url),{credentials:'same-origin'});return r.json();}
async function post(url, body){
  const r = await fetch(apiUrl(url), {method:'POST', credentials:'same-origin', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)});
  return r.json();
}

function esc(s){return (window.LS && LS.esc) ? LS.esc(s) : String(s||'');}
function parseUtc(ts){return (window.LS && LS.parseUtc) ? LS.parseUtc(ts) : new Date(ts);}
function fmtCountdown(seconds){return (window.LS && LS.fmtCountdown) ? LS.fmtCountdown(seconds) : String(seconds||'');}

function requireWebCrypto(){
  if(!window.crypto || !window.crypto.getRandomValues) throw new Error(STR.crypto_unavailable);
  if(!window.isSecureContext || !window.crypto.subtle) throw new Error(STR.crypto_webcrypto_unavailable);
  return window.crypto;
}

function b64ToBytes(b64){return Uint8Array.from(atob(b64), c => c.charCodeAt(0));}
function bytesToB64(bytes){return btoa(String.fromCharCode(...bytes));}

async function deriveKey(passphrase, kdfSaltB64, iters){
  const c = requireWebCrypto();
  const enc = new TextEncoder();
  const baseKey = await c.subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  const saltBytes = b64ToBytes(kdfSaltB64);
  return c.subtle.deriveKey(
    {name:'PBKDF2', salt:saltBytes, iterations: iters, hash:'SHA-256'},
    baseKey,
    {name:'AES-GCM', length:256},
    false,
    ['encrypt']
  );
}

async function aesEncrypt(plain, key){
  const c = requireWebCrypto();
  const iv = new Uint8Array(12);
  c.getRandomValues(iv);
  const enc = new TextEncoder();
  const ct = new Uint8Array(await c.subtle.encrypt({name:'AES-GCM', iv, tagLength:128}, key, enc.encode(plain)));
  const tag = ct.slice(ct.length - 16);
  const cipher = ct.slice(0, ct.length - 16);
  return {cipher_blob: bytesToB64(cipher), iv: bytesToB64(iv), auth_tag: bytesToB64(tag)};
}

function getSecretFromHash(){
  const raw = String(window.location.hash || '').replace(/^#/, '');
  if(!raw) return '';
  try{
    const p = new URLSearchParams(raw);
    return (p.get('s') || '').trim();
  }catch{
    return '';
  }
}

function setCountdown(revealDateUtc){
  const cd = document.getElementById('countdown');
  if(!cd) return;

  const d = parseUtc(revealDateUtc);
  if(!d || isNaN(d.getTime())) return;

  cd.style.display='block';

  function tick(){
    const now = Date.now();
    const until = d.getTime();
    const s = Math.max(0, Math.floor((until - now)/1000));
    if(s > 0) cd.textContent = STR.countdown_reveals_in.replace('{delta}', fmtCountdown(s));
    else cd.textContent = STR.countdown_eligible;
  }

  tick();
  setInterval(tick, 1000);
}

function setErr(msg){
  const el = document.getElementById('err');
  if(!el) return;
  if(!msg){ el.classList.remove('show'); el.textContent=''; return; }
  el.textContent = String(msg||'');
  el.classList.add('show');
}

function setOk(msg){
  const el = document.getElementById('ok');
  if(!el) return;
  if(!msg){ el.classList.remove('show'); el.textContent=''; return; }
  el.textContent = String(msg||'');
  el.classList.add('show');
}

let linkMeta = null;

async function loadMeta(){
  const metaEl = document.getElementById('meta');
  try{
    const j = await get('api/inbound_links.php?action=meta&t=' + encodeURIComponent(TOKEN));
    if(!j || !j.success) throw new Error((j && j.error) ? j.error : STR.failed);

    linkMeta = j.link || j.meta || j;

    const mode = String(linkMeta.mode || '');
    const fixed = linkMeta.reveal_date_fixed || linkMeta.reveal_date || '';
    const maxUses = (linkMeta.max_uses != null) ? String(linkMeta.max_uses) : '';
    const uses = (linkMeta.uses_count != null) ? String(linkMeta.uses_count) : '';
    const exp = linkMeta.expires_at || '';

    const modeLine = (mode === 'sender_sets_date') ? STR.meta_mode_sender : STR.meta_mode_recipient;

    let html = `<div class="k">${esc(modeLine)}</div>`;
    if(fixed){
      html += `<div class="k" style="margin-top:10px;">${esc(STR.meta_reveal_fixed)}</div><div class="v">${esc(String(fixed))}</div>`;
      setCountdown(fixed);
    }

    if(maxUses){
      html += `<div class="k" style="margin-top:10px;">${esc(STR.meta_uses)}</div><div class="v">${esc(uses ? (uses + ' / ' + maxUses) : maxUses)}</div>`;
    }

    if(exp){
      html += `<div class="k" style="margin-top:10px;">${esc(STR.meta_expires)}</div><div class="v">${esc(String(exp))}</div>`;
    }

    if(metaEl) metaEl.innerHTML = html;

    const secret = getSecretFromHash();
    const missing = document.getElementById('missing-secret');

    if(!secret){
      if(missing){
        missing.textContent = STR.err_missing_secret;
        missing.classList.add('show');
        missing.style.display = 'block';
      }
      return;
    }

    if(missing){
      missing.textContent = '';
      missing.classList.remove('show');
      missing.style.display = 'none';
    }

    const form = document.getElementById('form');
    if(form) form.style.display = 'block';

    const revealField = document.getElementById('reveal-field');
    if(revealField){
      revealField.style.display = (mode === 'sender_sets_date') ? 'block' : 'none';
    }

    if(mode === 'sender_sets_date'){
      const d = new Date(); d.setDate(d.getDate()+1); d.setSeconds(0,0);
      const inp = document.getElementById('reveal-date');
      if(inp) inp.value = d.toISOString().slice(0,16);
    }

  }catch(e){
    if(metaEl){
      metaEl.innerHTML = `<div class="msg msg-err show">${esc((e && e.message) ? e.message : STR.failed)}</div>`;
    }
  }
}

function parseLocalDatetimeAsIso(dtLocal){
  const s = String(dtLocal||'').trim();
  if(!s) return '';
  const d = new Date(s);
  if(isNaN(d.getTime())) return '';
  return d.toISOString();
}

async function doSubmit(){
  setErr('');
  setOk('');

  const secret = getSecretFromHash();
  if(!secret){ setErr(STR.err_missing_secret); return; }

  const label = ((document.getElementById('label')||{}).value || '').trim();
  const plain = ((document.getElementById('plain')||{}).value || '').trim();

  if(!label){ setErr(STR.err_label_required); return; }
  if(!plain){ setErr(STR.err_plain_required); return; }

  const mode = String((linkMeta && linkMeta.mode) ? linkMeta.mode : '');
  let revealIso = '';
  if(mode === 'sender_sets_date'){
    revealIso = parseLocalDatetimeAsIso((document.getElementById('reveal-date')||{}).value || '');
    if(!revealIso){ setErr(STR.err_reveal_required); return; }
  }

  const btn = document.getElementById('btn');
  const btnTxt = document.getElementById('btn-txt');
  const btnIco = document.getElementById('btn-ico');

  if(btn) btn.disabled = true;
  if(btnTxt) btnTxt.textContent = STR.submitting;
  if(btnIco) btnIco.textContent = '⏳';

  try{
    const c = requireWebCrypto();
    const saltBytes = new Uint8Array(32);
    c.getRandomValues(saltBytes);
    const kdf_salt = bytesToB64(saltBytes);

    const key = await deriveKey(secret, kdf_salt, PBKDF2_ITERS);
    const enc = await aesEncrypt(plain, key);

    const payload = {
      action: 'submit',
      t: TOKEN,
      label,
      cipher_blob: enc.cipher_blob,
      iv: enc.iv,
      auth_tag: enc.auth_tag,
      kdf_salt,
      kdf_iterations: PBKDF2_ITERS,
    };

    if(revealIso) payload.reveal_date = revealIso;

    const r = await post('api/inbound_links.php', payload);
    if(!r || !r.success) throw new Error((r && r.error) ? r.error : STR.failed);

    setOk(STR.submitted);

    if(btn) btn.disabled = true;

  }catch(e){
    setErr((e && e.message) ? e.message : STR.network_error);
    if(btn) btn.disabled = false;

  }finally{
    if(btnTxt) btnTxt.textContent = STR.submit;
    if(btnIco) btnIco.textContent = '🔒';
  }
}

document.addEventListener('DOMContentLoaded', ()=>{
  if(!TOKEN) return;
  loadMeta();

  const btn = document.getElementById('btn');
  if(btn) btn.addEventListener('click', doSubmit);
});
</script>

</body>
</html>
