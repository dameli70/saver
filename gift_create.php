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
?>
<!DOCTYPE html>
<html <?= htmlLangAttr() ?>>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title><?= htmlspecialchars(APP_NAME) ?> — <?= htmlspecialchars(t('page.gift_create')) ?></title>
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
        <div class="page-title"><?php e('page.gift_create'); ?></div>
        <div class="page-sub"><?php e('gift_create.page_intro'); ?></div>
      </div>
    </div>

    <div class="card share-card">
      <div class="card-title"><div class="dot"></div><?php e('gift_create.card_title'); ?></div>

      <div id="form">
        <div class="field">
          <label><?php e('gift_create.label_label'); ?> <span style="color:var(--muted);font-size:10px;">(<?php e('common.optional'); ?>)</span></label>
          <input type="text" id="label" maxlength="120" placeholder="<?= htmlspecialchars(t('gift_create.label_placeholder'), ENT_QUOTES, 'UTF-8') ?>">
        </div>

        <div class="field">
          <label><?php e('gift_create.message_label'); ?></label>
          <textarea id="plain" rows="6" placeholder="<?= htmlspecialchars(t('gift_create.message_placeholder'), ENT_QUOTES, 'UTF-8') ?>"></textarea>
        </div>

        <div class="field">
          <label><?php e('create_code.reveal_dt_label'); ?></label>
          <input type="datetime-local" id="reveal-date">
        </div>

        <div id="err" class="msg msg-err"></div>

        <button class="btn btn-primary" type="button" id="btn">
          <span class="btn-ico" id="btn-ico" aria-hidden="true">🎁</span>
          <span class="btn-txt" id="btn-txt"><?php e('gift_create.btn_create'); ?></span>
        </button>
      </div>

      <div id="out" style="display:none;margin-top:14px;">
        <div class="field" style="margin-top:0;">
          <label><?php e('gift_create.link_label'); ?></label>
          <input type="text" id="out-url" readonly>
        </div>
        <button class="btn btn-ghost" type="button" id="copy" style="margin-top:10px;">
          <span class="btn-ico" aria-hidden="true">⧉</span>
          <span class="btn-txt"><?php e('common.copy'); ?></span>
        </button>
        <div class="small" style="margin-top:10px;"><?php e('gift_create.note'); ?></div>
      </div>
    </div>

  </div>
</div>

<script>
const PBKDF2_ITERS = <?= (int)PBKDF2_ITERATIONS ?>;
const BASE_URL = <?= json_encode(getAppBaseUrl()) ?>;

const STR = {
  failed: <?= json_encode(t('common.failed')) ?>,
  network_error: <?= json_encode(t('common.network_error')) ?>,

  crypto_unavailable: <?= json_encode(t('crypto.unavailable')) ?>,
  crypto_webcrypto_unavailable: <?= json_encode(t('crypto.webcrypto_unavailable')) ?>,

  err_plain_required: <?= json_encode(t('gift_create.err_plain_required')) ?>,
  err_reveal_required: <?= json_encode(t('gift_create.err_reveal_required')) ?>,

  create: <?= json_encode(t('gift_create.btn_create')) ?>,
  creating: <?= json_encode(t('gift_create.btn_creating')) ?>,
  created: <?= json_encode(t('gift_create.toast_created')) ?>,
  copied: <?= json_encode(t('gift_create.toast_copied')) ?>,
};

function apiUrl(url){return url.startsWith('/') ? url.slice(1) : url;}
async function post(url, body){
  const r = await fetch(apiUrl(url), {method:'POST', credentials:'same-origin', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)});
  return r.json();
}

function toast(msg, type='ok'){
  if(window.LS && LS.toast) return LS.toast(msg, type);
  const t=document.createElement('div');t.className=`toast ${type}`;t.textContent=String(msg||'');document.body.appendChild(t);setTimeout(()=>t.remove(),3200);
}

function setErr(msg){
  const el = document.getElementById('err');
  if(!el) return;
  if(!msg){ el.classList.remove('show'); el.textContent=''; return; }
  el.textContent = String(msg||'');
  el.classList.add('show');
}

function requireWebCrypto(){
  if(!window.crypto || !window.crypto.getRandomValues) throw new Error(STR.crypto_unavailable);
  if(!window.isSecureContext || !window.crypto.subtle) throw new Error(STR.crypto_webcrypto_unavailable);
  return window.crypto;
}

function b64ToBytes(b64){return Uint8Array.from(atob(b64), c => c.charCodeAt(0));}
function bytesToB64(bytes){return btoa(String.fromCharCode(...bytes));}

function bytesToHex(bytes){
  return Array.from(bytes).map(b => b.toString(16).padStart(2,'0')).join('');
}

function formatSecret(hex){
  const parts = String(hex||'').match(/.{1,4}/g);
  return parts ? parts.join('-') : String(hex||'');
}

function genSecret(){
  const c = requireWebCrypto();
  const b = new Uint8Array(16);
  c.getRandomValues(b);
  return formatSecret(bytesToHex(b));
}

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

function parseLocalDatetimeAsIso(dtLocal){
  const s = String(dtLocal||'').trim();
  if(!s) return '';
  const d = new Date(s);
  if(isNaN(d.getTime())) return '';
  return d.toISOString();
}

async function doCreate(){
  setErr('');

  const label = ((document.getElementById('label')||{}).value || '').trim();
  const plain = ((document.getElementById('plain')||{}).value || '').trim();
  const revealIso = parseLocalDatetimeAsIso((document.getElementById('reveal-date')||{}).value || '');

  if(!plain){ setErr(STR.err_plain_required); return; }
  if(!revealIso){ setErr(STR.err_reveal_required); return; }

  const btn = document.getElementById('btn');
  const btnTxt = document.getElementById('btn-txt');
  const btnIco = document.getElementById('btn-ico');

  if(btn) btn.disabled = true;
  if(btnTxt) btnTxt.textContent = STR.creating;
  if(btnIco) btnIco.textContent = '⏳';

  try{
    const secret = genSecret();

    const c = requireWebCrypto();
    const saltBytes = new Uint8Array(32);
    c.getRandomValues(saltBytes);
    const kdf_salt = bytesToB64(saltBytes);

    const key = await deriveKey(secret, kdf_salt, PBKDF2_ITERS);

    const payloadPlain = JSON.stringify({label, message: plain});
    const enc = await aesEncrypt(payloadPlain, key);

    const r = await post('api/gifts.php', {
      action: 'create',
      reveal_date: revealIso,
      cipher_blob: enc.cipher_blob,
      iv: enc.iv,
      auth_tag: enc.auth_tag,
      kdf_salt,
      kdf_iterations: PBKDF2_ITERS,
    });

    if(!r || !r.success) throw new Error((r && r.error) ? r.error : STR.failed);

    const token = r.token || r.t || '';
    const viewUrl = r.gift_url || r.view_url || (token ? (BASE_URL + '/gift.php?t=' + encodeURIComponent(token)) : '');
    if(!viewUrl) throw new Error(STR.failed);

    const finalUrl = viewUrl + '#s=' + encodeURIComponent(secret);

    const out = document.getElementById('out');
    const outUrl = document.getElementById('out-url');

    if(outUrl) outUrl.value = finalUrl;
    if(out) out.style.display = 'block';

    const form = document.getElementById('form');
    if(form) form.style.display = 'none';

    toast(STR.created, 'ok');

  }catch(e){
    setErr((e && e.message) ? e.message : STR.network_error);

  }finally{
    if(btnTxt) btnTxt.textContent = STR.create;
    if(btnIco) btnIco.textContent = '🎁';
    if(btn) btn.disabled = false;
  }
}

async function doCopy(){
  const v = (document.getElementById('out-url')||{}).value || '';
  if(!v) return;

  try{
    if(window.LS && typeof LS.copySensitive === 'function'){
      const ok = await LS.copySensitive(v, {clearAfterMs: 0});
      if(!ok) return;
    }else{
      await navigator.clipboard.writeText(v);
    }
    toast(STR.copied, 'ok');
  }catch{
    toast(STR.failed, 'err');
  }
}

document.addEventListener('DOMContentLoaded', ()=>{
  const d = new Date(); d.setDate(d.getDate()+1); d.setSeconds(0,0);
  const inp = document.getElementById('reveal-date');
  if(inp) inp.value = d.toISOString().slice(0,16);

  const btn = document.getElementById('btn');
  if(btn) btn.addEventListener('click', doCreate);

  const copy = document.getElementById('copy');
  if(copy) copy.addEventListener('click', doCopy);
});
</script>

</body>
</html>
