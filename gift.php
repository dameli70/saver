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
<title><?= htmlspecialchars(APP_NAME) ?> — <?= htmlspecialchars(t('page.gift')) ?></title>
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
        <div class="page-title" id="title"><?php e('page.gift'); ?></div>
        <div class="page-sub"><?php e('gift.page_intro'); ?></div>
      </div>
    </div>

    <div class="card share-card">
      <div class="card-title"><div class="dot"></div><?php e('gift.card_title'); ?></div>

      <?php if ($token === ''): ?>
        <div class="msg msg-err show"><?php e('gift.invalid_link'); ?></div>
      <?php else: ?>
        <div class="share-meta" id="meta"><?php e('common.loading'); ?></div>
        <div class="share-countdown" id="countdown" style="display:none;"></div>

        <div id="missing-secret" class="msg msg-err" style="display:none;"></div>

        <div id="plain" class="share-plain" style="display:none;"></div>
        <div id="err" class="msg msg-err"></div>
      <?php endif; ?>
    </div>

  </div>
</div>

<script>
const TOKEN = <?= json_encode($token) ?>;

const STR = {
  failed: <?= json_encode(t('common.failed')) ?>,
  loading: <?= json_encode(t('common.loading')) ?>,

  crypto_unavailable: <?= json_encode(t('crypto.unavailable')) ?>,
  crypto_webcrypto_unavailable: <?= json_encode(t('crypto.webcrypto_unavailable')) ?>,

  err_missing_secret: <?= json_encode(t('gift.err_missing_secret')) ?>,

  meta_reveal_utc: <?= json_encode(t('share.reveal_utc')) ?>,

  countdown_reveals_in: <?= json_encode(t('share.countdown_reveals_in')) ?>,
  countdown_eligible: <?= json_encode(t('share.countdown_eligible')) ?>,

  locked: <?= json_encode(t('gift.meta_locked')) ?>,
  unlocked: <?= json_encode(t('gift.meta_unlocked')) ?>,
};

function apiUrl(url){return url.startsWith('/') ? url.slice(1) : url;}
async function get(url){const r=await fetch(apiUrl(url),{credentials:'same-origin'});return r.json();}

function esc(s){return (window.LS && LS.esc) ? LS.esc(s) : String(s||'');}
function parseUtc(ts){return (window.LS && LS.parseUtc) ? LS.parseUtc(ts) : new Date(ts);}
function fmtCountdown(seconds){return (window.LS && LS.fmtCountdown) ? LS.fmtCountdown(seconds) : String(seconds||'');}

function requireWebCrypto(){
  if(!window.crypto || !window.crypto.getRandomValues) throw new Error(STR.crypto_unavailable);
  if(!window.isSecureContext || !window.crypto.subtle) throw new Error(STR.crypto_webcrypto_unavailable);
  return window.crypto;
}

function b64ToBytes(b64){return Uint8Array.from(atob(b64), c => c.charCodeAt(0));}

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
    ['decrypt']
  );
}

async function aesDecrypt(cipherBlobB64, ivB64, tagB64, key){
  const c = requireWebCrypto();
  const cipher = b64ToBytes(cipherBlobB64);
  const iv = b64ToBytes(ivB64);
  const tag = b64ToBytes(tagB64);
  const data = new Uint8Array(cipher.length + tag.length);
  data.set(cipher, 0);
  data.set(tag, cipher.length);
  const pt = await c.subtle.decrypt({name:'AES-GCM', iv, tagLength:128}, key, data);
  return new TextDecoder().decode(pt);
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

function showErr(msg){
  const el = document.getElementById('err');
  if(!el) return;
  if(!msg){ el.classList.remove('show'); el.textContent=''; return; }
  el.textContent = String(msg||'');
  el.classList.add('show');
}

async function loadGift(){
  const metaEl = document.getElementById('meta');

  try{
    const j = await get('api/gifts.php?action=view&t=' + encodeURIComponent(TOKEN));
    if(!j || !j.success) throw new Error((j && j.error) ? j.error : STR.failed);

    const gift = j.gift || j;

    const revealAt = gift.reveal_date || '';
    const locked = !!(j.locked != null ? j.locked : gift.locked);

    let html = '';
    if(revealAt){
      html += `<div class="k">${esc(STR.meta_reveal_utc)}</div><div class="v">${esc(String(revealAt))}</div>`;
      setCountdown(revealAt);
    }

    html += `<div class="k" style="margin-top:10px;">${esc(locked ? STR.locked : STR.unlocked)}</div>`;

    if(metaEl) metaEl.innerHTML = html;

    if(locked){
      return;
    }

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

    const key = await deriveKey(secret, gift.kdf_salt, parseInt(gift.kdf_iterations || '0', 10) || 310000);
    const plain = await aesDecrypt(gift.cipher_blob, gift.iv, gift.auth_tag, key);

    let label = '';
    let message = plain;

    try{
      const o = JSON.parse(plain);
      if(o && typeof o === 'object'){
        label = (o.label != null) ? String(o.label) : '';
        message = (o.message != null) ? String(o.message) : plain;
      }
    }catch{}

    const title = document.getElementById('title');
    if(title && label.trim()) title.textContent = label.trim();

    const out = document.getElementById('plain');
    if(out){
      out.textContent = message;
      out.style.display = 'block';
    }

  }catch(e){
    if(metaEl){
      metaEl.innerHTML = `<div class="msg msg-err show">${esc((e && e.message) ? e.message : STR.failed)}</div>`;
    }
    showErr('');
  }
}

document.addEventListener('DOMContentLoaded', ()=>{
  if(!TOKEN) return;
  loadGift();
});
</script>

</body>
</html>
