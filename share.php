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
<title><?= htmlspecialchars(APP_NAME) ?> — Share</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Space+Grotesk:wght@500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet">
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
  <div class="topbar">
    <div class="topbar-logo"><?= htmlspecialchars(APP_NAME) ?></div>
    <div class="topbar-r">
      <a class="btn btn-ghost btn-sm" href="index.php"><?php e('common.home'); ?></a>
      <a class="btn btn-primary btn-sm" href="login.php"><?php e('common.login'); ?></a>
    </div>
  </div>

  <div class="app-body">
    <div class="card share-card">
      <div class="card-title"><div class="dot"></div>Shared time lock</div>

      <?php if ($token === ''): ?>
        <div class="msg msg-err show">Invalid link (missing token).</div>
      <?php else: ?>
        <div class="share-meta" id="sh-meta">Loading…</div>

        <div class="share-countdown" id="sh-countdown" style="display:none;"></div>

        <div class="share-secret" id="sh-secret-wrap" style="display:none;">
          <label>Share secret</label>
          <input type="password" id="sh-secret" placeholder="Paste the secret…" autocomplete="off">
          <button class="btn btn-primary" id="sh-decrypt"><span class="btn-ico" id="sh-decrypt-ico" aria-hidden="true">🔒</span><span class="btn-txt" id="sh-decrypt-txt">Decrypt</span></button>
          <div id="sh-err" class="msg msg-err"></div>
        </div>

        <div class="share-plain" id="sh-plain" style="display:none;"></div>
        <button class="btn btn-ghost" id="sh-copy" style="display:none;margin-top:10px;"><span class="btn-ico" aria-hidden="true">⧉</span><span class="btn-txt">Copy</span></button>

        <div class="small" id="sh-note" style="display:none;margin-top:10px;">
          Zero-knowledge: decryption happens only in your browser. The server never sees the secret or plaintext.
        </div>
      <?php endif; ?>
    </div>
  </div>
</div>

<script>
const TOKEN = <?= json_encode($token) ?>;

let sharePayload = null;
let revealed = null;

const reduceMotion = (()=>{
  try{ return window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches; }
  catch{ return false; }
})();

function apiUrl(url){return url.startsWith('/') ? url.slice(1) : url;}
async function get(url){const r=await fetch(apiUrl(url),{credentials:'same-origin'});return r.json();}

function esc(s){return (window.LS && LS.esc) ? LS.esc(s) : String(s||'');}

function parseUtc(ts){
  return (window.LS && LS.parseUtc) ? LS.parseUtc(ts) : new Date(ts);
}

function fmtCountdown(seconds){
  if(window.LS && LS.fmtCountdown) return LS.fmtCountdown(seconds);
  return String(seconds||'');
}

function b64ToBytes(b64){return Uint8Array.from(atob(b64), c => c.charCodeAt(0));}
function bytesToB64(bytes){return btoa(String.fromCharCode(...bytes));}

function requireWebCrypto(){
  if (!window.crypto || !window.crypto.getRandomValues) throw new Error('Secure cryptography is unavailable in this browser.');
  if (!window.isSecureContext || !window.crypto.subtle) throw new Error('Web Crypto API is unavailable. Use HTTPS (or localhost).');
  return window.crypto;
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
    ['encrypt','decrypt']
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

function setBtnState(btn, icoEl, txtEl, state, ico, txt){
  if(!btn) return;
  if(state) btn.setAttribute('data-state', state);
  else btn.removeAttribute('data-state');
  if(icoEl) icoEl.textContent = ico || '';
  if(txtEl) txtEl.textContent = txt || '';
}

function setErr(msg){
  const el = document.getElementById('sh-err');
  if(!el) return;
  if(!msg){ el.classList.remove('show'); el.textContent=''; return; }
  el.textContent = msg;
  el.classList.add('show');
}

function setCountdown(revealDateUtc){
  const cd = document.getElementById('sh-countdown');
  if(!cd) return;

  const d = parseUtc(revealDateUtc);
  if(!d || isNaN(d.getTime())) return;

  cd.style.display='block';

  function tick(){
    const now = Date.now();
    const until = d.getTime();
    const s = Math.max(0, Math.floor((until - now)/1000));
    if(s > 0) cd.textContent = `⏱ Reveals in ${fmtCountdown(s)}`;
    else cd.textContent = '⏱ Reveal eligible';
  }

  tick();
  setInterval(tick, 1000);
}

async function loadShare(){
  const meta = document.getElementById('sh-meta');

  try{
    const j = await get('api/share.php?t=' + encodeURIComponent(TOKEN));
    if(!j.success) throw new Error(j.error||'Failed');

    sharePayload = j;

    const lock = j.lock || {};
    const label = lock.label ? esc(lock.label) : 'Time lock';
    const revealAt = lock.reveal_date ? esc(lock.reveal_date) : '';

    if(meta){
      meta.innerHTML = `<div class="k">Label</div><div class="v">${label}</div>` + (revealAt ? `<div class="k" style="margin-top:10px;">Reveal (UTC)</div><div class="v">${revealAt}</div>` : '');
    }

    if(lock.reveal_date) setCountdown(lock.reveal_date);

    if(j.locked){
      return;
    }

    const wrap = document.getElementById('sh-secret-wrap');
    if(wrap) wrap.style.display='block';

  }catch(e){
    if(meta){
      meta.innerHTML = `<div class="msg msg-err show">${esc(e && e.message ? e.message : 'Invalid link')}</div>`;
    }
  }
}

async function doDecrypt(){
  if(!sharePayload || !sharePayload.share) return;

  const secret = (document.getElementById('sh-secret').value||'').trim();
  if(!secret){ setErr('Enter the share secret'); return; }

  const btn = document.getElementById('sh-decrypt');
  const ico = document.getElementById('sh-decrypt-ico');
  const txt = document.getElementById('sh-decrypt-txt');

  setErr('');
  setBtnState(btn, ico, txt, 'working', '⏳', 'Decrypting…');
  btn.disabled = true;

  try{
    const s = sharePayload.share;
    const key = await deriveKey(secret, s.share_kdf_salt, parseInt(s.share_kdf_iterations||310000,10)||310000);
    const plain = await aesDecrypt(s.share_cipher_blob, s.share_iv, s.share_auth_tag, key);

    revealed = plain;

    const out = document.getElementById('sh-plain');
    out.textContent = plain;
    out.style.display='block';

    const copy = document.getElementById('sh-copy');
    const note = document.getElementById('sh-note');
    if(copy) copy.style.display='inline-flex';
    if(note) note.style.display='block';

    setBtnState(btn, ico, txt, 'success', '☺', 'Decrypted');

  }catch(e){
    setErr((e && e.name==='OperationError') ? 'Decryption failed — wrong secret or tampered data' : ((e && e.message) ? e.message : 'Decryption failed'));
    setBtnState(btn, ico, txt, 'error', '⚠', 'Failed');

  }finally{
    setTimeout(()=>{
      setBtnState(btn, ico, txt, null, '🔒', 'Decrypt');
      btn.disabled = false;
    }, 900);
  }
}

async function copyPlain(){
  if(!revealed) return;
  try{
    if(window.LS && LS.copySensitive){
      const ok = await LS.copySensitive(revealed, {clearAfterMs: 30000});
      if(!ok) return;
    }else{
      await navigator.clipboard.writeText(revealed);
    }
    if(window.LS && LS.toast) LS.toast('Copied (will try to clear in ~30s)','ok');
  }catch{
    if(window.LS && LS.toast) LS.toast('Select the text manually','err');
  }
}

document.addEventListener('DOMContentLoaded', ()=>{
  if(!TOKEN) return;
  loadShare();

  const btn = document.getElementById('sh-decrypt');
  if(btn) btn.addEventListener('click', doDecrypt);

  const copy = document.getElementById('sh-copy');
  if(copy) copy.addEventListener('click', copyPlain);
});
</script>

</body>
</html>
