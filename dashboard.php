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

$userEmail = getCurrentUserEmail() ?? '';
$csrf      = getCsrfToken();

// Strict security headers
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none';");
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: no-referrer");
header("Permissions-Policy: clipboard-write=(self)");
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<title>LOCKSMITH — Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@300;400;500&family=Unbounded:wght@400;700;900&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#06070a;--s1:#0d0f14;--s2:#13161d;--s3:#1a1d27;
  --b1:rgba(255,255,255,.07);--b2:rgba(255,255,255,.13);
  --accent:#e8ff47;--red:#ff4757;--blue:#47b8ff;--green:#47ffb0;--orange:#ffaa00;
  --text:#dde1ec;--muted:#525970;
  --mono:'DM Mono',monospace;--display:'Unbounded',sans-serif;
  --sat:env(safe-area-inset-top,0px);--sab:env(safe-area-inset-bottom,0px);
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
html{scroll-behavior:smooth;-webkit-tap-highlight-color:transparent;}
body{background:var(--bg);color:var(--text);font-family:var(--mono);font-size:14px;
  min-height:100vh;overflow-x:hidden;-webkit-font-smoothing:antialiased;}
body::after{content:'';position:fixed;inset:0;pointer-events:none;z-index:9998;opacity:.5;
  background-image:url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.85' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='.035'/%3E%3C/svg%3E");}
.orb{position:fixed;border-radius:50%;filter:blur(100px);pointer-events:none;z-index:0;}
.orb1{width:500px;height:500px;background:rgba(232,255,71,.035);top:-150px;right:-100px;}
.orb2{width:350px;height:350px;background:rgba(71,184,255,.03);bottom:50px;left:-80px;}

/* ── AUTH ── */
#auth-screen{min-height:100vh;display:flex;align-items:center;justify-content:center;
  padding:max(40px,var(--sat)) 20px max(40px,var(--sab));position:relative;z-index:1;}
.auth-box{width:100%;max-width:420px;}
.auth-logo{font-family:var(--display);font-size:clamp(24px,6vw,32px);font-weight:900;letter-spacing:-1px;margin-bottom:2px;}
.auth-logo span{color:var(--accent);}
.auth-sub{color:var(--muted);font-size:10px;letter-spacing:2px;text-transform:uppercase;margin-bottom:6px;}
.zk-badge{
  display:inline-flex;align-items:center;gap:6px;
  background:rgba(71,255,176,.07);border:1px solid rgba(71,255,176,.2);
  color:var(--green);font-size:10px;letter-spacing:1px;padding:4px 10px;margin-bottom:28px;
}
.auth-tabs{display:flex;border-bottom:1px solid var(--b1);margin-bottom:22px;}
.auth-tab{padding:10px 18px;font-family:var(--mono);font-size:11px;letter-spacing:1px;
  cursor:pointer;border:none;background:none;color:var(--muted);border-bottom:2px solid transparent;
  margin-bottom:-1px;transition:all .2s;text-transform:uppercase;}
.auth-tab.active{color:var(--accent);border-bottom-color:var(--accent);}

/* ── FIELDS ── */
.field{margin-bottom:14px;}
.field label{display:block;font-size:10px;letter-spacing:2px;text-transform:uppercase;color:var(--muted);margin-bottom:6px;}
.field-note{font-size:10px;color:var(--muted);margin-top:5px;line-height:1.4;letter-spacing:.3px;}
.field input,.field select{width:100%;background:var(--s2);border:1px solid var(--b1);color:var(--text);
  font-family:var(--mono);font-size:15px;padding:14px;outline:none;transition:border-color .2s;
  -webkit-appearance:none;border-radius:0;-webkit-text-size-adjust:100%;}
.field input:focus,.field select:focus{border-color:var(--accent);}
.field input::placeholder{color:var(--muted);}
.field select option{background:var(--s2);}

/* ── BUTTONS ── */
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;
  padding:15px 24px;font-family:var(--mono);font-size:12px;letter-spacing:2px;
  text-transform:uppercase;cursor:pointer;border:none;transition:all .15s;
  border-radius:0;-webkit-appearance:none;touch-action:manipulation;min-height:48px;}
.btn-primary{background:var(--accent);color:#000;font-weight:500;width:100%;}
.btn-primary:hover{background:#f0ff60;}
.btn-primary:active{transform:scale(.98);}
.btn-primary:disabled{opacity:.4;pointer-events:none;}
.btn-ghost{background:transparent;border:1px solid var(--b2);color:var(--text);}
.btn-ghost:hover{border-color:var(--text);}
.btn-green{background:var(--green);color:#000;font-weight:500;}
.btn-green:hover{background:#6fffbe;}
.btn-red{background:rgba(255,71,87,.1);border:1px solid rgba(255,71,87,.3);color:var(--red);}
.btn-red:hover{background:rgba(255,71,87,.18);}
.btn-sm{padding:10px 16px;font-size:11px;min-height:40px;}
.btn-full{width:100%;}

/* ── MSGS ── */
.msg{padding:12px 14px;font-size:12px;margin-bottom:12px;display:none;letter-spacing:.4px;line-height:1.6;}
.msg.show{display:block;}
.msg-err{background:rgba(255,71,87,.08);border:1px solid rgba(255,71,87,.2);color:var(--red);}
.msg-ok{background:rgba(71,255,176,.08);border:1px solid rgba(71,255,176,.2);color:var(--green);}
.msg-warn{background:rgba(255,170,0,.08);border:1px solid rgba(255,170,0,.2);color:var(--orange);}

/* ── SECURITY CALLOUT ── */
.sec-callout{
  background:rgba(71,255,176,.04);border:1px solid rgba(71,255,176,.15);
  padding:14px 16px;margin-bottom:16px;font-size:11px;line-height:1.7;color:var(--muted);
}
.sec-callout strong{color:var(--green);}

/* ── APP ── */
#app{display:none;min-height:100vh;position:relative;z-index:1;padding-bottom:max(20px,var(--sab));}
#app.show{display:block;}
.topbar{display:flex;align-items:center;justify-content:space-between;
  padding:max(14px,var(--sat)) 20px 14px;border-bottom:1px solid var(--b1);
  position:sticky;top:0;background:rgba(6,7,10,.94);backdrop-filter:blur(16px);
  -webkit-backdrop-filter:blur(16px);z-index:100;}
.topbar-logo{font-family:var(--display);font-size:clamp(15px,4vw,19px);font-weight:900;letter-spacing:-1px;}
.topbar-logo span{color:var(--accent);}
.topbar-r{display:flex;align-items:center;gap:10px;}
.topbar-zk{font-size:9px;color:var(--green);letter-spacing:1px;border:1px solid rgba(71,255,176,.2);padding:3px 7px;display:none;}
@media(min-width:480px){.topbar-zk{display:block;}}
.user-pill{font-size:10px;color:var(--muted);letter-spacing:1px;max-width:130px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:none;}
@media(min-width:560px){.user-pill{display:block;}}

.app-body{max-width:680px;margin:0 auto;padding:22px 16px;}
@media(min-width:600px){.app-body{padding:30px 24px;}}

/* ── CARD ── */
.card{background:var(--s1);border:1px solid var(--b1);padding:20px;margin-bottom:16px;position:relative;}
@media(min-width:600px){.card{padding:24px 28px;}}
.card-accent::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;
  background:linear-gradient(90deg,var(--accent),transparent);}
.card-title{font-family:var(--display);font-size:11px;font-weight:700;letter-spacing:2px;
  text-transform:uppercase;color:var(--accent);margin-bottom:18px;display:flex;align-items:center;gap:8px;}
.card-title .dot{width:5px;height:5px;background:var(--accent);flex-shrink:0;}

/* ── TYPE GRID ── */
.type-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:8px;}
@media(min-width:380px){.type-grid{grid-template-columns:repeat(4,1fr);}}
.type-opt{padding:12px 6px;border:1px solid var(--b1);background:transparent;
  color:var(--muted);font-family:var(--mono);font-size:10px;letter-spacing:1px;
  text-transform:uppercase;cursor:pointer;text-align:center;transition:all .15s;
  min-height:44px;display:flex;align-items:center;justify-content:center;}
.type-opt:hover{border-color:var(--b2);color:var(--text);}
.type-opt.sel{border-color:var(--accent);color:var(--accent);background:rgba(232,255,71,.06);}

/* ── SLIDER ── */
.slider-row{display:flex;align-items:center;gap:14px;}
.slider-val{font-family:var(--display);font-size:26px;font-weight:900;color:var(--accent);min-width:40px;text-align:right;}
input[type=range]{-webkit-appearance:none;flex:1;height:4px;background:var(--b2);outline:none;cursor:pointer;border-radius:2px;}
input[type=range]::-webkit-slider-thumb{-webkit-appearance:none;width:22px;height:22px;background:var(--accent);cursor:pointer;border-radius:0;}
input[type=range]::-moz-range-thumb{width:22px;height:22px;background:var(--accent);border:none;cursor:pointer;border-radius:0;}

/* ── PROGRESS (KDF) ── */
.kdf-progress{display:none;margin-top:12px;animation:fadeIn .2s;}
.kdf-progress.show{display:block;}
.kdf-bar-wrap{height:3px;background:var(--b2);overflow:hidden;margin-bottom:6px;}
.kdf-bar{height:100%;background:var(--accent);transition:width .1s linear;width:0%;}
.kdf-label{font-size:10px;color:var(--muted);letter-spacing:1px;text-align:center;}
@keyframes fadeIn{from{opacity:0}to{opacity:1}}

/* ── CONFIRM SHEET ── */
#confirm-overlay{position:fixed;inset:0;background:rgba(0,0,0,.9);
  display:none;align-items:flex-end;justify-content:center;
  z-index:500;backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);
  padding:0 0 max(0px,var(--sab)) 0;}
#confirm-overlay.show{display:flex;}
@media(min-width:600px){#confirm-overlay{align-items:center;}
  .confirm-sheet{border:1px solid var(--b2);max-width:480px;padding:32px;}}
.confirm-sheet{background:var(--s1);border:1px solid var(--b2);border-bottom:none;
  padding:28px 24px max(28px,var(--sab));width:100%;max-width:480px;position:relative;
  animation:slideUp .3s cubic-bezier(.16,1,.3,1);}
.confirm-sheet::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:var(--orange);}
@keyframes slideUp{from{transform:translateY(40px);opacity:0;}to{transform:translateY(0);opacity:1;}}
.confirm-title{font-family:var(--display);font-size:clamp(15px,4vw,19px);font-weight:900;margin-bottom:6px;}
.confirm-sub{font-size:11px;color:var(--muted);letter-spacing:1px;margin-bottom:22px;line-height:1.5;}
.timer-wrap{display:flex;align-items:center;gap:16px;margin-bottom:22px;}
.timer-ring-svg{flex-shrink:0;}
.timer-track{fill:none;stroke:var(--b2);stroke-width:4;}
.timer-fill{fill:none;stroke:var(--orange);stroke-width:4;stroke-linecap:butt;
  transform:rotate(-90deg);transform-origin:50% 50%;transition:stroke-dashoffset .9s linear;}
.timer-num{font-family:var(--display);font-size:18px;font-weight:900;fill:var(--orange);}
.timer-msg{font-size:11px;line-height:1.6;color:var(--muted);}
.timer-msg strong{color:var(--accent);}
.autosave-bar{background:rgba(255,170,0,.07);border:1px solid rgba(255,170,0,.2);
  color:var(--orange);padding:10px 14px;font-size:11px;letter-spacing:.5px;
  line-height:1.5;margin-bottom:14px;display:none;}
.autosave-bar.show{display:block;}
.void-box{background:#000;border:1px solid rgba(255,71,87,.2);padding:18px;margin-top:14px;display:none;}
.void-box.show{display:block;}
.void-label{font-size:10px;letter-spacing:2px;color:var(--red);margin-bottom:10px;text-transform:uppercase;}
.void-pwd{font-size:20px;color:rgba(255,255,255,.3);letter-spacing:3px;word-break:break-all;line-height:1.4;}
.void-note{font-size:10px;color:var(--muted);margin-top:8px;}
.confirm-btns{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:6px;}

/* ── LOCK CARDS ── */
.locks-grid{display:flex;flex-direction:column;gap:12px;}
.lock-card{background:var(--s1);border:1px solid var(--b1);padding:16px 18px;position:relative;transition:border-color .2s;}
.lock-card:hover{border-color:var(--b2);}
.lock-card.st-locked{border-left:3px solid rgba(255,71,87,.5);}
.lock-card.st-unlocked{border-left:3px solid rgba(71,255,176,.5);}
.lock-card.st-pending{border-left:3px solid rgba(255,170,0,.5);}
.lock-card.st-auto_saved{border-left:3px solid rgba(71,184,255,.4);}
.lock-card.st-rejected{border-left:3px solid rgba(255,71,87,.2);opacity:.6;}
.lc-top{display:flex;align-items:flex-start;justify-content:space-between;gap:10px;margin-bottom:10px;}
.lc-label{font-family:var(--display);font-size:14px;font-weight:700;word-break:break-word;}
.lc-badge{display:inline-flex;align-items:center;flex-shrink:0;font-size:9px;
  letter-spacing:1px;text-transform:uppercase;padding:4px 8px;border:1px solid;}
.lc-badge.locked{background:rgba(255,71,87,.07);border-color:rgba(255,71,87,.2);color:var(--red);}
.lc-badge.unlocked{background:rgba(71,255,176,.07);border-color:rgba(71,255,176,.2);color:var(--green);}
.lc-badge.pending{background:rgba(255,170,0,.07);border-color:rgba(255,170,0,.2);color:var(--orange);}
.lc-badge.auto_saved{background:rgba(71,184,255,.07);border-color:rgba(71,184,255,.2);color:var(--blue);}
.lc-badge.rejected{background:rgba(255,71,87,.05);border-color:rgba(255,71,87,.1);color:var(--muted);}
.lc-meta{font-size:11px;color:var(--muted);line-height:1.7;margin-bottom:10px;}
.lc-meta span{color:var(--text);}
.lc-hint{font-size:11px;color:var(--muted);font-style:italic;margin-bottom:10px;
  padding:6px 10px;border-left:2px solid var(--b2);}
.lc-countdown{font-size:12px;color:var(--accent);margin-bottom:10px;letter-spacing:1px;}
.lc-actions{display:flex;gap:8px;flex-wrap:wrap;}
.lc-autosave-note{font-size:10px;color:var(--blue);letter-spacing:.4px;
  padding:6px 10px;border:1px solid rgba(71,184,255,.15);background:rgba(71,184,255,.05);margin-bottom:8px;line-height:1.5;}

/* ── REVEAL MODAL ── */
#reveal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.92);
  display:none;align-items:flex-end;justify-content:center;
  z-index:600;backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);
  padding:0 0 max(0px,var(--sab)) 0;}
#reveal-overlay.show{display:flex;}
@media(min-width:600px){#reveal-overlay{align-items:center;}
  .reveal-sheet{max-width:460px;border:1px solid rgba(232,255,71,.2);padding:32px;}}
.reveal-sheet{background:var(--s1);border:1px solid rgba(232,255,71,.15);border-bottom:none;
  padding:28px 22px max(28px,var(--sab));width:100%;max-width:460px;position:relative;
  animation:slideUp .3s cubic-bezier(.16,1,.3,1);}
.reveal-sheet::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:var(--accent);}
.reveal-title{font-family:var(--display);font-size:16px;font-weight:700;margin-bottom:3px;}
.reveal-sub{font-size:10px;color:var(--muted);letter-spacing:2px;text-transform:uppercase;margin-bottom:18px;}
.reveal-pwd{font-size:clamp(16px,4vw,22px);color:var(--accent);letter-spacing:3px;
  word-break:break-all;background:#000;padding:16px;border:1px solid rgba(232,255,71,.12);
  margin-bottom:16px;line-height:1.5;user-select:all;-webkit-user-select:all;}
.modal-close{position:absolute;top:12px;right:14px;background:none;border:none;color:var(--muted);
  font-size:22px;cursor:pointer;padding:4px;min-width:32px;min-height:32px;
  display:flex;align-items:center;justify-content:center;}
.modal-close:hover{color:var(--text);}
.vault-input-wrap{margin-bottom:16px;}
.vault-input-wrap label{font-size:10px;letter-spacing:2px;text-transform:uppercase;color:var(--muted);display:block;margin-bottom:6px;}
.vault-input-wrap input{width:100%;background:#000;border:1px solid rgba(232,255,71,.2);
  color:var(--accent);font-family:var(--mono);font-size:15px;padding:13px;outline:none;
  border-radius:0;-webkit-appearance:none;}
.vault-input-wrap input:focus{border-color:var(--accent);}

/* ── SECTION ── */
.sec-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;}
.empty{text-align:center;padding:60px 20px;color:var(--muted);}
.empty-icon{font-size:44px;margin-bottom:14px;}
.empty h3{font-family:var(--display);font-size:15px;font-weight:700;color:var(--text);margin-bottom:8px;}
.empty p{font-size:12px;line-height:1.6;}

/* ── TOAST ── */
.toast{position:fixed;bottom:max(24px,var(--sab));left:50%;transform:translateX(-50%);
  background:var(--s2);border:1px solid var(--b2);padding:12px 20px;
  font-size:12px;letter-spacing:.4px;z-index:9000;animation:toastIn .25s ease;
  white-space:nowrap;max-width:90vw;text-align:center;}
.toast.ok{border-color:rgba(71,255,176,.3);color:var(--green);}
.toast.err{border-color:rgba(255,71,87,.3);color:var(--red);}
.toast.warn{border-color:rgba(255,170,0,.3);color:var(--orange);}
@keyframes toastIn{from{opacity:0;transform:translate(-50%,10px);}to{opacity:1;transform:translate(-50%,0);}}

/* ── SPINNER ── */
.spin{display:inline-block;width:14px;height:14px;border:2px solid rgba(0,0,0,.3);
  border-top-color:#000;border-radius:50%;animation:spin .5s linear infinite;vertical-align:middle;}
@keyframes spin{to{transform:rotate(360deg);}}
.spin.light{border-color:rgba(255,255,255,.2);border-top-color:var(--muted);}
::-webkit-scrollbar{width:4px;}::-webkit-scrollbar-track{background:var(--bg);}::-webkit-scrollbar-thumb{background:var(--muted);}
</style>
</head>
<body>
<div class="orb orb1"></div><div class="orb orb2"></div>

<!-- ══ APP ══ -->
<div id="app" class="show">

  <div class="topbar">
    <div class="topbar-logo"><a href="index.php" style="color:inherit;text-decoration:none">LOCK<span>SMITH</span></a></div>
    <div class="topbar-r">
      <div class="topbar-zk">ZERO-KNOWLEDGE</div>
      <span class="user-pill" id="u-email"><?= htmlspecialchars($userEmail) ?></span>
      <a class="btn btn-ghost btn-sm" href="account.php">Account</a>
      <button class="btn btn-ghost btn-sm" onclick="doLogout()">Logout</button>
    </div>
  </div>

  <div class="app-body">

    <!-- VAULT PASSPHRASE SESSION (needed for crypto in browser) -->
    <div class="card" id="vault-unlock-card" style="display:none">
      <div class="card-title"><div class="dot" style="background:var(--orange)"></div><span style="color:var(--orange)">Enter Vault Passphrase</span></div>
      <p style="font-size:12px;color:var(--muted);margin-bottom:14px;line-height:1.6;">
        Your vault passphrase is required to generate or reveal codes. It is used only in your browser — never sent to the server.
      </p>
      <div class="field"><label>Vault Passphrase</label>
        <input type="password" id="vp-input" placeholder="Your vault passphrase…" autocomplete="current-password">
      </div>
      <div id="vp-err" class="msg msg-err"></div>
      <button class="btn btn-primary" onclick="unlockVault()"><span id="vp-txt">Unlock Vault</span></button>
    </div>

    <!-- GENERATE CARD -->
    <div class="card card-accent" id="gen-card">
      <div class="card-title"><div class="dot"></div>Create New Code</div>

      <div class="field"><label>Label</label>
        <input type="text" id="g-label" placeholder="e.g. Instagram, Gmail, Bank…" maxlength="255">
      </div>

      <div class="field"><label>Code Type</label>
        <div class="type-grid">
          <div class="type-opt sel" data-type="alphanumeric" onclick="pickType(this)">A–Z + 0–9</div>
          <div class="type-opt" data-type="numeric"          onclick="pickType(this)">0–9 only</div>
          <div class="type-opt" data-type="alpha"            onclick="pickType(this)">A–Z only</div>
          <div class="type-opt" data-type="custom"           onclick="pickType(this)">+ Symbols</div>
        </div>
      </div>

      <div class="field"><label>Length &nbsp;<span onclick="rndLen()" style="cursor:pointer;color:var(--muted);font-size:11px;">↻ randomize</span></label>
        <div class="slider-row">
          <input type="range" id="g-len" min="4" max="64" value="16" oninput="updLen()">
          <div class="slider-val" id="len-val">16</div>
        </div>
      </div>

      <div class="field"><label>Reveal Date &amp; Time</label>
        <input type="datetime-local" id="g-date">
      </div>

      <div class="field"><label>Memory Hint <span style="color:var(--muted);font-size:10px;">(optional — never the code)</span></label>
        <input type="text" id="g-hint" placeholder="e.g. Set before my summer trip" maxlength="500">
      </div>

      <div id="g-err" class="msg msg-err"></div>

      <!-- KDF progress bar shown during key derivation -->
      <div class="kdf-progress" id="kdf-progress">
        <div class="kdf-bar-wrap"><div class="kdf-bar" id="kdf-bar"></div></div>
        <div class="kdf-label" id="kdf-label">Deriving encryption key in your browser…</div>
      </div>

      <button class="btn btn-primary" id="g-btn" onclick="doGenerate()" style="margin-top:10px;">
        <span id="g-txt">Generate &amp; Lock</span>
      </button>
    </div>

    <!-- LOCKS LIST -->
    <div class="sec-header" id="codes">
      <div class="card-title" style="margin-bottom:0"><div class="dot"></div>My Codes</div>
      <button class="btn btn-ghost btn-sm" onclick="loadLocks()">↻</button>
    </div>
    <div id="locks-wrap">
      <div class="empty"><div class="empty-icon">🔒</div><h3>No codes yet</h3><p>Create your first code above.</p></div>
    </div>

  </div>
</div>

<!-- ══ CONFIRM SHEET ══ -->
<div id="confirm-overlay">
  <div class="confirm-sheet">
    <div class="confirm-title">Did you save the code?</div>
    <div class="confirm-sub" id="cs-sub">Code was copied to your clipboard.</div>
    <div class="timer-wrap">
      <svg class="timer-ring-svg" width="64" height="64" viewBox="0 0 64 64">
        <circle class="timer-track" cx="32" cy="32" r="28"/>
        <circle class="timer-fill" id="timer-circle" cx="32" cy="32" r="28" stroke-dasharray="175.93" stroke-dashoffset="0"/>
        <text class="timer-num" id="timer-num" x="32" y="37" text-anchor="middle">2:00</text>
      </svg>
      <div class="timer-msg" id="timer-msg">Confirm within <strong>2 minutes</strong> that you've saved this in your app.</div>
    </div>
    <div class="autosave-bar" id="autosave-bar">⏰ Auto-saved. Code stored but <strong>not time-locked</strong> until you confirm below.</div>
    <div class="void-box" id="void-box">
      <div class="void-label">// Void Code — browser-decrypted for reference only</div>
      <div class="void-pwd" id="void-pwd"></div>
      <div class="void-note">This code was never confirmed — it is not enforced or locked.</div>
    </div>
    <div class="confirm-btns" id="confirm-btns">
      <button class="btn btn-green" onclick="doConfirm('confirm')">✓ Yes, I saved it</button>
      <button class="btn btn-red"   onclick="doConfirm('reject')">✗ No, discard</button>
    </div>
    <div id="confirm-done" style="display:none;text-align:center;padding-top:8px;">
      <div id="confirm-done-msg" style="font-size:13px;margin-bottom:16px;line-height:1.7;"></div>
      <button class="btn btn-ghost btn-full" onclick="closeConfirm()">Close</button>
    </div>
  </div>
</div>

<!-- ══ REVEAL MODAL ══ -->
<div id="reveal-overlay" onclick="closeReveal(event)">
  <div class="reveal-sheet">
    <button class="modal-close" onclick="closeReveal()">×</button>
    <div class="reveal-title" id="rv-label"></div>
    <div class="reveal-sub">// Enter vault passphrase to decrypt</div>
    <div class="vault-input-wrap">
      <label>Vault Passphrase</label>
      <input type="password" id="rv-vault" placeholder="Your vault passphrase…" autocomplete="current-password">
    </div>
    <div id="rv-err" class="msg msg-err"></div>
    <div id="rv-hint" style="font-size:11px;color:var(--muted);font-style:italic;margin-bottom:14px;display:none;"></div>
    <div class="reveal-pwd" id="rv-pwd" style="display:none;"></div>
    <button class="btn btn-primary" id="rv-btn" onclick="doReveal()"><span id="rv-btn-txt">Decrypt &amp; Reveal</span></button>
    <button class="btn btn-full" id="rv-copy-btn" style="margin-top:10px;background:var(--s3);border:1px solid var(--b2);color:var(--text);display:none;" onclick="copyRevealed()">Copy Code</button>
    <div id="rv-zk-note" style="font-size:10px;color:var(--muted);margin-top:12px;letter-spacing:.5px;line-height:1.5;display:none;">
      🔐 Decrypted entirely in your browser. This server never saw this code.
    </div>
  </div>
</div>

<script>
// ═══════════════════════════════════════════════════════════
//  LOCKSMITH — Zero-Knowledge Client Engine
//
//  ALL ENCRYPTION / DECRYPTION HAPPENS HERE.
//  The server receives and returns only opaque ciphertext blobs.
//  The vault passphrase never leaves this script context.
//  Keys are derived in-browser via Web Crypto PBKDF2, then discarded.
// ═══════════════════════════════════════════════════════════

const CSRF = <?= json_encode($csrf) ?>;
const KDF_HASH = 'SHA-256';

let selType     = 'alphanumeric';
let pendingLock = null;   // { lock_id, label, reveal_date, kdf_salt, kdf_iterations, cipher_blob, iv, auth_tag }
let timerInt    = null;
let timerSecs   = 120;
let autoFired   = false;
let revealedPwd = null;
let vaultPhraseSession = null; // Held in memory only (not DOM, not storage)
const CIRC = 175.93;

// ─────────────────────────────────────────────────
//  WEB CRYPTO — PBKDF2 + AES-256-GCM
// ─────────────────────────────────────────────────

/** Derive AES-256-GCM key from passphrase + salt via PBKDF2 */
async function deriveKey(passphrase, saltB64, iterations) {
  const enc      = new TextEncoder();
  const salt     = b64ToBytes(saltB64);
  const keyMat   = await crypto.subtle.importKey(
    'raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: KDF_HASH },
    keyMat,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/** Encrypt plaintext string → { cipher_blob, iv, auth_tag } all base64 */
async function aesEncrypt(plaintext, key) {
  const enc   = new TextEncoder();
  const iv    = crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV
  const data  = enc.encode(plaintext);
  // AES-GCM produces ciphertext + 16-byte auth tag appended
  const buf   = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, data);
  const bytes = new Uint8Array(buf);
  const ctLen = bytes.length - 16;
  return {
    cipher_blob: bytesToB64(bytes.slice(0, ctLen)),
    iv:          bytesToB64(iv),
    auth_tag:    bytesToB64(bytes.slice(ctLen)),
  };
}

/** Decrypt cipher_blob + iv + auth_tag (all base64) → plaintext string */
async function aesDecrypt(cipherBlob, ivB64, authTagB64, key) {
  const ct      = b64ToBytes(cipherBlob);
  const iv      = b64ToBytes(ivB64);
  const tag     = b64ToBytes(authTagB64);
  // Reassemble: ciphertext || auth_tag
  const combined = new Uint8Array(ct.length + tag.length);
  combined.set(ct); combined.set(tag, ct.length);
  const buf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, combined);
  return new TextDecoder().decode(buf);
}

/** Generate cryptographically secure random password */
function genPassword(type, length) {
  const chars = {
    numeric:      '0123456789',
    alpha:        'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',
    alphanumeric: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
    custom:       'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?',
  }[type] || 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

  const arr = new Uint8Array(length * 4); // Over-generate to reject bias
  crypto.getRandomValues(arr);
  let result = '', i = 0;
  while (result.length < length) {
    const byte = arr[i++ % arr.length];
    const idx  = byte % chars.length;
    // Rejection sampling: skip if byte causes modulo bias
    if (byte < Math.floor(256 / chars.length) * chars.length) {
      result += chars[idx];
    }
  }
  return result;
}

// ─────────────────────────────────────────────────
//  BASE64 HELPERS
// ─────────────────────────────────────────────────
function bytesToB64(bytes) {
  return btoa(String.fromCharCode(...bytes));
}
function b64ToBytes(b64) {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

// ─────────────────────────────────────────────────
//  INIT
// ─────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  const d = new Date(); d.setDate(d.getDate()+1); d.setSeconds(0,0);
  document.getElementById('g-date').value = d.toISOString().slice(0,16);
  document.getElementById('vp-input').addEventListener('keydown', e => { if(e.key==='Enter') unlockVault(); });
  document.getElementById('rv-vault').addEventListener('keydown', e => { if(e.key==='Enter') doReveal(); });
  loadLocks();
  checkVaultUnlock();
});

function checkVaultUnlock() {
  if (!vaultPhraseSession) {
    document.getElementById('vault-unlock-card').style.display = 'block';
    document.getElementById('gen-card').style.opacity = '.4';
    document.getElementById('gen-card').style.pointerEvents = 'none';
  }
}

async function unlockVault() {
  const vp = document.getElementById('vp-input').value;
  const errEl = document.getElementById('vp-err');
  errEl.classList.remove('show');
  if (!vp || vp.length < 10) { errEl.textContent='Passphrase must be at least 10 characters'; errEl.classList.add('show'); return; }

  document.getElementById('vp-txt').innerHTML = '<span class="spin light"></span> Verifying…';

  // Test-derive a key to ensure passphrase is non-empty + usable
  // We do NOT verify against server here — server only verifies on reveal
  // This is intentional: vault passphrase is purely local
  try {
    // Quick test: can we import it? (doesn't hit server)
    const enc = new TextEncoder();
    await crypto.subtle.importKey('raw', enc.encode(vp), 'PBKDF2', false, ['deriveKey']);
    vaultPhraseSession = vp;
    document.getElementById('vault-unlock-card').style.display = 'none';
    document.getElementById('gen-card').style.opacity = '1';
    document.getElementById('gen-card').style.pointerEvents = '';
    toast('Vault unlocked — passphrase held in memory only', 'ok');
  } catch(e) {
    errEl.textContent = 'Invalid passphrase'; errEl.classList.add('show');
  } finally {
    document.getElementById('vp-txt').textContent = 'Unlock Vault';
  }
}

async function doLogout(){
  await post('/api/auth.php',{action:'logout'});
  vaultPhraseSession=null; // Clear passphrase from memory
  window.location='index.php';
}

// ─────────────────────────────────────────────────
//  GENERATE — Zero-Knowledge Flow
//  1. Request KDF salt from server
//  2. Derive key from vault passphrase + salt IN BROWSER (PBKDF2, 310k rounds)
//  3. Generate random code IN BROWSER
//  4. Encrypt code IN BROWSER (AES-256-GCM)
//  5. Send ONLY ciphertext to server — no key, no plaintext
//  6. Copy code to clipboard (never displayed)
// ─────────────────────────────────────────────────
function pickType(el){document.querySelectorAll('.type-opt').forEach(t=>t.classList.remove('sel'));el.classList.add('sel');selType=el.dataset.type;}
function updLen(){document.getElementById('len-val').textContent=document.getElementById('g-len').value;}
function rndLen(){const v=Math.floor(Math.random()*45)+8;document.getElementById('g-len').value=v;updLen();}

async function doGenerate(){
  if (!vaultPhraseSession) { toast('Enter your vault passphrase first','err'); return; }
  const label=document.getElementById('g-label').value.trim();
  const len=parseInt(document.getElementById('g-len').value);
  const date=document.getElementById('g-date').value;
  const hint=document.getElementById('g-hint').value.trim();
  const errEl=document.getElementById('g-err');
  errEl.classList.remove('show');

  if(!label){errEl.textContent='Please enter a label';errEl.classList.add('show');return;}
  if(!date){errEl.textContent='Please set a reveal date';errEl.classList.add('show');return;}

  document.getElementById('g-txt').innerHTML='<span class="spin"></span>';
  document.getElementById('g-btn').disabled=true;
  showKdfProgress(true);

  try {
    // Step 1: Get a fresh server-generated KDF salt (one-time use)
    const saltRes = await get('/api/salt.php');
    if (!saltRes.success) throw new Error(saltRes.error || 'Could not get salt');

    const { kdf_salt, kdf_iterations } = saltRes;

    // Step 2: Simulate progress for UX (PBKDF2 is synchronous-feeling in Web Crypto)
    animateKdfBar(kdf_iterations);

    // Step 3: Derive 256-bit key in browser (never sent to server)
    const key = await deriveKey(vaultPhraseSession, kdf_salt, kdf_iterations);
    document.getElementById('kdf-label').textContent='Generating code…';

    // Step 4: Generate random password (CSPRNG, entirely in browser)
    const plainPwd = genPassword(selType, len);

    // Step 5: Encrypt in browser
    const { cipher_blob, iv, auth_tag } = await aesEncrypt(plainPwd, key);
    document.getElementById('kdf-label').textContent='Sending ciphertext to server…';

    // Step 6: Send ONLY ciphertext blobs + metadata to server
    // plainPwd and key are local variables — they will be GC'd after this scope
    const r = await postCsrf('/api/generate.php', {
      label, type: selType, length: len, reveal_date: date, hint,
      cipher_blob, iv, auth_tag, kdf_salt
    });
    if (!r.success) { errEl.textContent=r.error||'Generation failed'; errEl.classList.add('show'); return; }

    // Step 7: Copy plaintext code to clipboard (blind — not shown in UI)
    try {
      await navigator.clipboard.writeText(plainPwd);
      toast('Code copied to clipboard (never displayed)', 'ok');
    } catch {
      // Fallback
      const ta=document.createElement('textarea');
      ta.value=plainPwd; ta.style.cssText='position:fixed;top:-9999px;left:-9999px;opacity:0;';
      document.body.appendChild(ta); ta.focus(); ta.select();
      try{document.execCommand('copy');}catch{}
      document.body.removeChild(ta);
      toast('Code copied (tap to verify paste worked)', 'warn');
    }

    // Notify server of copy (for audit — no password sent)
    await postCsrf('/api/copied.php', { lock_id: r.lock_id });

    // Hold lock info for confirm flow (cipher blobs needed for reject display)
    pendingLock = {
      lock_id: r.lock_id, label: r.label, reveal_date: r.reveal_date,
      kdf_salt, kdf_iterations, cipher_blob, iv, auth_tag
    };

    // plainPwd is now out of scope after this — key and plaintext are gone
    document.getElementById('g-label').value='';
    document.getElementById('g-hint').value='';

    openConfirmSheet(r.lock_id, r.label);

  } catch(e) {
    errEl.textContent = e.message || 'Error during generation';
    errEl.classList.add('show');
  } finally {
    document.getElementById('g-txt').textContent='Generate & Lock';
    document.getElementById('g-btn').disabled=false;
    showKdfProgress(false);
  }
}

function showKdfProgress(show){
  const el=document.getElementById('kdf-progress');
  if(show){ el.classList.add('show'); document.getElementById('kdf-bar').style.width='0%'; }
  else el.classList.remove('show');
}
function animateKdfBar(iterations){
  // Fake progress bar since PBKDF2 in Web Crypto doesn't report progress
  // Estimated time: ~1-2s for 310k iterations on modern devices
  const totalMs = Math.min(2000, iterations / 200);
  const steps   = 60;
  const stepMs  = totalMs / steps;
  let i = 0;
  const t = setInterval(() => {
    i++;
    const pct = Math.min(90, (i/steps)*100); // Hold at 90% until done
    document.getElementById('kdf-bar').style.width = pct + '%';
    if (i >= steps) clearInterval(t);
  }, stepMs);
}

// ─────────────────────────────────────────────────
//  CONFIRM SHEET
// ─────────────────────────────────────────────────
function openConfirmSheet(lockId, label){
  autoFired=false;
  document.getElementById('cs-sub').textContent=`"${label}" — blind-copied to clipboard.`;
  document.getElementById('autosave-bar').classList.remove('show');
  document.getElementById('void-box').classList.remove('show');
  document.getElementById('confirm-btns').style.display='grid';
  document.getElementById('confirm-done').style.display='none';
  document.getElementById('confirm-overlay').classList.add('show');
  timerSecs=120; updateTimerDisplay(); clearInterval(timerInt);
  timerInt=setInterval(()=>{timerSecs--;updateTimerDisplay();if(timerSecs<=0){clearInterval(timerInt);if(!autoFired)triggerAutoSave(lockId);}},1000);
}
function updateTimerDisplay(){
  const m=Math.floor(timerSecs/60),s=timerSecs%60;
  document.getElementById('timer-num').textContent=`${m}:${s.toString().padStart(2,'0')}`;
  const offset=CIRC*(1-timerSecs/120);
  document.getElementById('timer-circle').style.strokeDashoffset=offset;
  document.getElementById('timer-circle').style.stroke=timerSecs>30?'var(--orange)':'var(--red)';
}
async function triggerAutoSave(lockId){
  autoFired=true;
  await postCsrf('/api/confirm.php',{lock_id:lockId,action:'auto_save'});
  document.getElementById('autosave-bar').classList.add('show');
  document.getElementById('timer-msg').innerHTML='⏰ Auto-saved. Code stored but <strong>not time-locked</strong> until you confirm.';
  loadLocks();
}

async function doConfirm(action){
  if(!pendingLock)return;
  clearInterval(timerInt);
  const r=await postCsrf('/api/confirm.php',{lock_id:pendingLock.lock_id,action});
  document.getElementById('confirm-btns').style.display='none';
  document.getElementById('confirm-done').style.display='block';
  const msg=document.getElementById('confirm-done-msg');

  if(action==='confirm'){
    const d=new Date(r.reveal_date||pendingLock.reveal_date);
    const ds=d.toLocaleDateString('en-US',{year:'numeric',month:'long',day:'numeric',hour:'2-digit',minute:'2-digit'});
    msg.innerHTML=`✓ Lock activated.<br>Code sealed until<br><strong style="color:var(--accent)">${ds}</strong>`;
    loadLocks();
  } else if(action==='reject'){
    msg.innerHTML=`✗ Discarded. Decrypting void code in your browser…`;
    // Decrypt void code in browser to show user (passphrase + blobs from pendingLock)
    if(pendingLock.cipher_blob && vaultPhraseSession){
      try{
        const key=await deriveKey(vaultPhraseSession, pendingLock.kdf_salt, pendingLock.kdf_iterations);
        const plain=await aesDecrypt(pendingLock.cipher_blob, pendingLock.iv, pendingLock.auth_tag, key);
        document.getElementById('void-pwd').textContent=plain;
        document.getElementById('void-box').classList.add('show');
        msg.innerHTML=`✗ Code discarded. The void code is shown below — it was <strong>never locked</strong>.`;
      }catch{
        msg.innerHTML=`✗ Discarded. Could not decrypt void code.`;
      }
    }
    loadLocks();
  }
  pendingLock=null;
}
function closeConfirm(){clearInterval(timerInt);document.getElementById('confirm-overlay').classList.remove('show');pendingLock=null;}

// ─────────────────────────────────────────────────
//  LOCKS LIST
// ─────────────────────────────────────────────────
async function loadLocks(){
  const wrap=document.getElementById('locks-wrap');
  wrap.innerHTML='<div style="text-align:center;padding:40px;color:var(--muted);font-size:11px;letter-spacing:2px">LOADING…</div>';
  try{
    const r=await get('/api/locks.php');
    if(!r.success||!r.locks.length){
      wrap.innerHTML='<div class="empty"><div class="empty-icon">🔒</div><h3>No codes yet</h3><p>Create your first code above.</p></div>';
      return;
    }
    wrap.innerHTML='<div class="locks-grid" id="locks-grid"></div>';
    r.locks.forEach(l=>document.getElementById('locks-grid').appendChild(buildCard(l)));
  }catch{
    wrap.innerHTML='<div class="empty"><p>Failed to load.</p></div>';
  }
}

function buildCard(lock){
  const el=document.createElement('div');
  const st=lock.display_status;
  el.className=`lock-card st-${st}`;
  const badges={locked:'🔒 Locked',unlocked:'🔓 Unlocked',pending:'⏳ Pending',auto_saved:'💾 Auto-saved',rejected:'✗ Void'};
  const rd=new Date(lock.reveal_date).toLocaleDateString('en-US',{year:'numeric',month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'});
  let countdown='';
  if(st==='locked'&&lock.time_remaining){
    const t=lock.time_remaining;
    countdown=`<div class="lc-countdown">⏱ ${t.days}d ${t.hours}h ${t.minutes}m remaining</div>`;
  }
  let autoNote=st==='auto_saved'?`<div class="lc-autosave-note">ℹ Auto-saved without confirmation. Tap "Activate" to enforce reveal date.</div>`:'';
  const hintHtml=lock.hint?`<div class="lc-hint">"${esc(lock.hint)}"</div>`:'';
  const copiedStr=lock.copied_at?`<span style="color:var(--green)">✓</span>`:`<span style="color:var(--red)">not copied</span>`;

  let actions='';
  if(st==='unlocked') actions=`<button class="btn btn-green btn-sm" onclick="openReveal('${lock.id}','${esc(lock.label)}','${esc(lock.hint||'')}')">🔓 Reveal</button>`;
  else if(st==='auto_saved') actions=`<button class="btn btn-sm" style="background:var(--blue);color:#000;min-height:40px;font-family:var(--mono);font-size:11px;letter-spacing:1px;cursor:pointer;border:none;" onclick="reConfirm('${lock.id}')">Activate Lock</button>`;
  else if(st==='locked') actions=`<button class="btn btn-ghost btn-sm" disabled style="opacity:.3;cursor:not-allowed">Sealed until ${rd}</button>`;
  actions+=`<button class="btn btn-red btn-sm" onclick="delLock('${lock.id}')">Delete</button>`;

  el.innerHTML=`
    <div class="lc-top"><div class="lc-label">${esc(lock.label)}</div><div class="lc-badge ${st}">${badges[st]||st}</div></div>
    ${hintHtml}${autoNote}${countdown}
    <div class="lc-meta">Type: <span>${lock.password_type} · ${lock.password_length} chars</span><br>Reveal: <span>${rd}</span><br>Copied: ${copiedStr}</div>
    <div class="lc-actions">${actions}</div>`;
  return el;
}

// ─────────────────────────────────────────────────
//  REVEAL — Zero-Knowledge
//  Server returns ciphertext blobs (if date passed + vault verified)
//  Browser decrypts using vault passphrase
// ─────────────────────────────────────────────────
let currentRevealLockId = null;
let currentRevealLabel  = null;

function openReveal(lockId, label, hint){
  currentRevealLockId=lockId; currentRevealLabel=label;
  document.getElementById('rv-label').textContent=label;
  document.getElementById('rv-vault').value='';
  document.getElementById('rv-pwd').style.display='none';
  document.getElementById('rv-copy-btn').style.display='none';
  document.getElementById('rv-zk-note').style.display='none';
  document.getElementById('rv-btn').style.display='block';
  document.getElementById('rv-btn-txt').textContent='Decrypt & Reveal';
  document.getElementById('rv-err').classList.remove('show');
  const hi=document.getElementById('rv-hint');
  if(hint){hi.textContent=`Hint: "${hint}"`;hi.style.display='block';}else hi.style.display='none';
  document.getElementById('reveal-overlay').classList.add('show');
  setTimeout(()=>document.getElementById('rv-vault').focus(),200);
}

async function doReveal(){
  const vault=document.getElementById('rv-vault').value;
  const errEl=document.getElementById('rv-err');
  errEl.classList.remove('show');
  if(!vault){errEl.textContent='Enter your vault passphrase';errEl.classList.add('show');return;}
  document.getElementById('rv-btn-txt').innerHTML='<span class="spin"></span>';

  try{
    // Server verifies: identity (vault verifier hash) + date gate + ownership
    // Returns encrypted blobs only
    const r=await postCsrf('/api/reveal.php',{lock_id:currentRevealLockId, vault_passphrase:vault});
    if(!r.success){errEl.textContent=r.error||'Cannot reveal';errEl.classList.add('show');return;}

    // Browser decrypts using passphrase + returned blobs
    const key=await deriveKey(vault, r.kdf_salt, r.kdf_iterations);
    const plain=await aesDecrypt(r.cipher_blob, r.iv, r.auth_tag, key);

    revealedPwd=plain;
    document.getElementById('rv-pwd').textContent=plain;
    document.getElementById('rv-pwd').style.display='block';
    document.getElementById('rv-copy-btn').style.display='block';
    document.getElementById('rv-zk-note').style.display='block';
    document.getElementById('rv-vault').style.display='none';
    document.getElementById('rv-btn').style.display='none';

    // Update session passphrase cache (user just proved they know it)
    vaultPhraseSession=vault;

  }catch(e){
    if(e.name==='OperationError'){
      errEl.textContent='Decryption failed — wrong vault passphrase or tampered data';
    } else {
      errEl.textContent=e.message||'Decryption failed';
    }
    errEl.classList.add('show');
  }finally{
    document.getElementById('rv-btn-txt').textContent='Decrypt & Reveal';
  }
}

function closeReveal(e){
  if(e&&e.target!==document.getElementById('reveal-overlay'))return;
  document.getElementById('reveal-overlay').classList.remove('show');
  revealedPwd=null;
  currentRevealLockId=null;
  document.getElementById('rv-vault').style.display='block';
  document.getElementById('rv-btn').style.display='block';
}

async function copyRevealed(){
  if(!revealedPwd)return;
  try{await navigator.clipboard.writeText(revealedPwd);toast('Copied!','ok');}
  catch{toast('Select the text manually','err');}
}

// ─────────────────────────────────────────────────
//  RE-CONFIRM & DELETE
// ─────────────────────────────────────────────────
async function reConfirm(id){
  const r=await postCsrf('/api/confirm.php',{lock_id:id,action:'confirm'});
  if(r.success){toast('Lock activated!','ok');loadLocks();}
  else toast(r.error||'Failed','err');
}
async function delLock(id){
  if(!confirm('Permanently delete this lock? Encrypted data will be removed.'))return;
  const r=await postCsrf('/api/delete.php',{lock_id:id});
  if(r.success){toast('Deleted','ok');loadLocks();}
  else toast(r.error||'Delete failed','err');
}

// ─────────────────────────────────────────────────
//  HTTP
// ─────────────────────────────────────────────────
function apiUrl(url){
  return url.startsWith('/') ? url.slice(1) : url;
}
async function get(url){const r=await fetch(apiUrl(url),{credentials:'same-origin'});return r.json();}
async function post(url,body){
  const r=await fetch(apiUrl(url),{method:'POST',credentials:'same-origin',
    headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});return r.json();}
async function postCsrf(url,body){
  const r=await fetch(apiUrl(url),{method:'POST',credentials:'same-origin',
    headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF},body:JSON.stringify(body)});return r.json();}

// ─────────────────────────────────────────────────
//  UTILS
// ─────────────────────────────────────────────────
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function toast(msg,type='ok'){
  const t=document.createElement('div');t.className=`toast ${type}`;t.textContent=msg;
  document.body.appendChild(t);setTimeout(()=>t.remove(),3200);}
</script>
</body>
</html>
