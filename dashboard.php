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
$isAdmin   = isAdmin();
$csrf      = getCsrfToken();

$userId = (int)(getCurrentUserId() ?? 0);
$showSecurityBanner = !$isAdmin && !userHasTotp($userId) && !userHasPasskeys($userId);

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

.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;
  padding:15px 24px;font-family:var(--mono);font-size:12px;letter-spacing:2px;
  text-transform:uppercase;cursor:pointer;border:none;transition:all .15s;
  border-radius:0;-webkit-appearance:none;touch-action:manipulation;min-height:48px;text-decoration:none;}
.btn-primary{background:var(--accent);color:#000;font-weight:500;width:100%;}
.btn-primary:hover{background:#f0ff60;}
.btn-primary:active{transform:scale(.98);}
.btn-primary:disabled{opacity:.4;pointer-events:none;}
.btn-ghost{background:transparent;border:1px solid var(--b2);color:var(--text);}
.btn-ghost:hover{border-color:var(--text);}
.btn-green{background:var(--green);color:#000;font-weight:500;}
.btn-red{background:rgba(255,71,87,.1);border:1px solid rgba(255,71,87,.3);color:var(--red);}
.btn-sm{padding:10px 16px;font-size:11px;min-height:40px;}

.spin{display:inline-block;width:14px;height:14px;border:2px solid rgba(0,0,0,.35);border-top-color:#000;border-radius:50%;animation:spin .5s linear infinite;}
.spin.light{border-color:rgba(255,255,255,.25);border-top-color:var(--accent);}
@keyframes spin{to{transform:rotate(360deg);}}

.msg{padding:12px 14px;font-size:12px;margin-bottom:12px;display:none;letter-spacing:.4px;line-height:1.6;}
.msg.show{display:block;}
.msg-err{background:rgba(255,71,87,.08);border:1px solid rgba(255,71,87,.2);color:var(--red);}
.msg-ok{background:rgba(71,255,176,.08);border:1px solid rgba(71,255,176,.2);color:var(--green);}
.msg-warn{background:rgba(255,170,0,.08);border:1px solid rgba(255,170,0,.2);color:var(--orange);}

.field{margin-bottom:14px;}
.field label{display:block;font-size:10px;letter-spacing:2px;text-transform:uppercase;color:var(--muted);margin-bottom:6px;}
.field input,.field select{width:100%;background:var(--s2);border:1px solid var(--b1);color:var(--text);
  font-family:var(--mono);font-size:15px;padding:14px;outline:none;transition:border-color .2s;
  -webkit-appearance:none;border-radius:0;-webkit-text-size-adjust:100%;}
.field input:focus,.field select:focus{border-color:var(--accent);}

#app{min-height:100vh;position:relative;z-index:1;padding-bottom:max(20px,var(--sab));}
.topbar{display:flex;align-items:center;justify-content:space-between;
  padding:max(14px,var(--sat)) 20px 14px;border-bottom:1px solid var(--b1);
  position:sticky;top:0;background:rgba(6,7,10,.94);backdrop-filter:blur(16px);
  -webkit-backdrop-filter:blur(16px);z-index:100;}
.topbar-logo{font-family:var(--display);font-size:clamp(15px,4vw,19px);font-weight:900;letter-spacing:-1px;}
.topbar-logo span{color:var(--accent);}
.topbar-r{display:flex;align-items:center;gap:10px;flex-wrap:wrap;justify-content:flex-end;}
.user-pill{font-size:10px;color:var(--muted);letter-spacing:1px;max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:none;}
@media(min-width:560px){.user-pill{display:block;}}

.app-body{max-width:680px;margin:0 auto;padding:22px 16px;}
@media(min-width:600px){.app-body{padding:30px 24px;}}

/* ── SECURITY BANNER ── */
.sec-banner{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;
  background:rgba(255,170,0,.06);border:1px solid rgba(255,170,0,.22);
  padding:14px 14px;margin:0 0 16px 0;}
.sec-banner-title{font-family:var(--display);font-weight:800;font-size:12px;letter-spacing:1px;color:var(--orange);}
.sec-banner-sub{font-size:11px;color:var(--muted);line-height:1.6;max-width:520px;}

.card{background:var(--s1);border:1px solid var(--b1);padding:20px;margin-bottom:16px;position:relative;}
@media(min-width:600px){.card{padding:24px 28px;}}
.card-title{font-family:var(--display);font-size:11px;font-weight:700;letter-spacing:2px;
  text-transform:uppercase;color:var(--accent);margin-bottom:18px;display:flex;align-items:center;gap:8px;}
.card-title .dot{width:5px;height:5px;background:var(--accent);flex-shrink:0;}

.type-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:8px;}
@media(min-width:380px){.type-grid{grid-template-columns:repeat(4,1fr);}}
.type-opt{padding:12px 6px;border:1px solid var(--b1);background:transparent;
  color:var(--muted);font-family:var(--mono);font-size:10px;letter-spacing:1px;
  text-transform:uppercase;cursor:pointer;text-align:center;transition:all .15s;
  min-height:44px;display:flex;align-items:center;justify-content:center;}
.type-opt:hover{border-color:var(--b2);color:var(--text);}
.type-opt.sel{border-color:var(--accent);color:var(--accent);background:rgba(232,255,71,.06);}

.slider-row{display:flex;align-items:center;gap:14px;}
.slider-val{font-family:var(--display);font-size:26px;font-weight:900;color:var(--accent);min-width:40px;text-align:right;}
input[type=range]{-webkit-appearance:none;flex:1;height:4px;background:var(--b2);outline:none;cursor:pointer;border-radius:2px;}
input[type=range]::-webkit-slider-thumb{-webkit-appearance:none;width:22px;height:22px;background:var(--accent);cursor:pointer;border-radius:0;}

.kdf-progress{display:none;margin-top:12px;}
.kdf-progress.show{display:block;}
.kdf-bar-wrap{height:3px;background:var(--b2);overflow:hidden;margin-bottom:6px;}
.kdf-bar{height:100%;background:var(--accent);transition:width .1s linear;width:0%;}
.kdf-label{font-size:10px;color:var(--muted);letter-spacing:1px;text-align:center;}

.sec-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;}

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

.empty{text-align:center;padding:60px 20px;color:var(--muted);}
.empty-icon{font-size:44px;margin-bottom:14px;}
.empty h3{font-family:var(--display);font-size:15px;font-weight:700;color:var(--text);margin-bottom:8px;}
.empty p{font-size:12px;line-height:1.6;}

/* overlays */
#confirm-overlay,#reveal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.9);
  display:none;align-items:flex-end;justify-content:center;z-index:500;padding:0 0 max(0px,var(--sab)) 0;}
#confirm-overlay.show,#reveal-overlay.show{display:flex;}
.confirm-sheet,.reveal-sheet{background:var(--s1);border:1px solid var(--b2);border-bottom:none;
  padding:28px 22px max(28px,var(--sab));width:100%;max-width:480px;position:relative;}
@media(min-width:600px){#confirm-overlay,#reveal-overlay{align-items:center;}
  .confirm-sheet,.reveal-sheet{border:1px solid var(--b2);max-width:480px;padding:32px;}}
.modal-close{position:absolute;top:12px;right:14px;background:none;border:none;color:var(--muted);
  font-size:22px;cursor:pointer;padding:4px;min-width:32px;min-height:32px;
  display:flex;align-items:center;justify-content:center;}
.modal-close:hover{color:var(--text);}

.reveal-title{font-family:var(--display);font-size:16px;font-weight:700;margin-bottom:3px;}
.reveal-sub{font-size:10px;color:var(--muted);letter-spacing:2px;text-transform:uppercase;margin-bottom:18px;}
.reveal-pwd{font-size:clamp(16px,4vw,22px);color:var(--accent);letter-spacing:3px;
  word-break:break-all;background:#000;padding:16px;border:1px solid rgba(232,255,71,.12);
  margin-bottom:16px;line-height:1.5;user-select:all;-webkit-user-select:all;display:none;}
.vault-input-wrap{margin-bottom:16px;}
.vault-input-wrap label{font-size:10px;letter-spacing:2px;text-transform:uppercase;color:var(--muted);display:block;margin-bottom:6px;}
.vault-input-wrap input{width:100%;background:#000;border:1px solid rgba(232,255,71,.2);
  color:var(--accent);font-family:var(--mono);font-size:15px;padding:13px;outline:none;
  border-radius:0;-webkit-appearance:none;}

.toast{position:fixed;bottom:max(24px,var(--sab));left:50%;transform:translateX(-50%);
  background:#000;border:1px solid var(--b2);padding:10px 14px;font-size:12px;letter-spacing:.4px;z-index:900;max-width:92vw;}
.toast.ok{border-color:rgba(71,255,176,.25);color:var(--green);}
.toast.err{border-color:rgba(255,71,87,.3);color:var(--red);}
.toast.warn{border-color:rgba(255,170,0,.35);color:var(--orange);}
</style>
</head>
<body>
<div class="orb orb1"></div><div class="orb orb2"></div>

<div id="app">
  <div class="topbar">
    <div class="topbar-logo">LOCK<span>SMITH</span></div>
    <div class="topbar-r">
      <span class="user-pill"><?= htmlspecialchars($userEmail) ?></span>
      <a class="btn btn-ghost btn-sm" href="create_code.php">Create Code</a>
      <a class="btn btn-ghost btn-sm" href="my_codes.php">My Codes</a>
      <a class="btn btn-ghost btn-sm" href="rooms.php">Rooms</a>
      <a class="btn btn-ghost btn-sm" href="notifications.php">Notifications</a>
      <a class="btn btn-ghost btn-sm" href="backup.php">Backup</a>
      <a class="btn btn-ghost btn-sm" href="account.php">Account</a>
      <?php if ($isAdmin): ?><a class="btn btn-ghost btn-sm" href="admin.php">Admin</a><?php endif; ?>
      <a class="btn btn-ghost btn-sm" href="logout.php">Logout</a>
    </div>
  </div>

  <div class="app-body">

    <?php if ($showSecurityBanner): ?>
    <div class="sec-banner">
      <div>
        <div class="sec-banner-title">Security setup recommended</div>
        <div class="sec-banner-sub">Enable TOTP or add a passkey to protect sensitive actions.</div>
      </div>
      <a class="btn btn-ghost btn-sm" href="account.php#totp-card">Open account</a>
    </div>
    <?php endif; ?>

    <div class="card">
      <div class="card-title"><div class="dot"></div>Quick actions</div>
      <div style="display:flex;gap:10px;flex-wrap:wrap;">
        <a class="btn btn-primary" href="create_code.php" style="width:auto;">Create a code</a>
        <a class="btn btn-ghost" href="my_codes.php" style="width:auto;">My codes</a>
        <a class="btn btn-ghost" href="rooms.php" style="width:auto;">Rooms</a>
        <a class="btn btn-ghost" href="notifications.php" style="width:auto;">Notifications</a>
        <a class="btn btn-ghost" href="backup.php" style="width:auto;">Backup</a>
      </div>
      <div style="margin-top:12px;font-size:12px;color:var(--muted);line-height:1.7;">
        The vault passphrase never leaves your browser. Code creation and reveal are now separated into dedicated pages.
      </div>
    </div>

    <div class="card">
      <div class="card-title"><div class="dot"></div>Security</div>
      <div style="font-size:12px;color:var(--muted);line-height:1.7;">
        In strong security mode, sensitive actions may require re-authentication (TOTP or passkey).
        Configure this in <a href="account.php" style="color:var(--text);">Account</a>.
      </div>
    </div>

  </div>
</div>

</body>
</html>
