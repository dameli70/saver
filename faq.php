<?php
require_once __DIR__ . '/includes/install_guard.php';
requireInstalledForPage();

require_once __DIR__ . '/includes/helpers.php';
startSecureSession();

$loggedIn = isLoggedIn();
$verified = $loggedIn ? isEmailVerified() : false;
$isAdmin  = $loggedIn ? isAdmin() : false;
$userEmail = getCurrentUserEmail() ?? '';

header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; manifest-src 'self'; worker-src 'self'; frame-ancestors 'none';");
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: no-referrer");
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>FAQ — LOCKSMITH</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@300;400;500&family=Unbounded:wght@400;700;900&display=swap" rel="stylesheet">
<link rel="manifest" href="manifest.webmanifest">
<meta name="theme-color" content="#06070a">
<style>
:root{
  --bg:#06070a;--s1:#0d0f14;--s2:#13161d;--s3:#1a1d27;
  --b1:rgba(255,255,255,.07);--b2:rgba(255,255,255,.13);
  --accent:#e8ff47;--red:#ff4757;--blue:#47b8ff;--green:#47ffb0;--orange:#ffaa00;
  --text:#dde1ec;--muted:#525970;
  --mono:'DM Mono',monospace;--display:'Unbounded',sans-serif;
  --sat:env(safe-area-inset-top,0px);--sab:env(safe-area-inset-bottom,0px);
  --r:14px;
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:var(--mono);min-height:100vh;overflow-x:hidden;-webkit-font-smoothing:antialiased;}
a{color:inherit;}
.orb{position:fixed;border-radius:50%;filter:blur(120px);pointer-events:none;z-index:0;}
.orb1{width:520px;height:520px;background:rgba(232,255,71,.035);top:-170px;right:-120px;}
.orb2{width:360px;height:360px;background:rgba(71,184,255,.03);bottom:40px;left:-90px;}
.wrap{position:relative;z-index:1;}
.nav{display:flex;align-items:center;justify-content:space-between;padding:max(16px,var(--sat)) 20px 16px;border-bottom:1px solid var(--b1);background:rgba(6,7,10,.92);backdrop-filter:blur(14px);position:sticky;top:0;}
.logo{font-family:var(--display);font-weight:900;letter-spacing:-1px;font-size:18px;text-decoration:none;}
.logo span{color:var(--accent);} 
.nav-r{display:flex;align-items:center;gap:10px;flex-wrap:wrap;justify-content:flex-end;}
.pill{font-size:10px;color:var(--muted);letter-spacing:1px;max-width:200px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;display:none;}
@media(min-width:560px){.pill{display:block;}}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;
  padding:12px 18px;font-family:var(--mono);font-size:11px;letter-spacing:2px;
  text-transform:uppercase;cursor:pointer;border:none;transition:all .15s;border-radius:var(--r);
  -webkit-appearance:none;min-height:42px;text-decoration:none;}
.btn-primary{background:var(--accent);color:#000;font-weight:600;}
.btn-primary:hover{background:#f0ff60;}
.btn-ghost{background:transparent;border:1px solid var(--b2);color:var(--text);} 
.btn-ghost:hover{border-color:var(--text);} 

.container{max-width:980px;margin:0 auto;padding:28px 18px 70px;}
.h1{font-family:var(--display);font-weight:900;letter-spacing:-1px;font-size:28px;margin-bottom:8px;}
.sub{color:var(--muted);font-size:12px;line-height:1.7;margin-bottom:18px;max-width:780px;}

.grid{display:grid;grid-template-columns:1fr;gap:12px;}
@media(min-width:860px){.grid{grid-template-columns:280px 1fr;}}

.side{position:sticky;top:86px;align-self:start;border:1px solid var(--b1);background:rgba(13,15,20,.9);padding:14px;border-radius:var(--r);}
.side a{display:block;padding:10px 10px;border:1px solid transparent;border-radius:12px;text-decoration:none;font-size:11px;color:var(--muted);line-height:1.5;}
.side a:hover{border-color:var(--b1);color:var(--text);}

.card{border:1px solid var(--b1);background:rgba(13,15,20,.9);padding:18px;border-radius:var(--r);margin-bottom:12px;}
.card h2{font-family:var(--display);font-size:13px;letter-spacing:1px;margin-bottom:8px;color:var(--accent);}
.card p{color:var(--muted);font-size:12px;line-height:1.75;margin-bottom:10px;}
.card ul{margin-left:18px;color:var(--muted);font-size:12px;line-height:1.75;}
.card li{margin:6px 0;}
.note{font-size:11px;color:var(--muted);line-height:1.7;border-left:2px solid var(--b2);padding:8px 12px;margin-top:10px;}

</style>
</head>
<body>
<div class="orb orb1"></div><div class="orb orb2"></div>
<div class="wrap">
  <div class="nav">
    <a class="logo" href="index.php">LOCK<span>SMITH</span></a>
    <div class="nav-r">
      <?php if ($loggedIn): ?>
        <span class="pill"><?= htmlspecialchars($userEmail) ?></span>
        <?php if ($verified): ?>
          <a class="btn btn-ghost" href="dashboard.php">Dashboard</a>
          <a class="btn btn-ghost" href="codes.php">Codes</a>
          <a class="btn btn-ghost" href="profile.php">Profile</a>
          <a class="btn btn-ghost" href="security.php">Security</a>
          <?php if ($isAdmin): ?><a class="btn btn-ghost" href="admin.php">Admin</a><?php endif; ?>
        <?php else: ?>
          <a class="btn btn-ghost" href="profile.php">Verify Email</a>
        <?php endif; ?>
        <a class="btn btn-ghost" href="logout.php">Logout</a>
      <?php else: ?>
        <a class="btn btn-ghost" href="login.php">Login</a>
        <a class="btn btn-primary" href="signup.php">Create account</a>
      <?php endif; ?>
    </div>
  </div>

  <div class="container">
    <div class="h1">FAQ</div>
    <div class="sub">Quick answers. If you’re not sure what to do next, start with “What do I need to remember?”.</div>

    <div class="grid">
      <div class="side">
        <a href="#remember">What do I need to remember?</a>
        <a href="#time-lock">How does the time-lock work?</a>
        <a href="#vault">What is the vault passphrase?</a>
        <a href="#security">What are TOTP and passkeys?</a>
        <a href="#backups">Backups</a>
        <a href="#mobile">Mobile app</a>
        <a href="#pwa">Install as an app (PWA)</a>
      </div>

      <div>
        <div class="card" id="remember">
          <h2>What do I need to remember?</h2>
          <p>LOCKSMITH uses two different secrets:</p>
          <ul>
            <li><strong>Login password</strong> — lets you sign in. You can reset this by email.</li>
            <li><strong>Vault passphrase</strong> — unlocks your codes in your browser. The server never stores it and cannot reset it.</li>
          </ul>
          <div class="note">If you lose your vault passphrase, your stored codes cannot be recovered (even by an admin).</div>
        </div>

        <div class="card" id="time-lock">
          <h2>How does the time-lock work?</h2>
          <p>Each code has a reveal date. The server refuses to reveal the encrypted data until that date arrives (server time).</p>
          <p>Your device clock can’t bypass it.</p>
        </div>

        <div class="card" id="vault">
          <h2>What is the vault passphrase?</h2>
          <p>It’s the passphrase you type when generating or revealing codes. It’s used to derive an encryption key in your browser.</p>
          <ul>
            <li>Choose something long and memorable (10+ characters).</li>
            <li>Save it in a password manager and write down an offline copy.</li>
          </ul>
        </div>

        <div class="card" id="security">
          <h2>What are TOTP and passkeys?</h2>
          <p>They are extra security options to protect sensitive actions (reveal codes, backups, vault changes).</p>
          <ul>
            <li><strong>TOTP</strong>: 6‑digit codes from an authenticator app.</li>
            <li><strong>Passkeys</strong>: Face ID / Touch ID / security keys (WebAuthn).</li>
          </ul>
        </div>

        <div class="card" id="backups">
          <h2>Backups</h2>
          <p>Backups store only encrypted ciphertext and metadata (labels and dates). Your plaintext codes are never stored by the server.</p>
        </div>

        <div class="card" id="mobile">
          <h2>Mobile app</h2>
          <p>The mobile app needs the server base URL. You can find it in the installer and in your profile page.</p>
        </div>

        <div class="card" id="pwa">
          <h2>Install as an app (PWA)</h2>
          <p>You can install the web app on your phone:</p>
          <ul>
            <li>Android (Chrome): menu → “Install app”</li>
            <li>iPhone (Safari): Share → “Add to Home Screen”</li>
          </ul>
        </div>
      </div>
    </div>
  </div>
</div>

<script>
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('sw.js').catch(() => {});
}
</script>
</body>
</html>
