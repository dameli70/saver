<?php
require_once __DIR__ . '/includes/helpers.php';
startSecureSession();

$loggedIn = isLoggedIn();
$verified = $loggedIn ? isEmailVerified() : false;
$userEmail = getCurrentUserEmail() ?? '';

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
<title>LOCKSMITH — Time-Locked Codes</title>
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
body{background:var(--bg);color:var(--text);font-family:var(--mono);min-height:100vh;overflow-x:hidden;-webkit-font-smoothing:antialiased;}
a{color:inherit;}
.orb{position:fixed;border-radius:50%;filter:blur(120px);pointer-events:none;z-index:0;}
.orb1{width:520px;height:520px;background:rgba(232,255,71,.035);top:-170px;right:-120px;}
.orb2{width:360px;height:360px;background:rgba(71,184,255,.03);bottom:40px;left:-90px;}
.wrap{position:relative;z-index:1;}
.nav{display:flex;align-items:center;justify-content:space-between;padding:max(16px,var(--sat)) 20px 16px;border-bottom:1px solid var(--b1);background:rgba(6,7,10,.92);backdrop-filter:blur(14px);position:sticky;top:0;}
.logo{font-family:var(--display);font-weight:900;letter-spacing:-1px;font-size:18px;text-decoration:none;}
.logo span{color:var(--accent);} 
.nav-r{display:flex;align-items:center;gap:10px;}
.pill{font-size:10px;color:var(--muted);letter-spacing:1px;max-width:200px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;display:none;}
@media(min-width:560px){.pill{display:block;}}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;
  padding:12px 18px;font-family:var(--mono);font-size:11px;letter-spacing:2px;
  text-transform:uppercase;cursor:pointer;border:none;transition:all .15s;border-radius:0;
  -webkit-appearance:none;min-height:42px;text-decoration:none;}
.btn-primary{background:var(--accent);color:#000;font-weight:600;}
.btn-primary:hover{background:#f0ff60;}
.btn-ghost{background:transparent;border:1px solid var(--b2);color:var(--text);} 
.btn-ghost:hover{border-color:var(--text);} 
.hero{max-width:960px;margin:0 auto;padding:54px 18px 34px;}
.kicker{display:inline-flex;align-items:center;gap:10px;color:var(--green);font-size:10px;letter-spacing:2px;text-transform:uppercase;
  background:rgba(71,255,176,.06);border:1px solid rgba(71,255,176,.18);padding:6px 12px;margin-bottom:18px;}
.h1{font-family:var(--display);font-weight:900;letter-spacing:-1.4px;font-size:clamp(30px,5vw,52px);line-height:1.02;margin-bottom:12px;}
.h1 span{color:var(--accent);} 
.sub{color:var(--muted);font-size:13px;line-height:1.75;max-width:720px;margin-bottom:22px;}
.cta{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:18px;}
.grid{display:grid;grid-template-columns:1fr;gap:12px;margin-top:26px;}
@media(min-width:740px){.grid{grid-template-columns:repeat(3,1fr);} }
.card{background:rgba(13,15,20,.9);border:1px solid var(--b1);padding:18px;}
.card h3{font-family:var(--display);font-size:12px;letter-spacing:2px;text-transform:uppercase;color:var(--accent);margin-bottom:10px;}
.card p{color:var(--muted);font-size:12px;line-height:1.7;}
.how{max-width:960px;margin:0 auto;padding:10px 18px 60px;}
.how h2{font-family:var(--display);font-weight:900;font-size:16px;letter-spacing:1px;margin:18px 0 12px;}
.steps{display:grid;grid-template-columns:1fr;gap:10px;}
@media(min-width:740px){.steps{grid-template-columns:repeat(2,1fr);} }
.step{background:rgba(13,15,20,.7);border:1px solid var(--b1);padding:16px;}
.step .n{font-family:var(--display);font-weight:900;color:var(--accent);font-size:18px;margin-bottom:6px;}
.step .t{font-size:12px;letter-spacing:1px;text-transform:uppercase;color:var(--text);margin-bottom:6px;}
.step .d{font-size:12px;line-height:1.7;color:var(--muted);} 
.footer{border-top:1px solid var(--b1);padding:18px;color:var(--muted);font-size:11px;letter-spacing:.5px;text-align:center;}
.notice{max-width:960px;margin:0 auto;padding:18px 18px 0;}
.notice .box{border:1px solid rgba(255,170,0,.25);background:rgba(255,170,0,.06);padding:14px 16px;color:var(--muted);font-size:12px;line-height:1.6;}
.notice .box strong{color:var(--orange);} 
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
        <?php else: ?>
          <a class="btn btn-ghost" href="account.php">Verify Email</a>
        <?php endif; ?>
        <a class="btn btn-ghost" href="logout.php">Logout</a>
      <?php else: ?>
        <a class="btn btn-ghost" href="login.php">Login</a>
        <a class="btn btn-primary" href="signup.php">Create account</a>
      <?php endif; ?>
    </div>
  </div>

  <?php if ($loggedIn && !$verified): ?>
  <div class="notice">
    <div class="box"><strong>Action required:</strong> verify your email to unlock the dashboard and start generating codes.</div>
  </div>
  <?php endif; ?>

  <div class="hero">
    <div class="kicker">Zero-knowledge • Time-gated • AES-256-GCM</div>
    <div class="h1">Time-lock your <span>codes</span> — reveal them only when the date arrives.</div>
    <div class="sub">
      LOCKSMITH encrypts codes in your browser and stores only ciphertext on the server. The server enforces the reveal date; your device clock can’t bypass it.
    </div>

    <div class="cta">
      <?php if ($loggedIn && $verified): ?>
        <a class="btn btn-primary" href="dashboard.php">Generate a code</a>
        <a class="btn btn-ghost" href="dashboard.php#codes">View my codes</a>
      <?php elseif ($loggedIn && !$verified): ?>
        <a class="btn btn-primary" href="account.php">Verify email to continue</a>
        <a class="btn btn-ghost" href="logout.php">Switch account</a>
      <?php else: ?>
        <a class="btn btn-primary" href="signup.php">Generate a code</a>
        <a class="btn btn-ghost" href="login.php">I already have an account</a>
      <?php endif; ?>
    </div>

    <div class="grid">
      <div class="card">
        <h3>Time lock</h3>
        <p>Reveal is controlled by the server clock. Users can’t cheat by changing their local time.</p>
      </div>
      <div class="card">
        <h3>Zero-knowledge</h3>
        <p>Encryption and decryption happen in your browser. The server only ever stores and returns opaque ciphertext.</p>
      </div>
      <div class="card">
        <h3>Audit + safety</h3>
        <p>Copy and reveal events are recorded without logging secrets. Codes can be auto-saved until you confirm.</p>
      </div>
    </div>
  </div>

  <div class="how">
    <h2>How it works</h2>
    <div class="steps">
      <div class="step"><div class="n">1</div><div class="t">Create an account</div><div class="d">Pick a login password and a vault passphrase (used only in your browser).</div></div>
      <div class="step"><div class="n">2</div><div class="t">Verify your email</div><div class="d">Email verification is required before you can generate or reveal any codes.</div></div>
      <div class="step"><div class="n">3</div><div class="t">Generate + encrypt</div><div class="d">Your browser generates a random code and encrypts it with AES-256-GCM using a key derived from your passphrase.</div></div>
      <div class="step"><div class="n">4</div><div class="t">Seal until reveal date</div><div class="d">The server stores ciphertext and enforces the reveal date using its own clock.</div></div>
    </div>
  </div>

  <div class="footer">© <?= date('Y') ?> LOCKSMITH • Time-locked code vault</div>
</div>
</body>
</html>
