<?php
require_once __DIR__ . '/includes/install_guard.php';
requireInstalledForPage();

require_once __DIR__ . '/includes/helpers.php';
startSecureSession();

$loggedIn = isLoggedIn();
$verified = $loggedIn ? isEmailVerified() : false;
$isAdmin  = $loggedIn ? isAdmin() : false;
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
<script src="assets/theme.js"></script>
<link rel="stylesheet" href="assets/base.css">
<link rel="stylesheet" href="assets/panel.css">
<style>
a{color:inherit;}
.orb{filter:blur(120px);}
.orb1{width:520px;height:520px;top:-170px;right:-120px;}
.orb2{width:360px;height:360px;bottom:40px;left:-90px;}
.wrap{position:relative;z-index:1;}

.pill{font-size:10px;color:var(--muted);letter-spacing:1px;max-width:200px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;display:none;}
@media(min-width:560px){.pill{display:block;}}
 
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
      <button class="btn btn-ghost" type="button" data-theme-toggle></button>
      <?php if ($loggedIn): ?>
        <span class="pill"><?= htmlspecialchars($userEmail) ?></span>
        <?php if ($verified): ?>
          <a class="btn btn-ghost" href="dashboard.php">Dashboard</a>
          <a class="btn btn-ghost" href="create_code.php">Create Code</a>
          <a class="btn btn-ghost" href="my_codes.php">My Codes</a>
          <?php if ($isAdmin): ?>
            <a class="btn btn-ghost" href="admin.php">Admin</a>
          <?php endif; ?>
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
