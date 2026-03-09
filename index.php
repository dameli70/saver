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
<title><?= htmlspecialchars(APP_NAME) ?> — Save money with time locks</title>
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

.use{max-width:960px;margin:0 auto;padding:0 18px 22px;}
.use h2{font-family:var(--display);font-weight:900;font-size:16px;letter-spacing:1px;margin:0 0 10px;}
.bullets{display:grid;grid-template-columns:1fr;gap:10px;}
@media(min-width:740px){.bullets{grid-template-columns:repeat(3,1fr);} }
.bullet{border:1px solid var(--b1);background:rgba(0,0,0,.18);padding:14px;}
.bullet .t{font-family:var(--display);font-size:12px;font-weight:800;margin-bottom:6px;}
.bullet .d{font-size:12px;line-height:1.7;color:var(--muted);} 

.footer{border-top:1px solid var(--b1);padding:18px;color:var(--muted);font-size:11px;letter-spacing:.5px;text-align:center;}
.notice{max-width:960px;margin:0 auto;padding:18px 18px 0;}
.notice .box{border:1px solid rgba(255,170,0,.25);background:rgba(255,170,0,.06);padding:14px 16px;color:var(--muted);font-size:12px;line-height:1.6;}
.notice .box strong{color:var(--orange);} 

.faq{max-width:960px;margin:0 auto;padding:0 18px 60px;}
.faq h2{font-family:var(--display);font-weight:900;font-size:16px;letter-spacing:1px;margin:0 0 12px;}
.faq-grid{display:grid;grid-template-columns:1fr;gap:10px;}
@media(min-width:740px){.faq-grid{grid-template-columns:repeat(2,1fr);} }
.qa{background:rgba(13,15,20,.7);border:1px solid var(--b1);padding:14px;}
.qa summary{cursor:pointer;list-style:none;font-family:var(--display);font-weight:800;font-size:12px;letter-spacing:1px;line-height:1.4;}
.qa summary::-webkit-details-marker{display:none;}
.qa summary::after{content:'+';float:right;color:var(--muted);}
.qa[open] summary::after{content:'–';}
.qa p{margin-top:10px;color:var(--muted);font-size:12px;line-height:1.7;}
</style>
</head>
<body>
<div class="orb orb1"></div><div class="orb orb2"></div>
<div class="wrap">
  <div class="nav">
    <a class="logo" href="index.php"><?= htmlspecialchars(APP_NAME) ?></a>
    <div class="nav-r">
      <button class="btn btn-ghost btn-theme" type="button" data-theme-toggle>Theme</button>
      <a class="btn btn-ghost" href="#faq">FAQ</a>
      <?php if ($loggedIn): ?>
        <span class="pill"><?= htmlspecialchars($userEmail) ?></span>
        <?php if ($verified): ?>
          <a class="btn btn-ghost" href="dashboard.php">Dashboard</a>
          <a class="btn btn-ghost" href="create_code.php">Create Code</a>
          <a class="btn btn-ghost" href="my_codes.php">My Codes</a>
          <a class="btn btn-ghost" href="rooms.php">Rooms</a>
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
    <div class="box"><strong>Action required:</strong> verify your email to unlock your dashboard and start saving with time locks.</div>
  </div>
  <?php endif; ?>

  <div class="hero">
    <div class="kicker">Impulse-proof saving • Save together • Private by design</div>
    <div class="h1">Put a time lock between you and <span>impulse spending</span>.</div>
    <div class="sub">
      <?= htmlspecialchars(APP_NAME) ?> helps you build better money habits by adding friction: lock away the codes you use to spend (mobile money PINs, passwords, voucher codes)
      until a date you choose. For bigger goals, create a <strong>Saving Room</strong> to save with trusted people and clear rules.
      Your secrets are encrypted in your browser — the server can’t read them.
    </div>

    <div class="cta">
      <?php if ($loggedIn && $verified): ?>
        <a class="btn btn-primary" href="dashboard.php">Open my dashboard</a>
        <a class="btn btn-ghost" href="create_code.php">Create a time lock</a>
        <a class="btn btn-ghost" href="rooms.php">Explore saving rooms</a>
      <?php elseif ($loggedIn && !$verified): ?>
        <a class="btn btn-primary" href="account.php">Verify email to continue</a>
        <a class="btn btn-ghost" href="logout.php">Switch account</a>
      <?php else: ?>
        <a class="btn btn-primary" href="signup.php">Start saving</a>
        <a class="btn btn-ghost" href="login.php">I already have an account</a>
      <?php endif; ?>
    </div>

    <div class="grid">
      <div class="card">
        <h3>Cool-off period</h3>
        <p>Create a delay between a craving and a purchase. When the moment passes, you keep the money.</p>
      </div>
      <div class="card">
        <h3>Save with a room</h3>
        <p>Make a room for a goal (project, rent, trip). Set rules, invite people, and unlock by consensus or rotation.</p>
      </div>
      <div class="card">
        <h3>Private by design</h3>
        <p>We store encrypted blobs and labels. Your vault passphrase stays in your browser — even admins can’t decrypt your secrets.</p>
      </div>
    </div>
  </div>

  <div class="use">
    <h2>Popular ways people use <?= htmlspecialchars(APP_NAME) ?></h2>
    <div class="bullets">
      <div class="bullet"><div class="t">Break bad spending loops</div><div class="d">Lock your wallet PIN for 24 hours, a week, or until payday. Give yourself time to think.</div></div>
      <div class="bullet"><div class="t">Create a pause for habits</div><div class="d">Add a delay to high-risk moments. When you have to wait, it’s easier to choose what matters.</div></div>
      <div class="bullet"><div class="t">Fund a goal</div><div class="d">Use Saving Rooms to collect contributions for projects, school fees, business equipment, or travel.</div></div>
    </div>
  </div>

  <div class="how">
    <h2>How it works</h2>
    <div class="steps">
      <div class="step"><div class="n">1</div><div class="t">Create your vault</div><div class="d">Sign up, verify your email, and set a vault passphrase (used only in your browser).</div></div>
      <div class="step"><div class="n">2</div><div class="t">Create a time lock</div><div class="d">Choose what to lock (code / PIN / wallet flow), add a hint, and pick a reveal date.</div></div>
      <div class="step"><div class="n">3</div><div class="t">Save solo or together</div><div class="d">For group goals, create a Saving Room, invite trusted people, and set contribution rules.</div></div>
      <div class="step"><div class="n">4</div><div class="t">Reveal when it’s time</div><div class="d">After the date arrives, reveal requires strong re-authentication (passkey or authenticator code).</div></div>
    </div>

    <div style="margin-top:14px;color:var(--muted);font-size:11px;line-height:1.7;">
      Note: <?= htmlspecialchars(APP_NAME) ?> does not hold your funds or connect to your bank. It stores time-locked, encrypted access codes and group-saving rules.
    </div>
  </div>

  <div class="faq" id="faq">
    <h2>FAQ</h2>
    <div class="faq-grid">

      <details class="qa">
        <summary>Does <?= htmlspecialchars(APP_NAME) ?> hold my money?</summary>
        <p>No. <?= htmlspecialchars(APP_NAME) ?> does not connect to your bank or wallet. It stores time‑locked, encrypted codes (and room rules) so you can create a cool‑off period before spending.</p>
      </details>

      <details class="qa">
        <summary>Can admins read my locked codes?</summary>
        <p>No. Your vault passphrase stays in your browser. The server stores encrypted blobs and labels — even admins can’t decrypt your secrets.</p>
      </details>

      <details class="qa">
        <summary>What if I forget my vault passphrase?</summary>
        <p>Your vault passphrase can’t be reset by email. If you forget it, your locked codes can’t be recovered. Use a password manager and keep an encrypted backup.</p>
      </details>

      <details class="qa">
        <summary>What’s a “Saving Room”?</summary>
        <p>A Saving Room is a shared goal with clear rules: dates, contributions, and how unlocking works. You can save with trusted people and keep everyone aligned.</p>
      </details>

      <details class="qa">
        <summary>Can I unlock early?</summary>
        <p>Time locks are meant to protect you from impulse decisions. In general, you unlock when the date arrives — and sensitive actions may ask for extra confirmation (passkey or authenticator code).</p>
      </details>

      <details class="qa">
        <summary>How do backups work?</summary>
        <p>Backups are encrypted snapshots you can download and restore later. They help you move to a new device without relying on plaintext storage.</p>
      </details>

    </div>
  </div>

  <div class="footer">© <?= date('Y') ?> <?= htmlspecialchars(APP_NAME) ?> • <a href="#faq">FAQ</a> • Time locks for better money habits</div>
</div>
</body>
</html>
