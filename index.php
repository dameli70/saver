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
<html <?= htmlLangAttr() ?>>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title><?php e('index.title', ['app' => APP_NAME]); ?></title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;600;700;800;900&family=Syne:wght@400;500;600;700;800&family=JetBrains+Mono:wght@300;400;500;600&display=swap" rel="stylesheet">
<?php emitI18nJsGlobals(); ?>
<script src="assets/theme.js"></script>
<link rel="stylesheet" href="assets/base.css">
<link rel="stylesheet" href="assets/app.css">
<style>
a{color:inherit;}
.orb{filter:blur(120px);}
.orb1{width:520px;height:520px;top:-170px;right:-120px;}
.orb2{width:360px;height:360px;bottom:40px;left:-90px;}
.wrap{position:relative;z-index:1;}

.pill{font-size:10px;color:var(--muted);letter-spacing:1px;max-width:200px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;display:none;}
@media(min-width:560px){.pill{display:block;}}
 
.hero{max-width:960px;margin:0 auto;padding:54px 18px 34px;}
.kicker{display:inline-flex;align-items:center;gap:10px;color:var(--text);font-size:10px;letter-spacing:2.2px;text-transform:uppercase;
  background:linear-gradient(135deg, rgb(var(--accent-rgb) / .20), rgb(var(--accent2-rgb) / .10));
  border:1px solid rgb(var(--accent-rgb) / .28);
  padding:8px 14px;margin-bottom:18px;border-radius:var(--radius-pill);
  backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);
}
.h1{font-family:var(--display);font-weight:700;letter-spacing:-1.2px;font-size:clamp(30px,5vw,56px);line-height:1.02;margin-bottom:12px;}
.h1 span{background:linear-gradient(135deg,var(--accent),var(--accent2));-webkit-background-clip:text;background-clip:text;color:transparent;} 
.sub{color:var(--muted);font-size:14px;line-height:1.75;max-width:720px;margin-bottom:22px;}
.cta{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:18px;}
.grid{display:grid;grid-template-columns:1fr;gap:12px;margin-top:26px;}
@media(min-width:740px){.grid{grid-template-columns:repeat(3,1fr);} }
.card{background:linear-gradient(180deg, var(--s3), var(--s1));
  border:1px solid var(--b1);padding:18px;border-radius:var(--radius-card);box-shadow:var(--shadow-card);
  transition:transform .18s,box-shadow .18s,border-color .18s;background .18s;
  backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);
}
@media(hover:hover){
  .card:hover{transform:translateY(-2px);border-color:var(--b2);box-shadow:var(--shadow-card-hover);}
}
.card h3{font-family:var(--mono);font-size:10px;letter-spacing:2.2px;text-transform:uppercase;color:var(--muted);margin-bottom:10px;}
.card p{color:var(--muted);font-size:13px;line-height:1.7;}

.how{max-width:960px;margin:0 auto;padding:10px 18px 60px;}
.how h2{font-family:var(--display);font-weight:900;font-size:16px;letter-spacing:1px;margin:18px 0 12px;}
.steps{display:grid;grid-template-columns:1fr;gap:10px;}
@media(min-width:740px){.steps{grid-template-columns:repeat(2,1fr);} }
.step{background:var(--s2);border:1px solid var(--b1);padding:16px;border-radius:var(--radius-card);}
.step .n{font-family:var(--display);font-weight:900;color:var(--accent);font-size:18px;margin-bottom:6px;}
.step .t{font-size:12px;letter-spacing:1px;text-transform:uppercase;color:var(--text);margin-bottom:6px;}
.step .d{font-size:12px;line-height:1.7;color:var(--muted);} 

.use{max-width:960px;margin:0 auto;padding:0 18px 22px;}
.use h2{font-family:var(--display);font-weight:900;font-size:16px;letter-spacing:1px;margin:0 0 10px;}
.bullets{display:grid;grid-template-columns:1fr;gap:10px;}
@media(min-width:740px){.bullets{grid-template-columns:repeat(3,1fr);} }
.bullet{border:1px solid var(--b1);background:var(--s1);padding:14px;border-radius:var(--radius-card);}
.bullet .t{font-family:var(--display);font-size:12px;font-weight:800;margin-bottom:6px;}
.bullet .d{font-size:12px;line-height:1.7;color:var(--muted);} 

.footer{border-top:1px solid var(--b1);padding:18px;color:var(--muted);font-size:11px;letter-spacing:.5px;text-align:center;}
.notice{max-width:960px;margin:0 auto;padding:18px 18px 0;}
.notice .box{border:1px solid color-mix(in srgb, var(--orange) 25%, transparent);background:color-mix(in srgb, var(--orange) 6%, transparent);padding:14px 16px;color:var(--muted);font-size:12px;line-height:1.6;border-radius:var(--radius-card);}
.notice .box strong{color:var(--orange);} 

.faq{max-width:960px;margin:0 auto;padding:0 18px 60px;}
.faq h2{font-family:var(--display);font-weight:900;font-size:16px;letter-spacing:1px;margin:0 0 12px;}
.faq-grid{display:grid;grid-template-columns:1fr;gap:10px;}
@media(min-width:740px){.faq-grid{grid-template-columns:repeat(2,1fr);} }
.qa{background:var(--s2);border:1px solid var(--b1);padding:14px;border-radius:var(--radius-card);}
.qa summary{cursor:pointer;list-style:none;font-family:var(--display);font-weight:800;font-size:12px;letter-spacing:1px;line-height:1.4;}
.qa summary::-webkit-details-marker{display:none;}
.qa summary::after{content:'+';float:right;color:var(--muted);}
.qa[open] summary::after{content:'–';}
.qa p{margin-top:10px;color:var(--muted);font-size:12px;line-height:1.7;}
</style>
</head>
<body>
<div class="orb orb1"></div><div class="orb orb2"></div>
<div id="app" class="wrap">
  <?php include __DIR__ . '/includes/topbar_public.php'; ?>

  <?php if ($loggedIn && !$verified): ?>
  <div class="notice">
    <div class="box"><?= t('index.notice_verify') ?></div>
  </div>
  <?php endif; ?>

  <div class="hero">
    <div class="kicker"><?php e('index.kicker'); ?></div>
    <div class="h1"><?= t('index.h1') ?></div>
    <div class="sub"><?= t('index.sub_html', ['app' => htmlspecialchars(APP_NAME, ENT_QUOTES, 'UTF-8')]) ?></div>

    <div class="cta">
      <?php if ($loggedIn && $verified): ?>
        <a class="btn btn-primary" href="dashboard.php"><?php e('index.open_dashboard'); ?></a>
        <a class="btn btn-ghost" href="create_code.php"><?php e('index.create_time_lock'); ?></a>
        <a class="btn btn-ghost" href="rooms.php"><?php e('index.explore_rooms'); ?></a>
      <?php elseif ($loggedIn && !$verified): ?>
        <a class="btn btn-primary" href="account.php"><?php e('index.verify_email_continue'); ?></a>
        <a class="btn btn-ghost" href="logout.php"><?php e('index.switch_account'); ?></a>
      <?php else: ?>
        <a class="btn btn-primary" href="signup.php"><?php e('index.start_saving'); ?></a>
        <a class="btn btn-ghost" href="login.php"><?php e('index.have_account'); ?></a>
      <?php endif; ?>
    </div>

    <div class="grid">
      <div class="card">
        <h3><?php e('index.card1_title'); ?></h3>
        <p><?php e('index.card1_desc'); ?></p>
      </div>
      <div class="card">
        <h3><?php e('index.card2_title'); ?></h3>
        <p><?php e('index.card2_desc'); ?></p>
      </div>
      <div class="card">
        <h3><?php e('index.card3_title'); ?></h3>
        <p><?php e('index.card3_desc'); ?></p>
      </div>
    </div>
  </div>

  <div class="use">
    <h2><?php e('index.popular_uses', ['app' => APP_NAME]); ?></h2>
    <div class="bullets">
      <div class="bullet"><div class="t"><?php e('index.bullet1_t'); ?></div><div class="d"><?php e('index.bullet1_d'); ?></div></div>
      <div class="bullet"><div class="t"><?php e('index.bullet2_t'); ?></div><div class="d"><?php e('index.bullet2_d'); ?></div></div>
      <div class="bullet"><div class="t"><?php e('index.bullet3_t'); ?></div><div class="d"><?php e('index.bullet3_d'); ?></div></div>
    </div>
  </div>

  <div class="how">
    <h2><?php e('index.how_it_works'); ?></h2>
    <div class="steps">
      <div class="step"><div class="n">1</div><div class="t"><?php e('index.step1_t'); ?></div><div class="d"><?php e('index.step1_d'); ?></div></div>
      <div class="step"><div class="n">2</div><div class="t"><?php e('index.step2_t'); ?></div><div class="d"><?php e('index.step2_d'); ?></div></div>
      <div class="step"><div class="n">3</div><div class="t"><?php e('index.step3_t'); ?></div><div class="d"><?php e('index.step3_d'); ?></div></div>
      <div class="step"><div class="n">4</div><div class="t"><?php e('index.step4_t'); ?></div><div class="d"><?php e('index.step4_d'); ?></div></div>
    </div>

    <div style="margin-top:14px;color:var(--muted);font-size:11px;line-height:1.7;">
      <?php e('index.note_html', ['app' => APP_NAME]); ?>
    </div>
  </div>

  <div class="faq" id="faq">
    <h2><?php e('index.faq_title'); ?></h2>
    <div class="faq-grid">

      <details class="qa">
        <summary><?php e('index.faq_q1', ['app' => APP_NAME]); ?></summary>
        <p><?php e('index.faq_a1', ['app' => APP_NAME]); ?></p>
      </details>

      <details class="qa">
        <summary><?php e('index.faq_q2'); ?></summary>
        <p><?php e('index.faq_a2'); ?></p>
      </details>

      <details class="qa">
        <summary><?php e('index.faq_q3'); ?></summary>
        <p><?php e('index.faq_a3'); ?></p>
      </details>

      <details class="qa">
        <summary><?php e('index.faq_q4'); ?></summary>
        <p><?php e('index.faq_a4'); ?></p>
      </details>

      <details class="qa">
        <summary><?php e('index.faq_q5'); ?></summary>
        <p><?php e('index.faq_a5'); ?></p>
      </details>

      <details class="qa">
        <summary><?php e('index.faq_q6'); ?></summary>
        <p><?php e('index.faq_a6'); ?></p>
      </details>

    </div>
  </div>

  <div class="footer">© <?= date('Y') ?> <?= htmlspecialchars(APP_NAME) ?> • <a href="#faq"><?php e('common.faq'); ?></a> • <?php e('index.footer'); ?></div>
</div>
</body>
</html> 
