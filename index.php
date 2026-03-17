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
/* Landing page only: keep selectors scoped to avoid global collisions. */
body.page-index .orb{filter:blur(120px);}
body.page-index .orb1{width:520px;height:520px;top:-170px;right:-120px;}
body.page-index .orb2{width:360px;height:360px;bottom:40px;left:-90px;}

body.page-index .landing-wrap{position:relative;z-index:1;}

body.page-index .landing-hero{max-width:960px;margin:0 auto;padding:54px 18px 34px;}
@media(max-width:520px){body.page-index .landing-hero{padding-top:40px;}}

body.page-index .kicker{display:inline-flex;align-items:center;gap:10px;color:var(--text);font-size:10px;letter-spacing:2.2px;text-transform:uppercase;
  background:linear-gradient(135deg, rgb(var(--accent-rgb) / .20), rgb(var(--accent2-rgb) / .10));
  border:1px solid rgb(var(--accent-rgb) / .28);
  padding:8px 14px;margin-bottom:18px;border-radius:var(--radius-pill);
  backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);
}
body.page-index .h1{font-family:var(--display);font-weight:700;letter-spacing:-1.2px;font-size:clamp(30px,5vw,56px);line-height:1.02;margin-bottom:12px;}
body.page-index .h1 span{background:linear-gradient(135deg,var(--accent),var(--accent2));-webkit-background-clip:text;background-clip:text;color:transparent;}
body.page-index .sub{color:var(--muted);font-size:14px;line-height:1.75;max-width:720px;margin-bottom:22px;}
body.page-index .cta{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:18px;}

body.page-index .landing-teaser-grid{display:grid;grid-template-columns:1fr;gap:12px;margin-top:26px;}
@media(min-width:740px){body.page-index .landing-teaser-grid{grid-template-columns:repeat(3,1fr);} }
body.page-index .landing-teaser-card{background:linear-gradient(180deg, var(--s3), var(--s1));
  border:1px solid var(--b1);padding:18px;border-radius:var(--radius-card);box-shadow:var(--shadow-card);
  transition:transform .18s,box-shadow .18s,border-color .18s,background .18s;
  backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);
}
@media(hover:hover){
  body.page-index .landing-teaser-card:hover{transform:translateY(-2px);border-color:var(--b2);box-shadow:var(--shadow-card-hover);}
}
body.page-index .landing-teaser-card h3{font-family:var(--mono);font-size:10px;letter-spacing:2.2px;text-transform:uppercase;color:var(--muted);margin-bottom:10px;}
body.page-index .landing-teaser-card p{color:var(--muted);font-size:13px;line-height:1.7;}

body.page-index .landing-preview{max-width:960px;margin:0 auto;padding:0 18px 18px;}
body.page-index .landing-preview-card{border:1px solid var(--b1);
  background:linear-gradient(180deg, var(--s2), var(--s1));
  padding:18px;border-radius:var(--radius-card);box-shadow:var(--shadow-card);
  backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);
}
body.page-index .landing-preview-badges{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px;}
body.page-index .landing-preview-badges .badge{border-color:rgb(var(--accent-rgb) / .25);
  background:rgb(var(--accent-rgb) / .06);
  color:color-mix(in srgb, var(--accent) 70%, var(--text));
}
body.page-index .landing-preview-title{font-family:var(--display);font-weight:900;font-size:16px;letter-spacing:-.2px;margin-bottom:8px;}
body.page-index .landing-preview-sub{color:var(--muted);font-size:12px;line-height:1.7;margin-bottom:14px;}
body.page-index .landing-preview-ui{border:1px solid var(--b1);
  background:linear-gradient(180deg, var(--s3), var(--s2));
  border-radius:var(--radius-card);
  padding:12px;
  display:grid;gap:10px;
}
body.page-index .landing-preview-row{display:flex;align-items:center;justify-content:space-between;gap:12px;}
body.page-index .landing-preview-row .k{font-family:var(--mono);font-size:10px;letter-spacing:1.8px;text-transform:uppercase;color:var(--muted);}
body.page-index .landing-preview-row .v{font-family:var(--mono);font-size:12px;letter-spacing:.2px;color:var(--text);}

body.page-index .landing-features{max-width:960px;margin:0 auto;padding:0 18px 44px;}
body.page-index .landing-features h2{font-family:var(--display);font-weight:900;font-size:16px;letter-spacing:1px;margin:18px 0 8px;}
body.page-index .landing-features-sub{color:var(--muted);font-size:12px;line-height:1.7;max-width:760px;}
body.page-index .landing-features-grid{display:grid;grid-template-columns:1fr;gap:10px;margin-top:14px;}
@media(min-width:740px){body.page-index .landing-features-grid{grid-template-columns:repeat(3,1fr);} }
body.page-index .landing-feature-card{border:1px solid var(--b1);background:var(--s1);padding:14px;border-radius:var(--radius-card);}
body.page-index .landing-feature-card .t{font-family:var(--display);font-size:12px;font-weight:900;margin-bottom:6px;}
body.page-index .landing-feature-card .d{font-size:12px;line-height:1.7;color:var(--muted);} 

body.page-index .landing-use{max-width:960px;margin:0 auto;padding:0 18px 22px;}
body.page-index .landing-use h2{font-family:var(--display);font-weight:900;font-size:16px;letter-spacing:1px;margin:0 0 10px;}
body.page-index .landing-bullets{display:grid;grid-template-columns:1fr;gap:10px;}
@media(min-width:740px){body.page-index .landing-bullets{grid-template-columns:repeat(3,1fr);} }
body.page-index .landing-bullet{border:1px solid var(--b1);background:var(--s1);padding:14px;border-radius:var(--radius-card);}
body.page-index .landing-bullet .t{font-family:var(--display);font-size:12px;font-weight:800;margin-bottom:6px;}
body.page-index .landing-bullet .d{font-size:12px;line-height:1.7;color:var(--muted);} 

body.page-index .landing-how{max-width:960px;margin:0 auto;padding:10px 18px 50px;}
body.page-index .landing-how h2{font-family:var(--display);font-weight:900;font-size:16px;letter-spacing:1px;margin:18px 0 12px;}
body.page-index .landing-steps{display:grid;grid-template-columns:1fr;gap:10px;}
@media(min-width:740px){body.page-index .landing-steps{grid-template-columns:repeat(2,1fr);} }
body.page-index .landing-step{background:var(--s2);border:1px solid var(--b1);padding:16px;border-radius:var(--radius-card);}
body.page-index .landing-step .n{font-family:var(--display);font-weight:900;color:var(--accent);font-size:18px;margin-bottom:6px;}
body.page-index .landing-step .t{font-size:12px;letter-spacing:1px;text-transform:uppercase;color:var(--text);margin-bottom:6px;}
body.page-index .landing-step .d{font-size:12px;line-height:1.7;color:var(--muted);} 

body.page-index .landing-footer{border-top:1px solid var(--b1);padding:18px;color:var(--muted);font-size:11px;letter-spacing:.5px;text-align:center;}
body.page-index .landing-footer a{color:var(--text);text-decoration:none;border-bottom:1px solid var(--b2);}
body.page-index .landing-footer a:hover{border-bottom-color:var(--accent);}

body.page-index .notice{max-width:960px;margin:0 auto;padding:18px 18px 0;}
body.page-index .notice .box{border:1px solid color-mix(in srgb, var(--orange) 25%, transparent);background:color-mix(in srgb, var(--orange) 6%, transparent);padding:14px 16px;color:var(--muted);font-size:12px;line-height:1.6;border-radius:var(--radius-card);}
body.page-index .notice .box strong{color:var(--orange);} 

body.page-index .landing-faq{max-width:960px;margin:0 auto;padding:0 18px 60px;}
body.page-index .landing-faq h2{font-family:var(--display);font-weight:900;font-size:16px;letter-spacing:1px;margin:0 0 12px;}
body.page-index .landing-faq-grid{display:grid;grid-template-columns:1fr;gap:10px;}
@media(min-width:740px){body.page-index .landing-faq-grid{grid-template-columns:repeat(2,1fr);} }
body.page-index .landing-qa{background:var(--s2);border:1px solid var(--b1);padding:14px;border-radius:var(--radius-card);}
body.page-index .landing-qa summary{cursor:pointer;list-style:none;font-family:var(--display);font-weight:800;font-size:12px;letter-spacing:1px;line-height:1.4;}
body.page-index .landing-qa summary::-webkit-details-marker{display:none;}
body.page-index .landing-qa summary::after{content:'+';float:right;color:var(--muted);}
body.page-index .landing-qa[open] summary::after{content:'–';}
body.page-index .landing-qa p{margin-top:10px;color:var(--muted);font-size:12px;line-height:1.7;}
</style>
</head>
<body class="page-index">
<div class="orb orb1"></div><div class="orb orb2"></div>
<div id="app" class="landing-wrap">
  <?php include __DIR__ . '/includes/topbar_public.php'; ?>

  <?php if ($loggedIn && !$verified): ?>
  <div class="notice">
    <div class="box"><?= t('index.notice_verify') ?></div>
  </div>
  <?php endif; ?>

  <div class="landing-hero">
    <div class="kicker"><?php e('index.kicker'); ?></div>
    <h1 class="h1"><?= t('index.h1') ?></h1>
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

    <div class="landing-teaser-grid">
      <div class="landing-teaser-card">
        <h3><?php e('index.card1_title'); ?></h3>
        <p><?php e('index.card1_desc'); ?></p>
      </div>
      <div class="landing-teaser-card">
        <h3><?php e('index.card2_title'); ?></h3>
        <p><?php e('index.card2_desc'); ?></p>
      </div>
      <div class="landing-teaser-card">
        <h3><?php e('index.card3_title'); ?></h3>
        <p><?php e('index.card3_desc'); ?></p>
      </div>
    </div>
  </div>

  <div class="landing-preview">
    <div class="landing-preview-card">
      <div class="landing-preview-badges">
        <span class="badge"><?php e('index.preview.badge_server'); ?></span>
        <span class="badge"><?php e('index.preview.badge_client'); ?></span>
        <span class="badge"><?php e('index.preview.badge_reauth'); ?></span>
      </div>
      <div class="landing-preview-title"><?php e('index.preview.title'); ?></div>
      <div class="landing-preview-sub"><?php e('index.preview.sub'); ?></div>

      <div class="landing-preview-ui" aria-hidden="true">
        <div class="landing-preview-row"><span class="k"><?php e('index.preview.k_label'); ?></span><span class="v"><?php e('index.preview.v_label'); ?></span></div>
        <div class="landing-preview-row"><span class="k"><?php e('index.preview.k_state'); ?></span><span class="v"><?php e('index.preview.v_state'); ?></span></div>
        <div class="landing-preview-row"><span class="k"><?php e('index.preview.k_unlock'); ?></span><span class="v"><?php e('index.preview.v_unlock'); ?></span></div>
      </div>
    </div>
  </div>

  <div class="landing-features" id="features">
    <h2><?php e('index.features.title'); ?></h2>
    <div class="landing-features-sub"><?php e('index.features.sub'); ?></div>
    <div class="landing-features-grid">
      <div class="landing-feature-card"><div class="t"><?php e('index.features.f1_t'); ?></div><div class="d"><?php e('index.features.f1_d'); ?></div></div>
      <div class="landing-feature-card"><div class="t"><?php e('index.features.f2_t'); ?></div><div class="d"><?php e('index.features.f2_d'); ?></div></div>
      <div class="landing-feature-card"><div class="t"><?php e('index.features.f3_t'); ?></div><div class="d"><?php e('index.features.f3_d'); ?></div></div>
      <div class="landing-feature-card"><div class="t"><?php e('index.features.f4_t'); ?></div><div class="d"><?php e('index.features.f4_d'); ?></div></div>
      <div class="landing-feature-card"><div class="t"><?php e('index.features.f5_t'); ?></div><div class="d"><?php e('index.features.f5_d'); ?></div></div>
      <div class="landing-feature-card"><div class="t"><?php e('index.features.f6_t'); ?></div><div class="d"><?php e('index.features.f6_d'); ?></div></div>
      <div class="landing-feature-card"><div class="t"><?php e('index.features.f7_t'); ?></div><div class="d"><?php e('index.features.f7_d'); ?></div></div>
      <div class="landing-feature-card"><div class="t"><?php e('index.features.f8_t'); ?></div><div class="d"><?php e('index.features.f8_d'); ?></div></div>
      <div class="landing-feature-card"><div class="t"><?php e('index.features.f9_t'); ?></div><div class="d"><?php e('index.features.f9_d'); ?></div></div>
    </div>
  </div>

  <div class="landing-use">
    <h2><?php e('index.popular_uses', ['app' => APP_NAME]); ?></h2>
    <div class="landing-bullets">
      <div class="landing-bullet"><div class="t"><?php e('index.bullet1_t'); ?></div><div class="d"><?php e('index.bullet1_d'); ?></div></div>
      <div class="landing-bullet"><div class="t"><?php e('index.bullet2_t'); ?></div><div class="d"><?php e('index.bullet2_d'); ?></div></div>
      <div class="landing-bullet"><div class="t"><?php e('index.bullet3_t'); ?></div><div class="d"><?php e('index.bullet3_d'); ?></div></div>
    </div>
  </div>

  <div class="landing-how">
    <h2><?php e('index.how_it_works'); ?></h2>
    <div class="landing-steps">
      <div class="landing-step"><div class="n">1</div><div class="t"><?php e('index.step1_t'); ?></div><div class="d"><?php e('index.step1_d'); ?></div></div>
      <div class="landing-step"><div class="n">2</div><div class="t"><?php e('index.step2_t'); ?></div><div class="d"><?php e('index.step2_d'); ?></div></div>
      <div class="landing-step"><div class="n">3</div><div class="t"><?php e('index.step3_t'); ?></div><div class="d"><?php e('index.step3_d'); ?></div></div>
      <div class="landing-step"><div class="n">4</div><div class="t"><?php e('index.step4_t'); ?></div><div class="d"><?php e('index.step4_d'); ?></div></div>
    </div>

    <div style="margin-top:14px;color:var(--muted);font-size:11px;line-height:1.7;">
      <?php e('index.note_html', ['app' => APP_NAME]); ?>
    </div>
  </div>

  <div class="landing-faq" id="faq">
    <h2><?php e('index.faq_title'); ?></h2>
    <div class="landing-faq-grid">

      <details class="landing-qa">
        <summary><?php e('index.faq_q1', ['app' => APP_NAME]); ?></summary>
        <p><?php e('index.faq_a1', ['app' => APP_NAME]); ?></p>
      </details>

      <details class="landing-qa">
        <summary><?php e('index.faq_q2'); ?></summary>
        <p><?php e('index.faq_a2'); ?></p>
      </details>

      <details class="landing-qa">
        <summary><?php e('index.faq_q3'); ?></summary>
        <p><?php e('index.faq_a3'); ?></p>
      </details>

      <details class="landing-qa">
        <summary><?php e('index.faq_q4'); ?></summary>
        <p><?php e('index.faq_a4'); ?></p>
      </details>

      <details class="landing-qa">
        <summary><?php e('index.faq_q5'); ?></summary>
        <p><?php e('index.faq_a5'); ?></p>
      </details>

      <details class="landing-qa">
        <summary><?php e('index.faq_q6'); ?></summary>
        <p><?php e('index.faq_a6'); ?></p>
      </details>

    </div>
  </div>

  <div class="landing-footer">© <?= date('Y') ?> <?= htmlspecialchars(APP_NAME) ?> • <a href="#faq"><?php e('common.faq'); ?></a> • <?php e('index.footer'); ?></div>
</div>
</body>
</html> 
