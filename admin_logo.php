<?php
require_once __DIR__ . '/includes/install_guard.php';
requireInstalledForPage();

require_once __DIR__ . '/includes/helpers.php';
require_once __DIR__ . '/includes/app_settings.php';

startSecureSession();

if (!isLoggedIn()) {
    header('Location: login.php');
    exit;
}

if (!isEmailVerified()) {
    header('Location: account.php');
    exit;
}

if (!isAdmin()) {
    header('Location: dashboard.php');
    exit;
}

$userEmail = getCurrentUserEmail() ?? '';
$isAdmin   = true;
$csrf      = getCsrfToken();

$logoUrl = appUploadedLogoUrl();

header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none';");
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: no-referrer");
?>
<!doctype html>
<html <?= htmlLangAttr() ?>>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title><?= htmlspecialchars(APP_NAME) ?> — App logo</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;600;700;800;900&family=Syne:wght@400;500;600;700;800&family=JetBrains+Mono:wght@300;400;500;600&display=swap" rel="stylesheet">
<?php emitI18nJsGlobals(); ?>
<script src="assets/theme.js"></script>
<script src="assets/app.js"></script>
<link rel="stylesheet" href="assets/base.css">
<link rel="stylesheet" href="assets/app.css">
<style>
.wrap{max-width:980px;}
.crop-wrap{display:grid;grid-template-columns:1fr;gap:14px;align-items:start;}
@media(min-width:860px){.crop-wrap{grid-template-columns:360px 1fr;}}
.canvas-box{border:1px solid var(--b1);background:var(--s2);border-radius:var(--radius-card);padding:14px;}
.canvas-box canvas{width:100%;aspect-ratio:1/1;border-radius:14px;background:var(--s1);border:1px solid var(--b1);touch-action:none;}
.k{color:var(--muted);font-size:11px;line-height:1.6;}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center;}
.slider{width:220px;}
.preview-img{display:block;max-width:160px;max-height:160px;object-fit:contain;border:1px solid var(--b1);background:var(--s1);padding:8px;border-radius:16px;}
</style>
</head>
<body>
<div id="app">
  <?php $topbarBadgeText = 'SUPER ADMIN'; include __DIR__ . '/includes/topbar.php'; ?>

  <div class="app-body wide">

    <div class="page-head">
      <div>
        <div class="page-title">App logo</div>
        <div class="page-sub">Upload a square-cropped logo (stored encrypted server-side).</div>
      </div>
      <div class="page-actions">
        <a class="btn btn-ghost btn-sm" href="admin.php"><?php e('nav.admin'); ?></a>
        <a class="btn btn-ghost btn-sm" href="dashboard.php"><?php e('nav.dashboard'); ?></a>
      </div>
    </div>

    <div class="card wrap">
      <div class="card-title">Current logo</div>
      <div class="row" style="margin:10px 0 16px 0;">
        <img class="preview-img" id="current-logo" src="<?= $logoUrl !== '' ? htmlspecialchars($logoUrl, ENT_QUOTES, 'UTF-8') : 'data:,' ?>" alt="Current logo" onerror="this.style.display='none';" <?= $logoUrl === '' ? 'style="display:none;"' : '' ?>>
        <div class="k">
          <?php if ($logoUrl !== ''): ?>
            Served from <code>api/app_logo.php</code>.
          <?php else: ?>
            No uploaded logo found. The UI will fall back to <code>APP_LOGO_URL</code> if configured.
          <?php endif; ?>
        </div>
      </div>

      <div class="hr"></div>

      <div class="crop-wrap">
        <div class="canvas-box">
          <div class="k" style="margin-bottom:10px;">Drag to position. Use zoom to adjust crop.</div>
          <canvas id="crop-canvas" width="256" height="256" aria-label="Logo crop preview"></canvas>
          <div class="row" style="margin-top:12px;">
            <label class="k" for="zoom">Zoom</label>
            <input class="slider" id="zoom" type="range" min="1" max="3" step="0.01" value="1">
            <button class="btn btn-ghost btn-sm" type="button" id="reset">Reset</button>
          </div>
        </div>

        <div>
          <div class="field">
            <label>Select image</label>
            <input type="file" id="file" accept="image/png,image/jpeg,image/webp">
            <div class="k" style="margin-top:6px;">PNG / JPG / WebP. The client will crop to a square and upload a 512×512 PNG.</div>
          </div>

          <div class="row" style="margin-top:10px;">
            <button class="btn btn-primary" type="button" id="upload" disabled>Upload logo</button>
          </div>

          <div class="msg msg-ok" id="ok"></div>
          <div class="msg msg-err" id="err"></div>
        </div>
      </div>
    </div>

  </div>
</div>

<script>
(() => {
  const CSRF = <?= json_encode($csrf) ?>;

  const fileEl = document.getElementById('file');
  const canvas = document.getElementById('crop-canvas');
  const zoomEl = document.getElementById('zoom');
  const resetBtn = document.getElementById('reset');
  const uploadBtn = document.getElementById('upload');

  const okEl = document.getElementById('ok');
  const errEl = document.getElementById('err');

  function show(el, text){ if(!el) return; el.textContent = String(text||''); el.classList.add('show'); }
  function clear(el){ if(!el) return; el.textContent=''; el.classList.remove('show'); }

  const PREVIEW = 256;
  const OUT = 512;

  const st = {
    img: null,
    w: 0,
    h: 0,
    zoom: 1,
    offX: 0,
    offY: 0,
    dragging: false,
    dragStartX: 0,
    dragStartY: 0,
    dragOffX: 0,
    dragOffY: 0,
  };

  function baseScale(size){
    if(!st.img) return 1;
    const minDim = Math.min(st.w, st.h) || 1;
    return size / minDim;
  }

  function scale(size){
    return baseScale(size) * st.zoom;
  }

  function clampOffsets(){
    if(!st.img) return;
    const sc = scale(OUT);
    const dw = st.w * sc;
    const dh = st.h * sc;

    const minX = OUT - dw;
    const minY = OUT - dh;

    if (dw <= OUT) st.offX = (OUT - dw) / 2;
    else st.offX = Math.min(0, Math.max(minX, st.offX));

    if (dh <= OUT) st.offY = (OUT - dh) / 2;
    else st.offY = Math.min(0, Math.max(minY, st.offY));
  }

  function resetView(){
    if(!st.img) return;
    st.zoom = 1;
    if(zoomEl) zoomEl.value = '1';

    const sc = scale(OUT);
    const dw = st.w * sc;
    const dh = st.h * sc;
    st.offX = (OUT - dw) / 2;
    st.offY = (OUT - dh) / 2;

    clampOffsets();
    draw();
  }

  function draw(){
    const ctx = canvas.getContext('2d');
    if(!ctx){ return; }

    ctx.clearRect(0,0,PREVIEW,PREVIEW);

    if(!st.img){
      ctx.fillStyle = 'rgba(255,255,255,.05)';
      ctx.fillRect(0,0,PREVIEW,PREVIEW);
      ctx.fillStyle = 'rgba(255,255,255,.5)';
      ctx.font = '12px system-ui, -apple-system, Segoe UI, Roboto, sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText('Select an image to begin', PREVIEW/2, PREVIEW/2);
      return;
    }

    const scOut = scale(OUT);
    const scPrev = scOut * (PREVIEW / OUT);
    const ox = st.offX * (PREVIEW / OUT);
    const oy = st.offY * (PREVIEW / OUT);

    const dw = st.w * scPrev;
    const dh = st.h * scPrev;

    ctx.fillStyle = 'rgba(255,255,255,.02)';
    ctx.fillRect(0,0,PREVIEW,PREVIEW);

    ctx.imageSmoothingEnabled = true;
    ctx.imageSmoothingQuality = 'high';
    ctx.drawImage(st.img, ox, oy, dw, dh);

    ctx.strokeStyle = 'rgba(232,255,71,.22)';
    ctx.lineWidth = 2;
    ctx.strokeRect(1,1,PREVIEW-2,PREVIEW-2);
  }

  function setZoom(next){
    if(!st.img) return;

    const z = Math.max(1, Math.min(3, parseFloat(String(next||'1')) || 1));

    const scOld = scale(OUT);
    const srcCx = (OUT/2 - st.offX) / scOld;
    const srcCy = (OUT/2 - st.offY) / scOld;

    st.zoom = z;

    const scNew = scale(OUT);
    st.offX = (OUT/2) - (srcCx * scNew);
    st.offY = (OUT/2) - (srcCy * scNew);

    clampOffsets();
    draw();
  }

  function onPickFile(f){
    clear(okEl); clear(errEl);
    uploadBtn.disabled = true;

    if(!f){
      st.img = null;
      draw();
      return;
    }

    const r = new FileReader();
    r.onload = () => {
      const img = new Image();
      img.onload = () => {
        st.img = img;
        st.w = img.naturalWidth || img.width || 0;
        st.h = img.naturalHeight || img.height || 0;

        if(st.w < 64 || st.h < 64){
          st.img = null;
          draw();
          show(errEl, 'Image is too small.');
          return;
        }

        resetView();
        uploadBtn.disabled = false;
      };
      img.onerror = () => {
        st.img = null;
        draw();
        show(errEl, 'Could not load image.');
      };
      img.src = String(r.result||'');
    };
    r.onerror = () => {
      show(errEl, 'Could not read file.');
    };
    r.readAsDataURL(f);
  }

  function canvasPos(ev){
    const rect = canvas.getBoundingClientRect();
    const x = (ev.clientX - rect.left) * (PREVIEW / rect.width);
    const y = (ev.clientY - rect.top) * (PREVIEW / rect.height);
    return {x,y};
  }

  canvas.addEventListener('pointerdown', (ev) => {
    if(!st.img) return;
    st.dragging = true;
    canvas.setPointerCapture(ev.pointerId);
    const p = canvasPos(ev);
    st.dragStartX = p.x;
    st.dragStartY = p.y;
    st.dragOffX = st.offX;
    st.dragOffY = st.offY;
  });

  canvas.addEventListener('pointermove', (ev) => {
    if(!st.img || !st.dragging) return;
    const p = canvasPos(ev);

    const dxPrev = p.x - st.dragStartX;
    const dyPrev = p.y - st.dragStartY;

    const dxOut = dxPrev * (OUT / PREVIEW);
    const dyOut = dyPrev * (OUT / PREVIEW);

    st.offX = st.dragOffX + dxOut;
    st.offY = st.dragOffY + dyOut;

    clampOffsets();
    draw();
  });

  canvas.addEventListener('pointerup', () => { st.dragging = false; });
  canvas.addEventListener('pointercancel', () => { st.dragging = false; });

  zoomEl.addEventListener('input', () => setZoom(zoomEl.value));
  resetBtn.addEventListener('click', () => resetView());

  fileEl.addEventListener('change', () => {
    const f = (fileEl.files && fileEl.files[0]) ? fileEl.files[0] : null;
    onPickFile(f);
  });

  async function upload(){
    clear(okEl); clear(errEl);

    if(!st.img){
      show(errEl, 'Select an image first.');
      return;
    }

    uploadBtn.disabled = true;

    try{
      const out = document.createElement('canvas');
      out.width = OUT;
      out.height = OUT;

      const ctx = out.getContext('2d');
      if(!ctx) throw new Error('Canvas unavailable');

      clampOffsets();

      const sc = scale(OUT);
      const dw = st.w * sc;
      const dh = st.h * sc;

      ctx.clearRect(0,0,OUT,OUT);
      ctx.imageSmoothingEnabled = true;
      ctx.imageSmoothingQuality = 'high';
      ctx.drawImage(st.img, st.offX, st.offY, dw, dh);

      const blob = await new Promise((resolve, reject) => {
        out.toBlob((b) => b ? resolve(b) : reject(new Error('Failed to encode image')), 'image/png', 0.92);
      });

      const fd = new FormData();
      fd.append('logo', blob, 'logo.png');
      fd.append('csrf_token', CSRF);

      const resp = await fetch('api/app_logo_upload.php', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'X-CSRF-Token': CSRF },
        body: fd,
      });

      const j = await resp.json();
      if(!j || !j.success){
        throw new Error((j && j.error) ? j.error : 'Upload failed');
      }

      show(okEl, 'Uploaded.');

      const cur = document.getElementById('current-logo');
      if(cur){
        cur.style.display = 'block';
        cur.src = 'api/app_logo.php?v=' + String(Date.now());
      }

    }catch(e){
      show(errEl, (e && e.message) ? e.message : 'Upload failed');
    }finally{
      uploadBtn.disabled = false;
    }
  }

  uploadBtn.addEventListener('click', upload);

  draw();
})();
</script>
</body>
</html>
