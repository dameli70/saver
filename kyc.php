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
<title><?= htmlspecialchars(APP_NAME) ?> — KYC</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;600;700;800;900&family=Syne:wght@400;500;600;700;800&family=JetBrains+Mono:wght@300;400;500;600&display=swap" rel="stylesheet">
<?php emitI18nJsGlobals(); ?>
<script src="assets/theme.js"></script>
<script src="assets/app.js"></script>
<link rel="stylesheet" href="assets/base.css">
<link rel="stylesheet" href="assets/app.css">
<style>
.row{display:flex;align-items:flex-start;justify-content:space-between;gap:var(--ls-space-3);flex-wrap:wrap;}
.list{display:flex;flex-direction:column;gap:var(--ls-space-2);}
.doc{border:1px solid var(--b1);background:linear-gradient(180deg, var(--s2), var(--s1));padding:10px 12px;border-radius:var(--radius-card);display:flex;align-items:flex-start;justify-content:space-between;gap:10px;flex-wrap:wrap;}
</style>
</head>
<body>
<div id="app">
  <?php include __DIR__ . '/includes/topbar.php'; ?>

  <div class="app-body">

    <div class="page-head">
      <div>
        <div class="page-title">KYC</div>
        <div class="page-sub">Verify your identity for access to regulated features.</div>
      </div>
      <div class="page-actions">
        <a class="btn btn-ghost btn-sm" href="account.php"><?php e('nav.account'); ?></a>
      </div>
    </div>

    <div class="card" id="kyc-card">
      <div class="row">
        <div>
          <div class="k">Status</div>
          <div class="v" id="kyc-status">—</div>
        </div>
        <div class="badge wait" id="kyc-badge">⏳</div>
      </div>

      <div id="kyc-note" class="msg msg-warn"></div>
      <div id="kyc-err" class="msg msg-err"></div>
      <div id="kyc-ok" class="msg msg-ok"></div>

      <div class="hr"></div>

      <div class="k">Address</div>
      <div class="small" style="margin-top:6px;">This address will be used for your KYC submission.</div>

      <div style="margin-top:12px;display:grid;grid-template-columns:1fr;gap:12px;">
        <div class="field" style="margin:0;"><label>Address line 1</label><input id="addr-line1" autocomplete="address-line1"></div>
        <div class="field" style="margin:0;"><label>Address line 2 (optional)</label><input id="addr-line2" autocomplete="address-line2"></div>
        <div class="field" style="margin:0;"><label>City</label><input id="addr-city" autocomplete="address-level2"></div>
        <div class="field" style="margin:0;"><label>Region / State</label><input id="addr-region" autocomplete="address-level1"></div>
        <div class="field" style="margin:0;"><label>Postal code</label><input id="addr-postal" autocomplete="postal-code"></div>
        <div class="field" style="margin:0;"><label>Country</label><input id="addr-country" autocomplete="country"></div>
      </div>

      <div style="margin-top:12px;display:flex;gap:10px;flex-wrap:wrap;">
        <button class="btn btn-blue" type="button" id="addr-save"><?php e('common.save'); ?></button>
      </div>

      <div class="hr"></div>

      <div class="k">Documents</div>
      <div class="small" style="margin-top:6px;">Upload PDF or image documents (max 10MB each).</div>

      <div style="display:flex;gap:12px;flex-wrap:wrap;align-items:flex-end;margin-top:12px;">
        <div class="field" style="margin:0;min-width:180px;flex:1;">
          <label>Document type</label>
          <select id="doc-kind">
            <option value="">Select…</option>
            <option value="id">Identity document</option>
            <option value="address">Proof of address</option>
            <option value="selfie">Selfie</option>
            <option value="other">Other</option>
          </select>
        </div>
        <div class="field" style="margin:0;min-width:220px;flex:2;">
          <label>File</label>
          <input type="file" id="doc-file" accept="application/pdf,image/png,image/jpeg,image/webp">
        </div>
        <button class="btn btn-blue" type="button" id="doc-upload">Upload</button>
      </div>

      <div class="list" id="docs" style="margin-top:14px;"></div>

      <div class="hr"></div>

      <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center;">
        <button class="btn btn-primary" type="button" id="kyc-submit">Submit KYC</button>
        <div class="small" id="kyc-submit-hint"></div>
      </div>

    </div>

  </div>
</div>

<script>
(() => {
  const CSRF = <?= json_encode($csrf) ?>;

  const els = {
    badge: document.getElementById('kyc-badge'),
    status: document.getElementById('kyc-status'),
    note: document.getElementById('kyc-note'),
    ok: document.getElementById('kyc-ok'),
    err: document.getElementById('kyc-err'),

    line1: document.getElementById('addr-line1'),
    line2: document.getElementById('addr-line2'),
    city: document.getElementById('addr-city'),
    region: document.getElementById('addr-region'),
    postal: document.getElementById('addr-postal'),
    country: document.getElementById('addr-country'),

    save: document.getElementById('addr-save'),

    docKind: document.getElementById('doc-kind'),
    docFile: document.getElementById('doc-file'),
    docUpload: document.getElementById('doc-upload'),
    docs: document.getElementById('docs'),

    submit: document.getElementById('kyc-submit'),
    submitHint: document.getElementById('kyc-submit-hint'),
  };

  function show(el, text){ if(!el) return; el.textContent = String(text||''); el.classList.add('show'); }
  function clear(el){ if(!el) return; el.textContent=''; el.classList.remove('show'); }

  async function postCsrf(url, body){
    const r = await fetch(url, {
      method: 'POST',
      credentials: 'same-origin',
      headers: {'Content-Type': 'application/json', 'X-CSRF-Token': CSRF},
      body: JSON.stringify(body)
    });
    return r.json();
  }

  function setLocked(locked){
    const dis = !!locked;
    [els.line1, els.line2, els.city, els.region, els.postal, els.country].forEach(x => { if(x) x.disabled = dis; });
    if(els.save) els.save.disabled = dis;
    if(els.docKind) els.docKind.disabled = dis;
    if(els.docFile) els.docFile.disabled = dis;
    if(els.docUpload) els.docUpload.disabled = dis;
    if(els.submit) els.submit.disabled = dis;

    if(els.submitHint){
      els.submitHint.textContent = dis ? 'Submission is locked while in review.' : '';
    }
  }

  function badgeFor(status){
    const s = String(status||'draft');
    if(s === 'approved') return {cls:'badge ok', txt:'✓ APPROVED'};
    if(s === 'submitted') return {cls:'badge wait', txt:'⏳ SUBMITTED'};
    if(s === 'rejected') return {cls:'badge wait', txt:'REJECTED'};
    return {cls:'badge wait', txt:'DRAFT'};
  }

  function renderDocs(docs){
    if(!els.docs) return;
    els.docs.innerHTML = '';

    const arr = Array.isArray(docs) ? docs : [];
    if(!arr.length){
      const d = document.createElement('div');
      d.className = 'small';
      d.textContent = 'No documents uploaded yet.';
      els.docs.appendChild(d);
      return;
    }

    arr.forEach(doc => {
      const it = document.createElement('div');
      it.className = 'doc';

      const left = document.createElement('div');
      left.style.flex = '1';
      left.style.minWidth = '240px';

      const k = document.createElement('div');
      k.className = 'k';
      k.textContent = (doc.doc_kind ? String(doc.doc_kind).toUpperCase() : 'DOCUMENT');

      const v = document.createElement('div');
      v.className = 'v';
      v.textContent = doc.original_filename || ('Document #' + String(doc.id||''));

      const sm = document.createElement('div');
      sm.className = 'small';
      sm.textContent = (doc.content_type || '') + (doc.size_bytes ? (' · ' + String(Math.ceil(doc.size_bytes/1024)) + ' KB') : '');

      left.appendChild(k);
      left.appendChild(v);
      left.appendChild(sm);

      const right = document.createElement('div');
      right.style.display = 'flex';
      right.style.gap = '10px';
      right.style.alignItems = 'center';

      const a = document.createElement('a');
      a.className = 'btn btn-ghost btn-sm';
      a.href = doc.download_url || ('api/kyc_doc.php?id=' + encodeURIComponent(String(doc.id||'')));
      a.textContent = 'Download';

      right.appendChild(a);

      it.appendChild(left);
      it.appendChild(right);
      els.docs.appendChild(it);
    });
  }

  async function load(){
    clear(els.err); clear(els.ok); clear(els.note);
    if(els.badge){ els.badge.className = 'badge wait'; els.badge.textContent = '⏳'; }
    if(els.status) els.status.textContent = '—';

    try{
      const r = await fetch('api/kyc.php?action=status', {credentials:'same-origin'});
      const j = await r.json();
      if(!j || !j.success){
        throw new Error((j && j.error) ? j.error : 'Failed to load');
      }

      const sub = j.submission || {};
      const st = String(sub.status || 'draft');

      if(els.status) els.status.textContent = st;
      if(els.badge){
        const b = badgeFor(st);
        els.badge.className = b.cls;
        els.badge.textContent = b.txt;
      }

      const addr = j.address || {};
      if(els.line1) els.line1.value = addr.line1 || '';
      if(els.line2) els.line2.value = addr.line2 || '';
      if(els.city) els.city.value = addr.city || '';
      if(els.region) els.region.value = addr.region || '';
      if(els.postal) els.postal.value = addr.postal_code || '';
      if(els.country) els.country.value = addr.country || '';

      renderDocs(j.documents || []);

      const locked = (st === 'submitted' || st === 'approved');
      setLocked(locked);

      if(st === 'rejected' && sub.admin_note){
        show(els.note, String(sub.admin_note));
      }

    }catch(e){
      show(els.err, (e && e.message) ? e.message : 'Failed to load');
    }
  }

  if(els.save){
    els.save.addEventListener('click', async () => {
      clear(els.err); clear(els.ok);
      els.save.disabled = true;
      try{
        const j = await postCsrf('api/kyc.php', {
          action: 'save_address',
          line1: (els.line1 ? els.line1.value : ''),
          line2: (els.line2 ? els.line2.value : ''),
          city: (els.city ? els.city.value : ''),
          region: (els.region ? els.region.value : ''),
          postal_code: (els.postal ? els.postal.value : ''),
          country: (els.country ? els.country.value : ''),
        });
        if(!j || !j.success) throw new Error((j && j.error) ? j.error : 'Failed to save');
        show(els.ok, <?= json_encode(t('common.saved')) ?>);
      }catch(e){
        show(els.err, (e && e.message) ? e.message : 'Failed to save');
      }finally{
        els.save.disabled = false;
      }
    });
  }

  if(els.docUpload){
    els.docUpload.addEventListener('click', async () => {
      clear(els.err); clear(els.ok);
      els.docUpload.disabled = true;

      try{
        const f = (els.docFile && els.docFile.files && els.docFile.files[0]) ? els.docFile.files[0] : null;
        if(!f) throw new Error('Select a file first');

        const fd = new FormData();
        fd.append('doc', f, f.name || 'document');
        if(els.docKind && els.docKind.value) fd.append('doc_kind', els.docKind.value);

        const r = await fetch('api/kyc_upload.php', {
          method: 'POST',
          credentials: 'same-origin',
          headers: {'X-CSRF-Token': CSRF},
          body: fd,
        });

        let j = null;
        try{ j = await r.json(); }catch(e){ j = null; }

        if(!r.ok || !j || !j.success){
          throw new Error((j && j.error) ? j.error : 'Upload failed');
        }

        if(els.docFile) els.docFile.value = '';
        show(els.ok, 'Uploaded.');
        await load();

      }catch(e){
        show(els.err, (e && e.message) ? e.message : 'Upload failed');
      }finally{
        els.docUpload.disabled = false;
      }
    });
  }

  if(els.submit){
    els.submit.addEventListener('click', async () => {
      clear(els.err); clear(els.ok);
      els.submit.disabled = true;

      try{
        const j = await postCsrf('api/kyc.php', {action:'submit'});
        if(!j || !j.success) throw new Error((j && j.error) ? j.error : 'Submit failed');
        show(els.ok, 'Submitted.');
        await load();
      }catch(e){
        show(els.err, (e && e.message) ? e.message : 'Submit failed');
      }finally{
        els.submit.disabled = false;
      }
    });
  }

  load();
})();
</script>
</body>
</html>
