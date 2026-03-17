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
header("Permissions-Policy: clipboard-write=(self)");
?>
<!DOCTYPE html>
<html <?= htmlLangAttr() ?>>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title><?= htmlspecialchars(APP_NAME) ?> — <?= htmlspecialchars(t('page.my_codes')) ?></title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;600;700;800;900&family=Syne:wght@400;500;600;700;800&family=JetBrains+Mono:wght@300;400;500;600&display=swap" rel="stylesheet">
<?php emitI18nJsGlobals(); ?>
<script src="assets/theme.js"></script>
<script src="assets/app.js"></script>
<link rel="stylesheet" href="assets/base.css">
<link rel="stylesheet" href="assets/app.css">
<link rel="stylesheet" href="assets/my_codes_page.css">
</head>
<body>
<div class="orb orb1"></div><div class="orb orb2"></div>

<div id="app">
  <?php include __DIR__ . '/includes/topbar.php'; ?>

  <div class="app-body">

    <div class="page-head">
      <div>
        <div class="page-title"><?php e('page.my_codes'); ?></div>
        <div class="page-sub"><?php e('my_codes.intro'); ?></div>
      </div>
      <div class="page-actions">
        <a class="btn btn-primary btn-sm" href="create_code.php"><?php e('nav.create_code'); ?></a>
        <button class="btn btn-ghost btn-sm" type="button" onclick="loadLocks(true)">↻ <?php e('common.refresh'); ?></button>
      </div>
    </div>

    <div class="card locks-toolbar">
      <div class="toolbar">
        <div class="search">
          <input class="ls-input" id="locks-search" type="search" placeholder="<?= htmlspecialchars(t('my_codes.search_placeholder'), ENT_QUOTES, 'UTF-8') ?>" autocomplete="off">
        </div>

        <div class="locks-controls" aria-label="<?= htmlspecialchars(t('page.my_codes'), ENT_QUOTES, 'UTF-8') ?>">
          <div class="lc-ctl">
            <div class="lc-ctl-k"><?php e('my_codes.sort_label'); ?></div>
            <select class="ls-input lc-ctl-sel" id="locks-sort">
              <option value="created_desc"><?php e('my_codes.sort_created_newest'); ?></option>
              <option value="reveal_asc"><?php e('my_codes.sort_reveal_soonest'); ?></option>
              <option value="label_asc"><?php e('my_codes.sort_label_az'); ?></option>
            </select>
          </div>

          <div class="lc-ctl">
            <div class="lc-ctl-k"><?php e('my_codes.unlocking_label'); ?></div>
            <select class="ls-input lc-ctl-sel" id="locks-soon">
              <option value="all"><?php e('my_codes.unlocking_all'); ?></option>
              <option value="24h"><?php e('my_codes.unlocking_24h'); ?></option>
              <option value="7d"><?php e('my_codes.unlocking_7d'); ?></option>
            </select>
          </div>

          <details class="nav-dd lc-export" id="locks-export-dd">
            <summary class="btn btn-ghost btn-sm" aria-label="<?= htmlspecialchars(t('my_codes.export_label'), ENT_QUOTES, 'UTF-8') ?>"><span class="btn-ico" aria-hidden="true">⤓</span><span class="btn-txt"><?php e('my_codes.export_label'); ?></span></summary>
            <div class="nav-dd-panel lc-export-panel">
              <div class="nav-group-title"><?php e('my_codes.export_group_filtered'); ?></div>
              <button class="btn btn-ghost btn-sm" type="button" data-export="filtered" data-format="json"><?php e('my_codes.export_filtered_json'); ?></button>
              <button class="btn btn-ghost btn-sm" type="button" data-export="filtered" data-format="csv"><?php e('my_codes.export_filtered_csv'); ?></button>
              <div class="nav-group-title"><?php e('my_codes.export_group_selected'); ?></div>
              <button class="btn btn-ghost btn-sm" type="button" data-export="selected" data-format="json" id="locks-export-selected-json"><?php e('my_codes.export_selected_json'); ?></button>
              <button class="btn btn-ghost btn-sm" type="button" data-export="selected" data-format="csv" id="locks-export-selected-csv"><?php e('my_codes.export_selected_csv'); ?></button>
            </div>
          </details>

          <button class="btn btn-ghost btn-sm" type="button" id="locks-bulk-toggle"><span class="btn-ico" aria-hidden="true">☑</span><span class="btn-txt"><?php e('my_codes.select_mode'); ?></span></button>
        </div>

        <div class="seg" id="locks-seg" role="tablist" aria-label="<?= htmlspecialchars(t('page.my_codes'), ENT_QUOTES, 'UTF-8') ?>">
          <button type="button" class="active" data-filter="all" role="tab" aria-selected="true"><?php e('my_codes.filter_all'); ?></button>
          <button type="button" data-filter="sealed" role="tab" aria-selected="false"><?php e('my_codes.filter_sealed'); ?></button>
          <button type="button" data-filter="ready" role="tab" aria-selected="false"><?php e('my_codes.filter_ready'); ?></button>
          <button type="button" data-filter="wallet" role="tab" aria-selected="false"><?php e('my_codes.filter_wallet'); ?></button>
          <button type="button" data-filter="starred" role="tab" aria-selected="false"><?php e('my_codes.filter_starred'); ?></button>
        </div>
      </div>

      <div class="bulk-bar" id="locks-bulk-bar" style="display:none;">
        <div class="bulk-left"><span class="bulk-count" id="locks-bulk-count">0</span> <span class="bulk-sub"><?php e('my_codes.bulk_selected'); ?></span></div>
        <div class="bulk-actions">
          <button class="btn btn-ghost btn-sm" type="button" id="locks-bulk-clear"><?php e('my_codes.bulk_clear'); ?></button>
          <button class="btn btn-ghost btn-sm" type="button" id="locks-bulk-export"><?php e('my_codes.bulk_export'); ?></button>
          <button class="btn btn-red btn-sm" type="button" id="locks-bulk-delete"><?php e('my_codes.bulk_delete'); ?></button>
        </div>
      </div>
    </div>

    <div id="locks-wrap">
      <div class="empty"><div class="empty-icon">🔒</div><h3><?php e('common.loading'); ?></h3><p></p></div>
    </div>
  </div>
</div>

<!-- share overlay (pre-unlock) -->
<div id="share-overlay" class="ls-modal-overlay ls-sheet" onclick="closeShare(event)">
  <div class="ls-modal reveal-sheet" role="dialog" aria-modal="true" aria-labelledby="ps-title">
    <button class="ls-modal-x" type="button" aria-label="<?= htmlspecialchars(t('common.close'), ENT_QUOTES, 'UTF-8') ?>" onclick="closeShare();event.stopPropagation();">×</button>
    <div class="ls-modal-title" id="ps-title"><?php e('my_codes.share_title'); ?></div>
    <div class="ls-modal-sub"><?php e('my_codes.share_sub'); ?></div>

    <div class="small" id="ps-meta" style="margin-bottom:12px;"></div>

    <div class="vault-input-wrap">
      <label><?php e('create_code.vault_passphrase_label'); ?></label>
      <input type="password" id="ps-vault" placeholder="<?= htmlspecialchars(t('create_code.vault_passphrase_placeholder'), ENT_QUOTES, 'UTF-8') ?>" autocomplete="current-password">
      <div class="small" style="margin-top:8px;"><?php e('my_codes.share_note'); ?></div>
    </div>

    <div id="ps-legacy" style="display:none;">
      <div class="hr" style="margin:14px 0;"></div>
      <div class="vault-input-wrap" style="margin:0;">
        <label><?php e('my_codes.share_legacy_label'); ?></label>
        <input type="password" id="ps-code" placeholder="<?= htmlspecialchars(t('my_codes.share_legacy_placeholder'), ENT_QUOTES, 'UTF-8') ?>" autocomplete="off">
        <div class="small" style="margin-top:8px;"><?php e('my_codes.share_legacy_note'); ?></div>
      </div>
    </div>

    <label class="chk" style="margin:0 0 12px 0;">
      <input type="checkbox" id="ps-allow" checked>
      <span><?php e('my_codes.share_allow_label'); ?></span>
    </label>

    <div id="ps-err" class="msg msg-err"></div>

    <button class="btn btn-primary" id="ps-btn" onclick="createShareFromPrep()"><span class="btn-ico" id="ps-ico" aria-hidden="true">🔗</span><span class="btn-txt" id="ps-txt"><?php e('my_codes.share_create_btn'); ?></span></button>

    <div id="ps-out" class="rv-share" style="display:none;">
      <div class="hr"></div>
      <div class="rv-share-grid" style="margin-top:12px;">
        <div>
          <div class="k"><?php e('my_codes.share_link_label'); ?></div>
          <input class="ls-input" id="ps-url" readonly value="" style="margin-top:6px;">
          <button class="btn btn-ghost btn-sm btn-inline" type="button" id="ps-copy-url" style="margin-top:8px;"><?php e('my_codes.share_copy_link_btn'); ?></button>
        </div>
        <div>
          <div class="k"><?php e('my_codes.share_secret_label'); ?></div>
          <input class="ls-input" id="ps-secret" readonly value="" style="margin-top:6px;">
          <button class="btn btn-ghost btn-sm btn-inline" type="button" id="ps-copy-secret" style="margin-top:8px;"><?php e('my_codes.share_copy_secret_btn'); ?></button>
        </div>
      </div>

      <div class="msg msg-ok" id="ps-ok"></div>
      <button class="btn btn-red btn-sm btn-inline" type="button" id="ps-revoke" style="display:none;margin-top:12px;"><?php e('my_codes.share_revoke_btn'); ?></button>
    </div>
  </div>
</div>

<!-- reveal overlay -->
<div id="reveal-overlay" class="ls-modal-overlay ls-sheet" onclick="closeReveal(event)">
  <div class="ls-modal reveal-sheet" role="dialog" aria-modal="true" aria-labelledby="rv-label">
    <button class="ls-modal-x" type="button" aria-label="<?= htmlspecialchars(t('common.close'), ENT_QUOTES, 'UTF-8') ?>" onclick="closeReveal();event.stopPropagation();">×</button>
    <div class="ls-modal-title" id="rv-label"><?php e('my_codes.reveal_title_default'); ?></div>
    <div class="ls-modal-sub"><?php e('my_codes.reveal_sub'); ?></div>
    <div id="rv-hint" style="display:none;font-size:12px;color:var(--muted);line-height:1.6;margin-bottom:12px;"></div>

    <div class="vault-input-wrap">
      <label><?php e('create_code.vault_passphrase_label'); ?></label>
      <input type="password" id="rv-vault" placeholder="<?= htmlspecialchars(t('create_code.vault_passphrase_placeholder'), ENT_QUOTES, 'UTF-8') ?>" autocomplete="current-password">
    </div>

    <div class="reveal-pwd" id="rv-pwd"></div>

    <div id="rv-err" class="msg msg-err"></div>

    <button class="btn btn-primary" id="rv-btn" onclick="doReveal()"><span class="btn-ico" id="rv-btn-ico" aria-hidden="true">🔒</span><span class="btn-txt" id="rv-btn-txt"><?php e('my_codes.btn_decrypt_reveal'); ?></span></button>
    <button class="btn btn-ghost" id="rv-copy-btn" onclick="copyRevealed()" style="display:none;margin-top:10px;"><span class="btn-ico" aria-hidden="true">⧉</span><span class="btn-txt"><?php e('share.btn_copy'); ?></span></button>
    <div id="rv-clip-countdown" class="rv-clip-countdown" style="display:none;margin-top:8px;"></div>
    <button class="btn btn-ghost" id="rv-show-btn" onclick="showRevealedAgain()" style="display:none;margin-top:10px;"><span class="btn-ico" aria-hidden="true">👁</span><span class="btn-txt"><?php e('my_codes.show_again'); ?></span></button>
    <button class="btn btn-ghost" id="rv-share-btn" onclick="startShareFlow()" style="display:none;margin-top:10px;"><span class="btn-ico" aria-hidden="true">🔗</span><span class="btn-txt"><?php e('my_codes.share_create_btn'); ?></span></button>

    <div id="rv-share-wrap" class="rv-share" style="display:none;">
      <div class="hr"></div>
      <div class="k"><?php e('my_codes.reveal_share_title'); ?></div>
      <div class="small" style="margin-top:6px;"><?php e('my_codes.reveal_share_sub'); ?></div>

      <label class="chk" style="margin:12px 0 0 0;">
        <input type="checkbox" id="rv-share-allow" checked>
        <span><?php e('my_codes.share_allow_label'); ?></span>
      </label>

      <div class="rv-share-grid" style="margin-top:12px;">
        <div>
          <div class="k"><?php e('my_codes.share_link_label'); ?></div>
          <input class="ls-input" id="rv-share-url" readonly value="" style="margin-top:6px;">
          <button class="btn btn-ghost btn-sm btn-inline" type="button" id="rv-share-copy-url" style="margin-top:8px;"><?php e('my_codes.share_copy_link_btn'); ?></button>
        </div>
        <div>
          <div class="k"><?php e('my_codes.share_secret_label'); ?></div>
          <input class="ls-input" id="rv-share-secret" readonly value="" style="margin-top:6px;">
          <button class="btn btn-ghost btn-sm btn-inline" type="button" id="rv-share-copy-secret" style="margin-top:8px;"><?php e('my_codes.share_copy_secret_btn'); ?></button>
        </div>
      </div>

      <div class="msg msg-ok" id="rv-share-ok"></div>
      <div class="msg msg-err" id="rv-share-err"></div>

      <button class="btn btn-red btn-sm btn-inline" type="button" id="rv-share-revoke" style="display:none;margin-top:12px;"><?php e('my_codes.share_revoke_btn'); ?></button>
    </div>

    <div id="rv-zk-note" style="display:none;margin-top:10px;font-size:10px;color:var(--muted);letter-spacing:1px;line-height:1.6;">
      <?php e('my_codes.zk_note'); ?>
    </div>
  </div>
</div>

<script>
const CSRF = <?= json_encode($csrf) ?>;

let vaultPhraseSession = null;
let vaultSlotSession   = 1;

let revealedPwd = null;
let currentReveal = null; // {kind:'lock'|'wallet', id:string, label:string, hint:string, reveal_date:string, cipher_blob:string, iv:string, auth_tag:string, kdf_salt:string, kdf_iterations:int}

let currentShareId = null;
let shareAfterReveal = false;
let shareAfterPayload = null;

let currentShareLock = null;
let currentPreShareId = null;

let countdownTimer = null;
let countdownRefreshTimer = null;

let allLocksSession = [];
let locksOffline = false;
let locksLoading = false;
let locksLastError = null;

let locksFilter = 'all'; // all|sealed|ready|wallet|starred
let locksQuery = '';

let locksSort  = 'created_desc'; // created_desc|reveal_asc|label_asc
let locksSoon  = 'all'; // all|24h|7d

let locksBulkMode = false;
let locksSelected = new Set();

let revealAutoHideTimer = null;
let revealClipboardCountdownTimer = null;
let revealPlainHidden = false;

const LOCKS_STARS_KEY = (()=>{
  try{ return 'ls_my_codes_stars:' + String(location.pathname||''); }
  catch{ return 'ls_my_codes_stars'; }
})();

let locksStarsSet = new Set();

function lsGet(key){
  try{ return localStorage.getItem(key); }catch{ return null; }
}

function lsSet(key, val){
  try{ localStorage.setItem(key, String(val)); }catch{}
}

function lockKey(kind, id){
  return String(kind||'') + ':' + String(id||'');
}

function loadStars(){
  try{
    const arr = JSON.parse(lsGet(LOCKS_STARS_KEY) || '[]');
    locksStarsSet = new Set(Array.isArray(arr) ? arr.map(String) : []);
  }catch{
    locksStarsSet = new Set();
  }
}

function saveStars(){
  try{ lsSet(LOCKS_STARS_KEY, JSON.stringify(Array.from(locksStarsSet))); }
  catch{}
}

function isStarredLock(l){
  if(!l) return false;
  return locksStarsSet.has(lockKey(l.kind, l.id));
}

function toggleStarFor(l){
  if(!l) return;
  const k = lockKey(l.kind, l.id);
  if(locksStarsSet.has(k)) locksStarsSet.delete(k);
  else locksStarsSet.add(k);
  saveStars();
  updateLocksSegCounts();
  renderLocks();
}

const LOCKS_TOOLBAR_STATE_KEY = (()=>{
  try{ return 'ls_my_codes_toolbar:' + String(location.pathname||''); }
  catch{ return 'ls_my_codes_toolbar'; }
})();

function persistLocksToolbarState(){
  lsSet(LOCKS_TOOLBAR_STATE_KEY, JSON.stringify({
    filter: locksFilter,
    query: locksQuery,
    sort: locksSort,
    soon: locksSoon,
  }));
}

function restoreLocksToolbarState(){
  try{
    const st = JSON.parse(lsGet(LOCKS_TOOLBAR_STATE_KEY) || 'null');
    if(!st || typeof st !== 'object') return;

    const allowedFilters = ['all','sealed','ready','wallet','starred'];
    const allowedSort = ['created_desc','reveal_asc','label_asc'];
    const allowedSoon = ['all','24h','7d'];

    const f = allowedFilters.includes(String(st.filter||'')) ? String(st.filter) : 'all';
    const q = (typeof st.query === 'string') ? st.query : '';
    const s = allowedSort.includes(String(st.sort||'')) ? String(st.sort) : 'created_desc';
    const so = allowedSoon.includes(String(st.soon||'')) ? String(st.soon) : 'all';

    locksQuery = q;
    locksSort = s;
    locksSoon = so;

    const search = document.getElementById('locks-search');
    if(search) search.value = q;

    const sortSel = document.getElementById('locks-sort');
    if(sortSel) sortSel.value = locksSort;

    const soonSel = document.getElementById('locks-soon');
    if(soonSel) soonSel.value = locksSoon;

    setLocksFilter(f, {noRender:true, noPersist:true});
  }catch{}
}

const reduceMotion = (()=>{
  try{ return window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches; }
  catch{ return false; }
})();

function tr(key, fallback){
  if(window.LS && LS.t){
    const v = LS.t(key);
    if(v && v !== key) return v;
  }
  return fallback || key;
}

function toast(msg,type='ok'){
  if(window.LS && LS.toast) LS.toast(msg,type);
}

function esc(s){
  return (window.LS && LS.esc) ? LS.esc(s) : String(s||'');
}

function fmt(tpl, vars){
  return String(tpl||'').replace(/\{(\w+)\}/g, (m, k)=>{
    if(vars && Object.prototype.hasOwnProperty.call(vars, k)) return String(vars[k]);
    return m;
  });
}

function requireOnlineAction(){
  if(!locksOffline) return true;
  toast(tr('my_codes.offline_action_disabled', 'Offline mode: this action is disabled.'), 'warn');
  return false;
}

function parseUtc(ts){
  if(window.LS && typeof LS.parseUtc === 'function') return LS.parseUtc(ts);
  if(!ts) return null;
  const d = new Date(String(ts));
  return isNaN(d.getTime()) ? null : d;
}

function fmtLocalTs(ts){
  const d = parseUtc(ts);
  if(!d) return '';
  if(window.LS && typeof LS.fmtLocal === 'function') return LS.fmtLocal(d);
  return d.toLocaleString();
}

function fmtUtcTs(ts){
  const d = parseUtc(ts);
  if(!d) return '';
  if(window.LS && typeof LS.fmtUtc === 'function') return LS.fmtUtc(d);
  return new Intl.DateTimeFormat(undefined, {year:'numeric',month:'short',day:'numeric',hour:'2-digit',minute:'2-digit',timeZone:'UTC',timeZoneName:'short'}).format(d);
}

function fmtCountdown(totalSeconds){
  if(window.LS && typeof LS.fmtCountdown === 'function') return LS.fmtCountdown(totalSeconds);
  const s = Math.max(0, Math.floor(Number(totalSeconds)||0));
  const days = Math.floor(s/86400);
  const hours = Math.floor((s%86400)/3600);
  const minutes = Math.floor((s%3600)/60);
  const seconds = s%60;
  if(days > 0) return `${days}d ${hours}h ${minutes}m`;
  if(hours > 0) return `${hours}h ${minutes}m`;
  if(minutes > 0) return `${minutes}m ${seconds}s`;
  return `${seconds}s`;
}

function renderLoadingSkeleton(){
  const title = tr('common.loading', 'Loading…');
  const sub = tr('my_codes.loading_sub', 'Fetching your codes…');
  return `<div class="empty"><div class="empty-icon"><span class="spin light"></span></div><h3>${esc(title)}</h3><p>${esc(sub)}</p></div>`;
}

async function readJsonResponse(r){
  const txt = await r.text();
  try{ return JSON.parse(txt); }
  catch{
    throw new Error('Invalid server response');
  }
}

async function get(url){
  const r = await fetch(apiUrl(url), {credentials:'same-origin', headers:{'Accept':'application/json'}});
  return readJsonResponse(r);
}

async function postCsrf(url, body){
  const r = await fetch(apiUrl(url), {
    method: 'POST',
    credentials: 'same-origin',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      'X-CSRF-Token': CSRF,
    },
    body: JSON.stringify(body || {}),
  });
  return readJsonResponse(r);
}

function apiUrl(url){return url.startsWith('/') ? url.slice(1) : url;}

function getFilteredLocks(){
  const list = (allLocksSession || []).filter(l => matchesFilter(l) && matchesQuery(l) && matchesSoon(l));
  return sortLocks(list);
}

function renderLocks(){
  updateLocksSegCounts();
  updateBulkUi();

  const wrap = document.getElementById('locks-wrap');
  if(!wrap) return;

  if(locksLoading && !(allLocksSession && allLocksSession.length) && !locksOffline){
    wrap.innerHTML = renderLoadingSkeleton();
    return;
  }

  const list = getFilteredLocks();

  if(!locksOffline && locksLastError && !locksLoading && !list.length){
    const title = tr('my_codes.load_failed_title', 'Failed to load codes');
    const retry = tr('common.retry', 'Retry');
    wrap.innerHTML = `<div class="empty"><div class="empty-icon">⚠</div><h3>${esc(title)}</h3><p>${esc(locksLastError)}</p><button class="btn btn-ghost btn-sm" type="button" onclick="loadLocks(true)">↻ ${esc(retry)}</button></div>`;
    return;
  }

  if(locksOffline){
    wrap.innerHTML = '';

    const banner = document.createElement('div');
    banner.className = 'card';
    banner.style.marginBottom = '12px';

    const msg = document.createElement('div');
    msg.className = 'small';
    msg.textContent = tr('my_codes.offline_banner', 'Offline mode: showing cached metadata. Reveal is disabled until you’re back online.');

    banner.appendChild(msg);
    wrap.appendChild(banner);

    const holder = document.createElement('div');
    holder.innerHTML = '<div class="locks-grid" id="locks-grid"></div>';
    wrap.appendChild(holder.firstChild);

    const grid = document.getElementById('locks-grid');
    list.forEach(l => grid.appendChild(buildCard(l, {offline:true})));
    startCountdownTicker();
    return;
  }

  if(!list.length){
    const t1 = (window.LS && LS.t) ? LS.t('my_codes.empty_title') : '';
    const t2 = (window.LS && LS.t) ? LS.t('my_codes.empty_sub') : '';
    wrap.innerHTML = `<div class="empty"><div class="empty-icon">🔒</div><h3>${esc(t1 || 'No time locks yet')}</h3><p>${esc(t2 || 'Create one from “Create Lock”.')}</p></div>`;
    return;
  }

  wrap.innerHTML = '';

  if(locksLastError){
    const err = document.createElement('div');
    err.className = 'msg msg-err show';
    err.textContent = String(locksLastError || '');
    err.style.marginBottom = '12px';
    wrap.appendChild(err);
  }

  const holder = document.createElement('div');
  holder.innerHTML = '<div class="locks-grid" id="locks-grid"></div>';
  wrap.appendChild(holder.firstChild);

  const grid = document.getElementById('locks-grid');
  list.forEach(l => grid.appendChild(buildCard(l, {offline:locksOffline})));

  startCountdownTicker();
}

function setLocksFilter(next, opts){
  const o = opts || {};
  locksFilter = String(next || 'all');

  const seg = document.getElementById('locks-seg');
  if(seg){
    seg.querySelectorAll('button[data-filter]').forEach(b => {
      const isActive = (b.getAttribute('data-filter') === locksFilter);
      if(isActive) b.classList.add('active');
      else b.classList.remove('active');
      b.setAttribute('aria-selected', isActive ? 'true' : 'false');
    });
  }

  updateLocksSegCounts();
  if(!o.noPersist) persistLocksToolbarState();
  if(!o.noRender) renderLocks();
}

function setBulkMode(next){
  const v = !!next;
  if(v === locksBulkMode) return;
  locksBulkMode = v;
  if(!locksBulkMode) locksSelected.clear();
  updateBulkUi();
  renderLocks();
}

function toggleBulkSelection(key){
  if(!locksBulkMode) return;
  const k = String(key||'');
  if(!k) return;

  if(locksSelected.has(k)) locksSelected.delete(k);
  else locksSelected.add(k);

  const card = document.querySelector(`.lock-card[data-key="${k}"]`);
  if(card){
    if(locksSelected.has(k)) card.classList.add('bulk-selected');
    else card.classList.remove('bulk-selected');
  }

  const selBtn = document.querySelector(`.lc-select[data-key="${k}"]`);
  if(selBtn){
    const on = locksSelected.has(k);
    selBtn.textContent = on ? '☑' : '☐';
    selBtn.setAttribute('aria-pressed', on ? 'true' : 'false');
  }

  updateBulkUi();
}

function pruneBulkSelection(){
  const present = new Set((allLocksSession || []).map(l => lockKey(l.kind, l.id)));
  locksSelected.forEach(k => {
    if(!present.has(k)) locksSelected.delete(k);
  });
}

function updateBulkUi(){
  pruneBulkSelection();

  const toggleBtn = document.getElementById('locks-bulk-toggle');
  if(toggleBtn){
    toggleBtn.classList.toggle('active', locksBulkMode);
    toggleBtn.setAttribute('aria-pressed', locksBulkMode ? 'true' : 'false');
  }

  const bar = document.getElementById('locks-bulk-bar');
  if(bar) bar.style.display = locksBulkMode ? 'flex' : 'none';

  const n = locksSelected.size;
  const countEl = document.getElementById('locks-bulk-count');
  if(countEl) countEl.textContent = String(n);

  const clearBtn = document.getElementById('locks-bulk-clear');
  const exportBtn = document.getElementById('locks-bulk-export');
  const deleteBtn = document.getElementById('locks-bulk-delete');

  if(clearBtn) clearBtn.disabled = (n === 0);
  if(exportBtn) exportBtn.disabled = (n === 0);
  if(deleteBtn) deleteBtn.disabled = (n === 0) || locksOffline;

  const expSelJson = document.getElementById('locks-export-selected-json');
  const expSelCsv = document.getElementById('locks-export-selected-csv');
  if(expSelJson) expSelJson.disabled = (n === 0);
  if(expSelCsv) expSelCsv.disabled = (n === 0);
}

function getLockByKey(k){
  const key = String(k||'');
  if(!key) return null;
  for(const l of (allLocksSession || [])){
    if(lockKey(l.kind, l.id) === key) return l;
  }
  return null;
}

function downloadText(filename, text, mime){
  const blob = new Blob([String(text||'')], {type: mime || 'text/plain'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(()=>URL.revokeObjectURL(url), 1000);
}

function csvCell(v){
  const s = String(v ?? '');
  if(/[\n",]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
  return s;
}

function exportLocks(which, format){
  const scope = String(which||'filtered');
  const fmt2 = String(format||'json');

  const list = (scope === 'selected')
    ? Array.from(locksSelected).map(getLockByKey).filter(Boolean)
    : getFilteredLocks();

  if(scope === 'selected' && !list.length){
    toast(tr('my_codes.bulk_none_selected', 'Select at least one item.'), 'warn');
    return;
  }

  const ts = new Date();
  const safeTs = ts.toISOString().replace(/[:.]/g,'-');

  if(fmt2 === 'csv'){
    const cols = ['kind','id','label','hint','reveal_date','created_at','display_status','password_type','password_length','copied_at','revealed_at','carrier_name'];
    const rows = [cols.join(',')];
    list.forEach(l => {
      rows.push(cols.map(c => csvCell(l && Object.prototype.hasOwnProperty.call(l, c) ? l[c] : '')).join(','));
    });
    downloadText(`time_locks_${scope}_${safeTs}.csv`, rows.join('\n'), 'text/csv');
  }else{
    const payload = {exported_at: ts.toISOString(), scope, locks: list};
    downloadText(`time_locks_${scope}_${safeTs}.json`, JSON.stringify(payload, null, 2), 'application/json');
  }
}

async function bulkDeleteSelected(){
  if(!requireOnlineAction()) return;

  const keys = Array.from(locksSelected);
  if(!keys.length){
    toast(tr('my_codes.bulk_none_selected', 'Select at least one item.'), 'warn');
    return;
  }

  const msg = fmt(tr('my_codes.bulk_delete_confirm', 'Delete {n} selected items?'), {n: keys.length});

  {
    const ok2 = (window.LS && typeof window.LS.confirm === 'function')
      ? await window.LS.confirm(msg, {title: tr('common.confirm', 'Confirm'), danger: true})
      : (typeof window.uiConfirm === 'function' ? await window.uiConfirm({title: tr('common.confirm', 'Confirm'), message: msg, danger: true}) : false);
    if(!ok2) return;
  }

  let ok = 0;
  let fail = 0;

  for(const k of keys){
    const l = getLockByKey(k);
    if(!l) continue;
    const did = await delLock(l.kind, l.id, {skipConfirm:true, silent:true, skipReload:true});
    if(did) ok++;
    else fail++;
  }

  locksSelected.clear();
  setBulkMode(false);
  await loadLocks(true);

  if(fail){
    toast(fmt(tr('my_codes.bulk_delete_done_partial', 'Deleted {ok}/{n}. {fail} failed.'), {ok, n: keys.length, fail}), 'warn');
  }else{
    toast(fmt(tr('my_codes.bulk_delete_done', 'Deleted {n}.'), {n: ok}), 'ok');
  }
}

function matchesFilterFor(filter, l){
  if(filter === 'wallet') return l.kind === 'wallet';
  if(filter === 'ready') return String(l.display_status||'') === 'unlocked';
  if(filter === 'sealed'){
    const st = String(l.display_status||'');
    return (st === 'locked' || st === 'pending' || st === 'auto_saved');
  }
  if(filter === 'starred') return isStarredLock(l);
  return true;
}

function matchesFilter(l){
  return matchesFilterFor(locksFilter, l);
}

function matchesQuery(l){
  const q = String(locksQuery||'').trim().toLowerCase();
  if(!q) return true;
  const label = String(l.label||'').toLowerCase();
  return label.indexOf(q) !== -1;
}

function matchesSoon(l){
  const v = String(locksSoon||'all');
  if(v === 'all') return true;

  const d = parseUtc(l.reveal_date);
  if(!d || isNaN(d.getTime())) return false;

  const remainingMs = d.getTime() - Date.now();
  if(remainingMs <= 0) return false;

  const limMs = (v === '24h') ? 86400000 : (v === '7d' ? 7*86400000 : 0);
  if(!limMs) return true;
  return remainingMs <= limMs;
}

function sortLocks(list){
  const s = String(locksSort||'created_desc');
  const arr = Array.isArray(list) ? list.slice() : [];

  if(s === 'label_asc'){
    arr.sort((a,b)=>String(a.label||'').localeCompare(String(b.label||''), undefined, {sensitivity:'base'}));
    return arr;
  }

  if(s === 'reveal_asc'){
    arr.sort((a,b)=>{
      const da = parseUtc(a.reveal_date || '')
      const db = parseUtc(b.reveal_date || '')
      const ta = (da && !isNaN(da.getTime())) ? da.getTime() : Number.POSITIVE_INFINITY;
      const tb = (db && !isNaN(db.getTime())) ? db.getTime() : Number.POSITIVE_INFINITY;
      if(ta !== tb) return ta - tb;

      const ca = parseUtc(a.created_at || '')
      const cb = parseUtc(b.created_at || '')
      const tca = (ca && !isNaN(ca.getTime())) ? ca.getTime() : 0;
      const tcb = (cb && !isNaN(cb.getTime())) ? cb.getTime() : 0;
      return tcb - tca;
    });
    return arr;
  }

  // created_desc (default)
  arr.sort((a,b)=>{
    const da = parseUtc(a.created_at || a.reveal_date || '')
    const db = parseUtc(b.created_at || b.reveal_date || '')
    const ta = (da && !isNaN(da.getTime())) ? da.getTime() : 0;
    const tb = (db && !isNaN(db.getTime())) ? db.getTime() : 0;
    return tb - ta;
  });
  return arr;
}

function updateLocksSegCounts(){
  const seg = document.getElementById('locks-seg');
  if(!seg) return;

  const src = allLocksSession || [];

  const allowedFilters = ['all','sealed','ready','wallet','starred'];

  const counts = {
    all: src.filter(l => matchesQuery(l) && matchesSoon(l)).length,
    sealed: src.filter(l => matchesQuery(l) && matchesSoon(l) && matchesFilterFor('sealed', l)).length,
    ready: src.filter(l => matchesQuery(l) && matchesSoon(l) && matchesFilterFor('ready', l)).length,
    wallet: src.filter(l => matchesQuery(l) && matchesSoon(l) && matchesFilterFor('wallet', l)).length,
    starred: src.filter(l => matchesQuery(l) && matchesSoon(l) && matchesFilterFor('starred', l)).length,
  };

  seg.querySelectorAll('button[data-filter]').forEach(b => {
    const f0 = b.getAttribute('data-filter') || 'all';
    const f = allowedFilters.includes(f0) ? f0 : 'all';

    if(!b.getAttribute('data-label')){
      const raw = String(b.textContent||'').trim();
      const base0 = raw.replace(/\s*\(\d+\)\s*$/, '').trim();
      b.setAttribute('data-label', base0);
    }

    const base = b.getAttribute('data-label') || '';
    const n = (typeof counts[f] === 'number') ? counts[f] : counts.all;
    b.textContent = `${base} (${n})`;
  });
}

function initLocksToolbar(){
  const seg = document.getElementById('locks-seg');
  if(seg && !seg.getAttribute('data-init')){
    seg.setAttribute('data-init','1');
    seg.addEventListener('click', (e)=>{
      const b = e.target && e.target.closest ? e.target.closest('button[data-filter]') : null;
      if(!b) return;
      setLocksFilter(b.getAttribute('data-filter') || 'all');
    });
  }

  const search = document.getElementById('locks-search');
  if(search && !search.getAttribute('data-init')){
    search.setAttribute('data-init','1');
    search.addEventListener('input', ()=>{
      locksQuery = String(search.value || '');
      persistLocksToolbarState();
      renderLocks();
    });
  }

  const sortSel = document.getElementById('locks-sort');
  if(sortSel && !sortSel.getAttribute('data-init')){
    sortSel.setAttribute('data-init','1');
    sortSel.value = locksSort;
    sortSel.addEventListener('change', ()=>{
      locksSort = String(sortSel.value || 'created_desc');
      persistLocksToolbarState();
      renderLocks();
    });
  }

  const soonSel = document.getElementById('locks-soon');
  if(soonSel && !soonSel.getAttribute('data-init')){
    soonSel.setAttribute('data-init','1');
    soonSel.value = locksSoon;
    soonSel.addEventListener('change', ()=>{
      locksSoon = String(soonSel.value || 'all');
      persistLocksToolbarState();
      updateLocksSegCounts();
      renderLocks();
    });
  }

  const exportDd = document.getElementById('locks-export-dd');
  if(exportDd && !exportDd.getAttribute('data-init')){
    exportDd.setAttribute('data-init','1');
    exportDd.addEventListener('click', (e)=>{
      const b = e.target && e.target.closest ? e.target.closest('button[data-export][data-format]') : null;
      if(!b) return;
      e.preventDefault();
      exportLocks(b.getAttribute('data-export'), b.getAttribute('data-format'));
      exportDd.removeAttribute('open');
    });
  }

  const bulkToggle = document.getElementById('locks-bulk-toggle');
  if(bulkToggle && !bulkToggle.getAttribute('data-init')){
    bulkToggle.setAttribute('data-init','1');
    bulkToggle.setAttribute('aria-pressed', locksBulkMode ? 'true' : 'false');
    bulkToggle.addEventListener('click', ()=>setBulkMode(!locksBulkMode));
  }

  const bulkClear = document.getElementById('locks-bulk-clear');
  if(bulkClear && !bulkClear.getAttribute('data-init')){
    bulkClear.setAttribute('data-init','1');
    bulkClear.addEventListener('click', ()=>{
      locksSelected.clear();
      updateBulkUi();
      renderLocks();
    });
  }

  const bulkExport = document.getElementById('locks-bulk-export');
  if(bulkExport && !bulkExport.getAttribute('data-init')){
    bulkExport.setAttribute('data-init','1');
    bulkExport.addEventListener('click', ()=>{
      // Bulk export supports both JSON and CSV via the Export dropdown.
      const dd = document.getElementById('locks-export-dd');
      if(dd){
        dd.setAttribute('open','');
        try{ dd.scrollIntoView({block:'nearest'}); }catch{}
      }else{
        exportLocks('selected', 'json');
      }
    });
  }

  const bulkDelete = document.getElementById('locks-bulk-delete');
  if(bulkDelete && !bulkDelete.getAttribute('data-init')){
    bulkDelete.setAttribute('data-init','1');
    bulkDelete.addEventListener('click', bulkDeleteSelected);
  }
}

function b64ToBytes(b64){return Uint8Array.from(atob(b64), c => c.charCodeAt(0));}
function bytesToB64(bytes){return btoa(String.fromCharCode(...bytes));}

function requireWebCrypto(){
  if (!window.crypto || !window.crypto.getRandomValues) {
    throw new Error('Secure cryptography is unavailable in this browser.');
  }
  if (!window.isSecureContext || !window.crypto.subtle) {
    throw new Error('Web Crypto API is unavailable. Use HTTPS (or localhost) to use the vault.');
  }
  return window.crypto;
}

async function deriveKey(passphrase, kdfSaltB64, iters){
  const c = requireWebCrypto();
  const enc = new TextEncoder();
  const baseKey = await c.subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  const saltBytes = b64ToBytes(kdfSaltB64);
  return c.subtle.deriveKey(
    {name:'PBKDF2', salt:saltBytes, iterations: iters, hash:'SHA-256'},
    baseKey,
    {name:'AES-GCM', length:256},
    false,
    ['encrypt','decrypt']
  );
}

async function aesEncrypt(plain, key){
  const c = requireWebCrypto();
  const iv = new Uint8Array(12);
  c.getRandomValues(iv);
  const enc = new TextEncoder();
  const ct = new Uint8Array(await c.subtle.encrypt({name:'AES-GCM', iv, tagLength:128}, key, enc.encode(plain)));
  const tag = ct.slice(ct.length - 16);
  const cipher = ct.slice(0, ct.length - 16);
  return {cipher_blob: bytesToB64(cipher), iv: bytesToB64(iv), auth_tag: bytesToB64(tag)};
}

async function aesDecrypt(cipherBlobB64, ivB64, tagB64, key){
  const c = requireWebCrypto();
  const cipher = b64ToBytes(cipherBlobB64);
  const iv = b64ToBytes(ivB64);
  const tag = b64ToBytes(tagB64);
  const data = new Uint8Array(cipher.length + tag.length);
  data.set(cipher, 0);
  data.set(tag, cipher.length);
  const pt = await c.subtle.decrypt({name:'AES-GCM', iv, tagLength:128}, key, data);
  return new TextDecoder().decode(pt);
}

function startCountdownTicker(){
  if(countdownTimer) clearInterval(countdownTimer);

  function tick(){
    let shouldRefresh = false;

    document.querySelectorAll('[data-countdown-until]')
      .forEach(el => {
        const until = parseInt(el.getAttribute('data-countdown-until')||'0', 10) || 0;
        if(!until) return;

        const now = Date.now();
        const remainingMs = until - now;
        const seconds = Math.max(0, Math.floor(remainingMs / 1000));

        const totalAttr = parseInt(el.getAttribute('data-countdown-total')||'0', 10) || 0;
        const totalMs = totalAttr > 0 ? totalAttr : Math.max(1, until - now);
        if(!totalAttr) el.setAttribute('data-countdown-total', String(totalMs));

        const nextText = seconds > 0
          ? fmt(tr('share.countdown_reveals_in', '⏱ Reveals in {delta}'), {delta: fmtCountdown(seconds)})
          : tr('share.countdown_eligible', '⏱ Reveal eligible');
        const txtEl = el.querySelector('.cd-txt') || el;
        if(txtEl.textContent !== nextText){
          txtEl.textContent = nextText;
          if(!reduceMotion){
            txtEl.classList.remove('tick');
            void txtEl.offsetWidth;
            txtEl.classList.add('tick');
          }
        }

        const clampedRemaining = Math.max(0, remainingMs);
        const p = totalMs > 0 ? Math.max(0, Math.min(1, 1 - (clampedRemaining / totalMs))) : 1;
        el.style.setProperty('--p', String(p));

        const urg = (seconds <= 0) ? 0 : (seconds <= 10 ? 3 : (seconds <= 60 ? 2 : 1));
        el.setAttribute('data-urgency', String(urg));

        if(seconds <= 0 && el.getAttribute('data-hit-zero') !== '1'){
          el.setAttribute('data-hit-zero', '1');
          const card = el.closest ? el.closest('.lock-card') : null;
          if(card && card.classList.contains('st-locked')) shouldRefresh = true;
        }
      });

    if(shouldRefresh){
      if(countdownRefreshTimer) clearTimeout(countdownRefreshTimer);
      countdownRefreshTimer = setTimeout(()=>{ countdownRefreshTimer = null; loadLocks(); }, 1200);
    }
  }

  tick();
  countdownTimer = setInterval(tick, 1000);
}

async function loadLocks(force=false){
  if(countdownRefreshTimer){
    clearTimeout(countdownRefreshTimer);
    countdownRefreshTimer = null;
  }

  initLocksToolbar();

  const wrap = document.getElementById('locks-wrap');
  if(!wrap) return;

  if(force) allLocksSession = [];

  locksLoading = true;
  locksOffline = false;
  locksLastError = null;
  renderLocks();

  try{
    let prevCache = null;
    try{ prevCache = JSON.parse(lsGet('ls_my_codes_cache') || 'null'); }catch{}

    const [a,b] = await Promise.allSettled([
      get('api/locks.php'),
      get('api/wallet_locks.php'),
    ]);

    const locksOk  = (a.status==='fulfilled' && a.value && a.value.success);
    const walletOk = (b.status==='fulfilled' && b.value && b.value.success);

    const locks = locksOk ? (a.value.locks||[]) : [];
    const walletLocks = walletOk ? (b.value.wallet_locks||[]) : [];

    const locksErr = (a.status === 'rejected')
      ? ((a.reason && a.reason.message) ? a.reason.message : 'Failed to load locks')
      : ((!locksOk && a.value && a.value.error) ? String(a.value.error) : null);

    const walletErr = (b.status === 'rejected')
      ? ((b.reason && b.reason.message) ? b.reason.message : 'Failed to load wallet locks')
      : ((!walletOk && b.value && b.value.error) ? String(b.value.error) : null);

    // Wallet locks are an optional module. Only surface wallet-load errors if:
    // - locks failed (already error), OR
    // - user is filtering to wallet, OR
    // - user previously had cached wallet locks that now can't be refreshed.
    if(!locksOk){
      const parts = [];
      if(locksErr) parts.push(locksErr);
      if(!walletOk && walletErr) parts.push(walletErr);
      locksLastError = parts.length ? parts.join(' · ') : 'Failed to load.';
    }else if(!walletOk){
      const hadWalletCached = !!(prevCache && Array.isArray(prevCache.wallet_locks) && prevCache.wallet_locks.length);
      const wantsWallet = (locksFilter === 'wallet');
      locksLastError = (hadWalletCached || wantsWallet) ? (walletErr || 'Failed to load wallet locks') : null;
    }

    // Update cache, preserving the previous list for whichever endpoint failed.
    if(locksOk || walletOk){
      try{
        const prev = (prevCache && typeof prevCache === 'object') ? prevCache : {};
        lsSet('ls_my_codes_cache', JSON.stringify({
          ts: Date.now(),
          locks: locksOk ? locks : (prev.locks || []),
          wallet_locks: walletOk ? walletLocks : (prev.wallet_locks || []),
        }));
      }catch{}
    }

    if(!locksOk && !walletOk){
      throw new Error(locksLastError || 'Failed to load');
    }

    const mapped = [];

    locks.forEach(l => mapped.push(Object.assign({kind:'lock'}, l)));

    walletLocks.forEach(w => {
      const stRaw = String(w.display_status||'');
      const st = (stRaw === 'setup_pending') ? 'pending'
              : (stRaw === 'setup_failed') ? 'rejected'
              : (stRaw === 'inactive') ? 'rejected'
              : stRaw;

      mapped.push({
        kind: 'wallet',
        id: w.id,
        label: w.label || (w.carrier_name ? (w.carrier_name + ' wallet PIN') : 'Wallet PIN'),
        hint: null,
        password_type: w.carrier_pin_type || 'numeric',
        password_length: parseInt(w.carrier_pin_length||'4',10) || 4,
        reveal_date: w.unlock_at,
        unlock_at: w.unlock_at,
        created_at: w.created_at,
        copied_at: null,
        revealed_at: w.revealed_at,
        display_status: st,
        time_remaining: w.time_remaining || null,
        carrier_name: w.carrier_name || '',
        setup_status: w.setup_status || null,
        setup_confirmed_at: w.setup_confirmed_at || null,
        setup_failed_at: w.setup_failed_at || null,
      });
    });

    mapped.sort((x,y) => {
      const dx = parseUtc(x.created_at || x.reveal_date || '');
      const dy = parseUtc(y.created_at || y.reveal_date || '');
      const ax = (dx && !isNaN(dx.getTime())) ? dx.getTime() : 0;
      const ay = (dy && !isNaN(dy.getTime())) ? dy.getTime() : 0;
      return ay - ax;
    });

    allLocksSession = mapped;

  }catch(e){
    let usedCache = false;

    try{
      const cached = JSON.parse(lsGet('ls_my_codes_cache') || 'null');
      const locks = cached && cached.locks ? cached.locks : [];
      const walletLocks = cached && cached.wallet_locks ? cached.wallet_locks : [];

      const mapped = [];
      locks.forEach(l => mapped.push(Object.assign({kind:'lock'}, l)));
      walletLocks.forEach(w => {
        const stRaw = String(w.display_status||'');
        const st = (stRaw === 'setup_pending') ? 'pending'
                : (stRaw === 'setup_failed') ? 'rejected'
                : (stRaw === 'inactive') ? 'rejected'
                : stRaw;

        mapped.push({
          kind: 'wallet',
          id: w.id,
          label: w.label || (w.carrier_name ? (w.carrier_name + ' wallet PIN') : 'Wallet PIN'),
          hint: null,
          password_type: w.carrier_pin_type || 'numeric',
          password_length: parseInt(w.carrier_pin_length||'4',10) || 4,
          reveal_date: w.unlock_at,
          unlock_at: w.unlock_at,
          created_at: w.created_at,
          copied_at: null,
          revealed_at: w.revealed_at,
          display_status: st,
          time_remaining: w.time_remaining || null,
          carrier_name: w.carrier_name || '',
          setup_status: w.setup_status || null,
          setup_confirmed_at: w.setup_confirmed_at || null,
          setup_failed_at: w.setup_failed_at || null,
        });
      });

      mapped.sort((x,y) => {
        const dx = parseUtc(x.created_at || x.reveal_date || '');
        const dy = parseUtc(y.created_at || y.reveal_date || '');
        const ax = (dx && !isNaN(dx.getTime())) ? dx.getTime() : 0;
        const ay = (dy && !isNaN(dy.getTime())) ? dy.getTime() : 0;
        return ay - ax;
      });

      if(mapped.length){
        allLocksSession = mapped;
        locksOffline = true;
        locksLastError = null;
        usedCache = true;
      }
    }catch{}

    if(!usedCache){
      locksOffline = false;
      allLocksSession = [];
      locksLastError = (e && e.message) ? e.message : 'Failed to load.';
    }

  }finally{
    locksLoading = false;
    renderLocks();
  }
}

function addUtcMonths(d, months){
  const x = new Date(d.getTime());
  x.setUTCMonth(x.getUTCMonth() + (parseInt(months||'0',10)||0));
  return x;
}

function fmtLocalDate(d){
  if(!d || isNaN(d.getTime())) return '';
  if(window.LS && typeof LS.fmtLocal === 'function') return LS.fmtLocal(d);
  return d.toLocaleString();
}

function getDeleteEligibility(lock){
  if(!lock) return {disabled:false, reason:''};

  const kind = String(lock.kind || 'lock');
  const protectedStatus = (kind === 'lock')
    ? (String(lock.confirmation_status||'') === 'confirmed')
    : (kind === 'wallet' && String(lock.setup_status||'') === 'active');

  if(!protectedStatus) return {disabled:false, reason:''};

  if(!lock.revealed_at){
    return {
      disabled: true,
      reason: tr('my_codes.delete_disabled_until_revealed', 'Delete is available after this code is revealed at least once.'),
    };
  }

  const revealedAt = parseUtc(lock.revealed_at);
  if(!revealedAt || isNaN(revealedAt.getTime())) return {disabled:false, reason:''};

  const earliest = addUtcMonths(revealedAt, 1);
  const remainingSeconds = Math.ceil((earliest.getTime() - Date.now()) / 1000);

  if(remainingSeconds > 0){
    return {
      disabled: true,
      reason: fmt(
        tr('my_codes.delete_disabled_too_soon_fmt', 'Delete available {ts} (in {delta}).'),
        {ts: fmtLocalDate(earliest), delta: fmtCountdown(remainingSeconds)}
      ),
    };
  }

  return {disabled:false, reason:''};
}

function icsEscape(s){
  return String(s||'')
    .replace(/\\/g, '\\\\')
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '')
    .replace(/,/g, '\\,')
    .replace(/;/g, '\\;');
}

function fmtIcsUtc(d){
  const pad = (n)=>String(n).padStart(2,'0');
  return `${d.getUTCFullYear()}${pad(d.getUTCMonth()+1)}${pad(d.getUTCDate())}T${pad(d.getUTCHours())}${pad(d.getUTCMinutes())}${pad(d.getUTCSeconds())}Z`;
}

function safeFilename(s){
  return String(s||'')
    .toLowerCase()
    .replace(/[^a-z0-9\-_.]+/g,'_')
    .replace(/_+/g,'_')
    .replace(/^_+|_+$/g,'')
    .slice(0, 48) || 'time_lock';
}

function downloadLockIcs(lock){
  const d = parseUtc(lock && lock.reveal_date);
  if(!d || isNaN(d.getTime())) return;

  const uid = `${String(lock.kind||'lock')}-${String(lock.id||'')}`.replace(/[^A-Za-z0-9-]/g,'') + '@' + String(location.host||'localhost');
  const dtstamp = fmtIcsUtc(new Date());
  const dtstart = fmtIcsUtc(d);

  const summary = fmt(tr('my_codes.calendar_summary_fmt', 'Unlock: {label}'), {label: String(lock.label || tr('my_codes.reveal_title_default','Reveal'))});

  const lines = [
    'BEGIN:VCALENDAR',
    'VERSION:2.0',
    'PRODID:-//Locksmith//TimeLocks//EN',
    'CALSCALE:GREGORIAN',
    'METHOD:PUBLISH',
    'BEGIN:VEVENT',
    `UID:${icsEscape(uid)}`,
    `DTSTAMP:${dtstamp}`,
    `DTSTART:${dtstart}`,
    `SUMMARY:${icsEscape(summary)}`,
    `DESCRIPTION:${icsEscape(tr('my_codes.calendar_desc', 'Your time lock becomes eligible to reveal.'))}`,
    'END:VEVENT',
    'END:VCALENDAR',
  ];

  downloadText(`${safeFilename(lock.label || 'time_lock')}.ics`, lines.join('\r\n') + '\r\n', 'text/calendar');
}

function buildCard(lock, opts={}){
  const el=document.createElement('div');
  const st=lock.display_status;
  el.className=`lock-card st-${st}`;

  const k = lockKey(lock.kind, lock.id);
  el.setAttribute('data-key', k);

  const offline = !!(opts && opts.offline);

  if(locksBulkMode){
    const sel=document.createElement('button');
    sel.className='lc-select';
    sel.type='button';
    sel.setAttribute('data-key', k);
    sel.setAttribute('aria-label', tr('my_codes.bulk_select_one', 'Select'));
    sel.textContent = locksSelected.has(k) ? '☑' : '☐';
    sel.setAttribute('aria-pressed', locksSelected.has(k) ? 'true' : 'false');
    sel.addEventListener('click', (e)=>{ e.stopPropagation(); toggleBulkSelection(k); });
    el.appendChild(sel);

    if(locksSelected.has(k)) el.classList.add('bulk-selected');

    el.addEventListener('click', (e)=>{
      if(!locksBulkMode) return;
      const inBtn = e.target && e.target.closest ? e.target.closest('button') : null;
      if(inBtn) return;
      toggleBulkSelection(k);
    });
  }

  try{
    if(lock && lock.id && String(lock.id).length === 36){
      if(lock.kind === 'lock') el.id = 'lock-' + String(lock.id);
      else if(lock.kind === 'wallet') el.id = 'wallet-' + String(lock.id);
    }
  }catch{}

  const badges={locked:'🔒 Locked',unlocked:'🔓 Unlocked',pending:'⏳ Pending',auto_saved:'💾 Auto-saved',rejected:'✗ Void'};

  const revealD = parseUtc(lock.reveal_date);
  const localStr = fmtLocalTs(lock.reveal_date);
  const utcStr = fmtUtcTs(lock.reveal_date);

  const top=document.createElement('div');
  top.className='lc-top';

  const labelWrap=document.createElement('div');
  labelWrap.className='lc-label-wrap';

  const label=document.createElement('div');
  label.className='lc-label';
  label.textContent=lock.label || '';

  const star=document.createElement('button');
  star.className='lc-star';
  star.type='button';
  const starred = isStarredLock(lock);
  star.textContent = starred ? '★' : '☆';
  star.title = starred ? tr('my_codes.unstar', 'Unstar') : tr('my_codes.star', 'Star');
  star.setAttribute('aria-pressed', starred ? 'true' : 'false');
  if(locksBulkMode){
    star.disabled = true;
    star.style.opacity = '.35';
  }else{
    star.addEventListener('click', (e)=>{ e.stopPropagation(); toggleStarFor(lock); });
  }

  labelWrap.appendChild(label);
  labelWrap.appendChild(star);

  const badge=document.createElement('div');
  badge.className=`lc-badge ${st}`;
  badge.textContent=badges[st]||st;

  top.appendChild(labelWrap);
  top.appendChild(badge);
  el.appendChild(top);

  if(lock.hint){
    const hint=document.createElement('div');
    hint.className='lc-hint';
    hint.textContent=`"${lock.hint}"`;
    el.appendChild(hint);
  }

  if(st==='auto_saved'){
    const note=document.createElement('div');
    note.className='lc-autosave-note';
    note.textContent=tr('my_codes.autosave_note', 'ℹ Auto-saved without confirmation. Tap "Activate" to enforce reveal date.');
    el.appendChild(note);
  }

  if((st==='locked' || st==='unlocked') && revealD && !isNaN(revealD.getTime())){
    const cd=document.createElement('div');
    cd.className='lc-countdown';

    const untilMs = revealD.getTime();
    cd.setAttribute('data-countdown-until', String(untilMs));
    cd.setAttribute('data-countdown-total', String(Math.max(1, untilMs - Date.now())));

    const txt=document.createElement('span');
    txt.className='cd-txt';
    txt.textContent='⏱';

    const bar=document.createElement('div');
    bar.className='cd-bar';

    cd.appendChild(txt);
    cd.appendChild(bar);
    el.appendChild(cd);
  }

  const meta=document.createElement('div');
  meta.className='lc-meta';

  const whenHtml = `<span>${esc(localStr)}</span> <span class="utc-pill" title="Stored & enforced in UTC">${esc(utcStr)}</span>`;

  if(lock.kind === 'wallet'){
    const revealed = lock.revealed_at ? '<span style="color:var(--green)">✓</span>' : '<span style="color:var(--muted)">—</span>';
    meta.innerHTML=`Type: <span>Wallet PIN · ${esc(lock.password_length)} chars</span><br>Carrier: <span>${esc(lock.carrier_name||'')}</span><br>Unlock: ${whenHtml}<br>Revealed: ${revealed}`;
  } else {
    const copied = lock.copied_at ? '<span style="color:var(--green)">✓</span>' : '<span style="color:var(--red)">not copied</span>';
    meta.innerHTML=`Type: <span>${esc(lock.password_type)} · ${esc(lock.password_length)} chars</span><br>Reveal: ${whenHtml}<br>Copied: ${copied}`;
  }

  el.appendChild(meta);

  const details=document.createElement('details');
  details.className='lc-details';

  const detSum=document.createElement('summary');
  detSum.textContent = tr('my_codes.details_summary', 'Details');
  details.appendChild(detSum);

  const detGrid=document.createElement('div');
  detGrid.className='lc-details-grid';

  function addDetailRow(kTxt, vNodes){
    const row=document.createElement('div');
    row.className='lc-drow';

    const kEl=document.createElement('div');
    kEl.className='lc-dk';
    kEl.textContent = kTxt;

    const vEl=document.createElement('div');
    vEl.className='lc-dv';

    if(Array.isArray(vNodes) && vNodes.length){
      vNodes.forEach(n => vEl.appendChild(n));
    }else{
      const dash=document.createElement('span');
      dash.style.color='var(--muted)';
      dash.textContent='—';
      vEl.appendChild(dash);
    }

    row.appendChild(kEl);
    row.appendChild(vEl);
    detGrid.appendChild(row);
  }

  function tsNodes(ts){
    if(!ts) return null;
    const local = fmtLocalTs(ts);
    const utc = fmtUtcTs(ts);
    if(!local && !utc) return null;

    const a=document.createElement('span');
    a.textContent = local || utc;

    if(utc){
      const b=document.createElement('span');
      b.className='utc-pill';
      b.title='UTC';
      b.textContent = utc;
      return [a, document.createTextNode(' '), b];
    }

    return [a];
  }

  addDetailRow(tr('my_codes.details_created_at', 'Created'), tsNodes(lock.created_at));

  if(lock.kind === 'wallet'){
    addDetailRow(tr('my_codes.details_unlock_at', 'Unlock'), tsNodes(lock.reveal_date || lock.unlock_at));
    addDetailRow(tr('my_codes.details_setup_status', 'Setup'), [document.createTextNode(String(lock.setup_status || '—'))]);
    addDetailRow(tr('my_codes.details_setup_confirmed_at', 'Setup confirmed'), tsNodes(lock.setup_confirmed_at));
    addDetailRow(tr('my_codes.details_setup_failed_at', 'Setup failed'), tsNodes(lock.setup_failed_at));
    addDetailRow(tr('my_codes.details_revealed_at', 'Revealed'), tsNodes(lock.revealed_at));
  } else {
    addDetailRow(tr('my_codes.details_reveal_date', 'Reveal'), tsNodes(lock.reveal_date));
    addDetailRow(tr('my_codes.details_copied_at', 'Copied'), tsNodes(lock.copied_at));
    addDetailRow(tr('my_codes.details_confirmed_at', 'Confirmed'), tsNodes(lock.confirmed_at));
    addDetailRow(tr('my_codes.details_rejected_at', 'Voided'), tsNodes(lock.rejected_at));
    addDetailRow(tr('my_codes.details_auto_saved_at', 'Auto-saved'), tsNodes(lock.auto_saved_at));
    addDetailRow(tr('my_codes.details_revealed_at', 'Revealed'), tsNodes(lock.revealed_at));
  }

  details.appendChild(detGrid);
  el.appendChild(details);

  const actions=document.createElement('div');
  actions.className='lc-actions';

  if(st==='unlocked'){
    const b=document.createElement('button');
    b.className='btn btn-green btn-sm';
    b.type='button';
    b.textContent='Reveal';
    if(offline){
      b.disabled = true;
      b.style.opacity = '.45';
      b.textContent = 'Reveal (offline)';
    }else{
      b.addEventListener('click', ()=>openReveal(lock.kind, lock.id, lock.label||'Reveal', lock.hint||''));
    }
    actions.appendChild(b);

    if(lock.kind === 'lock'){
      const s=document.createElement('button');
      s.className='btn btn-ghost btn-sm';
      s.type='button';
      s.textContent='Share';
      if(offline){
        s.disabled = true;
        s.style.opacity = '.45';
      }else{
        s.addEventListener('click', ()=>{
          shareAfterReveal = true;
          openReveal(lock.kind, lock.id, lock.label||'Reveal', lock.hint||'');
        });
      }
      actions.appendChild(s);
    }
  } else if(st==='pending'){
    if(lock.kind === 'lock'){
      const c=document.createElement('button');
      c.className='btn btn-green btn-sm';
      c.type='button';
      c.textContent = tr('my_codes.action_confirm', 'Confirm');
      if(offline){
        c.disabled = true;
        c.style.opacity = '.45';
      }else{
        c.addEventListener('click', ()=>runLockAction(lock.id, 'confirm'));
      }
      actions.appendChild(c);

      const v=document.createElement('button');
      v.className='btn btn-red btn-sm';
      v.type='button';
      v.textContent = tr('my_codes.action_void', 'Void');
      if(offline){
        v.disabled = true;
        v.style.opacity = '.45';
      }else{
        v.addEventListener('click', ()=>runLockAction(lock.id, 'reject'));
      }
      actions.appendChild(v);

      const a=document.createElement('button');
      a.className='btn btn-ghost btn-sm';
      a.type='button';
      a.textContent = tr('my_codes.action_auto_save', 'Auto-save');
      if(offline){
        a.disabled = true;
        a.style.opacity = '.45';
      }else{
        a.addEventListener('click', ()=>runLockAction(lock.id, 'auto_save'));
      }
      actions.appendChild(a);
    }
  } else if(st==='auto_saved'){
    const b=document.createElement('button');
    b.className='btn btn-sm btn-activate';
    b.type='button';
    b.textContent = tr('my_codes.action_activate', 'Activate');
    if(offline){
      b.disabled = true;
      b.style.opacity = '.45';
      b.style.cursor = 'not-allowed';
    }else{
      b.addEventListener('click', ()=>runLockAction(lock.id, 'confirm'));
    }
    actions.appendChild(b);

    const v=document.createElement('button');
    v.className='btn btn-red btn-sm';
    v.type='button';
    v.textContent = tr('my_codes.action_void', 'Void');
    if(offline){
      v.disabled = true;
      v.style.opacity = '.45';
    }else{
      v.addEventListener('click', ()=>runLockAction(lock.id, 'reject'));
    }
    actions.appendChild(v);

  } else if(st==='locked'){
    const b=document.createElement('button');
    b.className='btn btn-ghost btn-sm';
    b.type='button';
    b.disabled=true;
    b.style.opacity='.3';
    b.style.cursor='not-allowed';
    b.textContent=`${tr('my_codes.sealed_until', 'Sealed until')} ${localStr}`;
    b.title=`UTC: ${utcStr}`;
    actions.appendChild(b);

    if(lock.kind === 'lock'){
      const s=document.createElement('button');
      s.className='btn btn-ghost btn-sm';
      s.type='button';
      s.textContent='Share';
      if(offline){
        s.disabled = true;
        s.style.opacity = '.45';
        s.title = 'Offline';
      }else{
        s.addEventListener('click', ()=>openShare(lock));
        s.title = 'Create a share link (requires vault passphrase; legacy: paste saved code)';
      }
      actions.appendChild(s);
    }
  }

  if(revealD && !isNaN(revealD.getTime()) && revealD.getTime() > Date.now()){
    const cal=document.createElement('button');
    cal.className='btn btn-ghost btn-sm btn-calendar';
    cal.type='button';
    cal.textContent = tr('my_codes.add_to_calendar', 'Add to calendar');
    cal.addEventListener('click', ()=>downloadLockIcs(lock));
    actions.appendChild(cal);
  }

  const delInfo = getDeleteEligibility(lock);

  const del=document.createElement('button');
  del.className='btn btn-red btn-sm';
  del.type='button';
  del.textContent='Delete';
  if(offline){
    del.disabled = true;
    del.style.opacity = '.45';
    del.textContent = 'Delete (offline)';
  }else if(delInfo && delInfo.disabled){
    del.disabled = true;
    del.style.opacity = '.45';
    del.style.cursor = 'not-allowed';
    del.title = String(delInfo.reason || '');
  }else{
    del.addEventListener('click', ()=>delLock(lock.kind, lock.id));
  }
  actions.appendChild(del);

  if(locksBulkMode){
    actions.querySelectorAll('button').forEach(b => {
      b.disabled = true;
      b.style.opacity = '.35';
      b.style.cursor = 'not-allowed';
    });
  }

  el.appendChild(actions);
  return el;
}

function setBtnState(btn, icoEl, txtEl, state, ico, txt){
  if(!btn) return;
  if(state) btn.setAttribute('data-state', state);
  else btn.removeAttribute('data-state');
  if(icoEl) icoEl.textContent = ico || '';
  if(txtEl) txtEl.textContent = txt || '';
}

function showRv(el){
  if(!el) return;
  el.style.display='block';
  if(!reduceMotion){
    el.classList.remove('rv-in');
    void el.offsetWidth;
    el.classList.add('rv-in');
  }
}

function hideRv(el){
  if(!el) return;
  el.style.display='none';
  el.classList.remove('rv-in');
}

function setRevealSheetState(state){
  const sheet = document.querySelector('#reveal-overlay .reveal-sheet');
  if(!sheet) return;
  if(state) sheet.setAttribute('data-state', state);
  else sheet.removeAttribute('data-state');
}

function setRevealClipboardCountdownText(text){
  const el = document.getElementById('rv-clip-countdown');
  if(!el) return;
  if(!text){
    el.style.display = 'none';
    el.textContent = '';
    return;
  }
  el.textContent = String(text || '');
  el.style.display = 'block';
}

function resetRevealCopyBtn(){
  const btn = document.getElementById('rv-copy-btn');
  const txt = btn ? btn.querySelector('.btn-txt') : null;
  if(txt) txt.textContent = tr('share.btn_copy', 'Copy');
  setRevealClipboardCountdownText('');
}

function clearRevealClipboardCountdown(){
  if(revealClipboardCountdownTimer){
    clearInterval(revealClipboardCountdownTimer);
    revealClipboardCountdownTimer = null;
  }
  resetRevealCopyBtn();
}

function clearRevealTimers(){
  if(revealAutoHideTimer){
    clearTimeout(revealAutoHideTimer);
    revealAutoHideTimer = null;
  }
  revealPlainHidden = false;
  hideRv(document.getElementById('rv-show-btn'));
  clearRevealClipboardCountdown();
}

function scheduleRevealAutoHide(totalSeconds){
  if(revealAutoHideTimer) clearTimeout(revealAutoHideTimer);

  const s = Math.max(1, parseInt(totalSeconds||'0', 10) || 0);
  revealAutoHideTimer = setTimeout(()=>{
    const overlay = document.getElementById('reveal-overlay');
    if(!(overlay && overlay.classList.contains('show'))) return;
    if(!revealedPwd) return;

    const pwdEl = document.getElementById('rv-pwd');
    if(pwdEl){
      pwdEl.textContent = '';
      hideRv(pwdEl);
    }

    revealPlainHidden = true;
    showRv(document.getElementById('rv-show-btn'));
  }, s * 1000);
}

function showRevealedAgain(){
  if(!revealedPwd || !currentReveal || !currentReveal.id) return;

  const pwdEl = document.getElementById('rv-pwd');
  if(pwdEl){
    pwdEl.textContent = String(revealedPwd || '');
    showRv(pwdEl);
  }

  revealPlainHidden = false;
  hideRv(document.getElementById('rv-show-btn'));
  scheduleRevealAutoHide(30);
}

function startRevealClipboardCountdown(totalSeconds){
  clearRevealClipboardCountdown();

  let left = Math.max(0, parseInt(totalSeconds||'0', 10) || 0);
  if(left <= 0) return;

  const btn = document.getElementById('rv-copy-btn');
  const txt = btn ? btn.querySelector('.btn-txt') : null;
  if(txt) txt.textContent = tr('my_codes.copied', 'Copied');

  const tick = ()=>{
    setRevealClipboardCountdownText(
      fmt(tr('my_codes.clipboard_clearing_in_fmt', 'Clearing clipboard in ~{n}s'), {n: left})
    );
  };

  tick();
  revealClipboardCountdownTimer = setInterval(()=>{
    left -= 1;
    if(left <= 0){
      clearRevealClipboardCountdown();
      return;
    }
    tick();
  }, 1000);
}

function openReveal(kind, id, label, hint){
  clearRevealTimers();
  currentReveal = {kind, id, share_after: !!shareAfterReveal};
  shareAfterReveal = false;
  currentShareId = null;
  revealedPwd = null;

  const overlay = document.getElementById('reveal-overlay');
  const sheet = overlay ? overlay.querySelector('.reveal-sheet') : null;
  if(sheet) sheet.removeAttribute('data-state');

  document.getElementById('rv-label').textContent=label;
  document.getElementById('rv-vault').value=vaultPhraseSession||'';

  const pwdEl = document.getElementById('rv-pwd');
  pwdEl.textContent='';
  hideRv(pwdEl);
  hideRv(document.getElementById('rv-copy-btn'));
  hideRv(document.getElementById('rv-share-btn'));
  hideRv(document.getElementById('rv-share-wrap'));
  hideRv(document.getElementById('rv-zk-note'));
  hideRv(document.getElementById('rv-show-btn'));

  const shareOk = document.getElementById('rv-share-ok');
  const shareErr = document.getElementById('rv-share-err');
  if(shareOk) shareOk.classList.remove('show');
  if(shareErr) shareErr.classList.remove('show');
  const shareUrl = document.getElementById('rv-share-url');
  const shareSecret = document.getElementById('rv-share-secret');
  if(shareUrl) shareUrl.value='';
  if(shareSecret) shareSecret.value='';
  const revokeBtn = document.getElementById('rv-share-revoke');
  if(revokeBtn) revokeBtn.style.display='none';

  const btn = document.getElementById('rv-btn');
  const ico = document.getElementById('rv-btn-ico');
  const txt = document.getElementById('rv-btn-txt');
  btn.style.display='block';
  btn.disabled=false;
  setBtnState(btn, ico, txt, null, '🔒', currentReveal.share_after ? tr('my_codes.btn_decrypt_share', 'Decrypt & Share') : tr('my_codes.btn_decrypt_reveal', 'Decrypt & Reveal'));

  const errEl = document.getElementById('rv-err');
  errEl.classList.remove('show');

  const hi=document.getElementById('rv-hint');
  if(hint){hi.textContent=`Hint: "${hint}"`;hi.style.display='block';}else hi.style.display='none';

  overlay.classList.add('show');
  document.body.style.overflow='hidden';
  setTimeout(()=>document.getElementById('rv-vault').focus(),200);
}

async function ensureReauth(methods){
  if(window.LS && LS.reauth){
    return LS.reauth(methods||{}, {post: postCsrf});
  }
  toast(tr('js.enable_totp_or_passkey', 'Enable TOTP or add a passkey in Security'), 'warn');
  return false;
}

async function doReveal(){
  const btn = document.getElementById('rv-btn');
  const ico = document.getElementById('rv-btn-ico');
  const txt = document.getElementById('rv-btn-txt');

  const vault=document.getElementById('rv-vault').value || vaultPhraseSession;
  const errEl=document.getElementById('rv-err');
  errEl.classList.remove('show');

  if(!vault){errEl.textContent=tr('create_code.gen.toast_need_vault','Enter your vault passphrase');errEl.classList.add('show');return;}
  if(!currentReveal || !currentReveal.id){errEl.textContent=tr('my_codes.err_no_lock_selected','No lock selected');errEl.classList.add('show');return;}
  if(!requireOnlineAction()){
    errEl.textContent=tr('my_codes.offline_action_disabled', 'Offline mode: this action is disabled.');
    errEl.classList.add('show');
    return;
  }

  setBtnState(btn, ico, txt, 'working', '⏳', tr('share.btn_decrypting', 'Decrypting…'));
  btn.disabled=true;
  setRevealSheetState('working');

  try{
    const endpoint = (currentReveal.kind === 'wallet') ? 'api/wallet_reveal.php' : 'api/reveal.php';
    const body = (currentReveal.kind === 'wallet')
      ? {wallet_lock_id: currentReveal.id}
      : {lock_id: currentReveal.id};

    let r=await postCsrf(endpoint, body);
    if(!r.success && (r.error_code==='reauth_required' || r.error_code==='security_setup_required')){
      const ok = await ensureReauth(r.methods||{});
      if(!ok) throw new Error(r.error||'Re-authentication required');
      r=await postCsrf(endpoint, body);
    }
    if(!r.success) throw new Error(r.error||'Cannot reveal');

    const payload = (currentReveal.kind === 'wallet') ? (r.wallet_lock || {}) : r;

    let plain = null;

    const inbound = (payload && payload.inbound) ? payload.inbound : null;
    const wrapIters = inbound ? (parseInt(inbound.secret_kdf_iterations || '0', 10) || 0) : 0;

    if(inbound
      && inbound.secret_cipher_blob
      && inbound.secret_iv
      && inbound.secret_auth_tag
      && inbound.secret_kdf_salt
      && wrapIters > 0){

      const wrapKey = await deriveKey(vault, inbound.secret_kdf_salt, wrapIters);
      const secret = await aesDecrypt(inbound.secret_cipher_blob, inbound.secret_iv, inbound.secret_auth_tag, wrapKey);

      const payloadIters = parseInt(payload.kdf_iterations || '0', 10) || 0;
      const payloadKey = await deriveKey(secret, payload.kdf_salt, payloadIters);
      plain = await aesDecrypt(payload.cipher_blob, payload.iv, payload.auth_tag, payloadKey);

    }else{
      const key=await deriveKey(vault, payload.kdf_salt, payload.kdf_iterations);
      plain=await aesDecrypt(payload.cipher_blob, payload.iv, payload.auth_tag, key);
    }

    revealedPwd=plain;

    const pwdEl = document.getElementById('rv-pwd');
    if(currentReveal && currentReveal.share_after){
      // Sharing does not require displaying the plaintext to the user.
      pwdEl.textContent='';
      hideRv(pwdEl);
      hideRv(document.getElementById('rv-copy-btn'));
      hideRv(document.getElementById('rv-share-btn'));
      showRv(document.getElementById('rv-zk-note'));
    } else {
      pwdEl.textContent=plain;
      showRv(pwdEl);
      showRv(document.getElementById('rv-copy-btn'));
      if(currentReveal.kind === 'lock') showRv(document.getElementById('rv-share-btn'));
      showRv(document.getElementById('rv-zk-note'));

      revealPlainHidden = false;
      hideRv(document.getElementById('rv-show-btn'));
      scheduleRevealAutoHide(30);
    }

    vaultPhraseSession=vault;

    if(currentReveal.kind !== 'wallet'){
      vaultSlotSession=parseInt(r.vault_verifier_slot||1,10)||1;
      lsSet('vault_slot', String(vaultSlotSession));
    }

    setRevealSheetState('success');
    setBtnState(btn, ico, txt, 'success', '☺', currentReveal && currentReveal.share_after ? 'Decrypted' : 'Revealed');

    setTimeout(()=>{
      btn.style.display='none';
      setRevealSheetState(null);
      if(currentReveal && currentReveal.share_after && currentReveal.kind === 'lock'){
        startShareFlow();
      }
    }, 700);

  }catch(e){
    if(e && e.name==='OperationError') errEl.textContent='Decryption failed — wrong vault passphrase or tampered data';
    else errEl.textContent=(e && e.message) ? e.message : 'Decryption failed';
    errEl.classList.add('show');

    setRevealSheetState('error');
    setBtnState(btn, ico, txt, 'error', '⚠', 'Failed');

    setTimeout(()=>{
      setRevealSheetState(null);
      setBtnState(
        btn,
        ico,
        txt,
        null,
        '🔒',
        (currentReveal && currentReveal.share_after)
          ? tr('my_codes.btn_decrypt_share', 'Decrypt & Share')
          : tr('my_codes.btn_decrypt_reveal', 'Decrypt & Reveal')
      );
      btn.disabled=false;
    }, 900);
  }
}

function closeReveal(e){
  const overlay = document.getElementById('reveal-overlay');
  if(e && e.target !== overlay) return;

  overlay.classList.remove('show');
  setRevealSheetState(null);
  clearRevealTimers();

  const pwdEl = document.getElementById('rv-pwd');
  if(pwdEl){ pwdEl.textContent = ''; hideRv(pwdEl); }
  hideRv(document.getElementById('rv-copy-btn'));
  hideRv(document.getElementById('rv-share-btn'));
  hideRv(document.getElementById('rv-share-wrap'));
  hideRv(document.getElementById('rv-zk-note'));
  hideRv(document.getElementById('rv-show-btn'));
  resetRevealCopyBtn();

  const navOv = document.getElementById('ls-nav-overlay');
  const moreOv = document.getElementById('ls-overflow-overlay');
  if(!(navOv && navOv.classList.contains('show')) && !(moreOv && moreOv.classList.contains('show'))){
    document.body.style.overflow = '';
  }

  revealedPwd=null;
  currentReveal=null;
  currentShareId=null;
  shareAfterReveal=false;
}

function setShareSheetState(state){
  const sheet = document.querySelector('#share-overlay .reveal-sheet');
  if(!sheet) return;
  if(state) sheet.setAttribute('data-state', state);
  else sheet.removeAttribute('data-state');
}

function openShare(lock){
  if(!lock || lock.kind !== 'lock' || !lock.id) return;

  currentShareLock = lock;
  currentPreShareId = null;

  const overlay = document.getElementById('share-overlay');
  const sheet = overlay ? overlay.querySelector('.reveal-sheet') : null;
  if(sheet) sheet.removeAttribute('data-state');

  const title = document.getElementById('ps-title');
  if(title) title.textContent = lock.label ? String(lock.label) : tr('my_codes.share_title', 'Share lock');

  const meta = document.getElementById('ps-meta');
  if(meta){
    const localStr = fmtLocalTs(lock.reveal_date);
    const utcStr = fmtUtcTs(lock.reveal_date);
    meta.innerHTML = `${esc(fmt(tr('my_codes.sealed_until', 'Sealed until')))} <span>${esc(localStr)}</span> <span class="utc-pill" title="Stored & enforced in UTC">${esc(utcStr)}</span>`;
  }

  const vp = document.getElementById('ps-vault');
  if(vp) vp.value = vaultPhraseSession || '';

  const legacy = document.getElementById('ps-legacy');
  if(legacy) legacy.style.display = 'none';
  const code = document.getElementById('ps-code');
  if(code) code.value = '';

  const allow = document.getElementById('ps-allow');
  if(allow) allow.checked = true;

  const err = document.getElementById('ps-err');
  if(err){ err.classList.remove('show'); err.textContent=''; }

  const out = document.getElementById('ps-out');
  if(out) out.style.display='none';

  const ok = document.getElementById('ps-ok');
  if(ok){ ok.className='msg msg-ok'; ok.textContent=''; ok.classList.remove('show'); }

  const revoke = document.getElementById('ps-revoke');
  if(revoke) revoke.style.display='none';

  const btn = document.getElementById('ps-btn');
  const ico = document.getElementById('ps-ico');
  const txt = document.getElementById('ps-txt');
  if(btn){ btn.disabled = false; setBtnState(btn, ico, txt, null, '🔗', tr('my_codes.share_create_btn', 'Create share link')); }

  if(overlay){
    overlay.classList.add('show');
    document.body.style.overflow='hidden';
    setTimeout(()=>{ if(vp) vp.focus(); }, 150);
  }
}

function closeShare(e){
  const overlay = document.getElementById('share-overlay');
  if(!overlay) return;
  if(e && e.target !== overlay) return;

  overlay.classList.remove('show');
  setShareSheetState(null);

  const navOv = document.getElementById('ls-nav-overlay');
  const moreOv = document.getElementById('ls-overflow-overlay');
  const rvOv = document.getElementById('reveal-overlay');

  if(!(rvOv && rvOv.classList.contains('show'))
    && !(navOv && navOv.classList.contains('show'))
    && !(moreOv && moreOv.classList.contains('show'))){
    document.body.style.overflow = '';
  }

  currentShareLock = null;
  currentPreShareId = null;
}

function setPreShareMsg(el, txt, ok){
  if(!el) return;
  el.textContent = txt || '';
  if(!txt){ el.classList.remove('show'); return; }
  el.classList.add('show');
  el.className = 'msg ' + (ok ? 'msg-ok' : 'msg-err') + ' show';
}

async function revokePreShare(){
  if(!currentPreShareId) return;
  if(!requireOnlineAction()) return;

  {
    const msg = tr('my_codes.share_revoke_confirm', 'Revoke this share link? Anyone with it will lose access.');
    const ok = (window.LS && typeof window.LS.confirm === 'function')
      ? await window.LS.confirm(msg, {title: tr('common.confirm', 'Confirm'), danger: true})
      : (typeof window.uiConfirm === 'function' ? await window.uiConfirm({title: tr('common.confirm', 'Confirm'), message: msg, danger: true}) : false);
    if(!ok) return;
  }

  const okEl = document.getElementById('ps-ok');
  const errEl = document.getElementById('ps-err');
  setPreShareMsg(okEl, '', true);
  setPreShareMsg(errEl, '', false);

  const r = await postCsrf('api/shares.php', {action:'revoke', share_id: currentPreShareId});
  if(!r.success){
    setPreShareMsg(errEl, r.error || 'Failed', false);
    return;
  }

  currentPreShareId = null;
  const revokeBtn = document.getElementById('ps-revoke');
  if(revokeBtn) revokeBtn.style.display='none';
  setPreShareMsg(okEl, tr('my_codes.share_link_revoked', 'Link revoked.'), true);
}

async function createShareFromPrep(){
  if(!currentShareLock || currentShareLock.kind !== 'lock' || !currentShareLock.id){
    toast(tr('my_codes.toast_select_lock_first','Select a lock first'), 'err');
    return;
  }
  if(!requireOnlineAction()) return;

  const legacyWrap = document.getElementById('ps-legacy');
  const code = (document.getElementById('ps-code').value || '').trim();
  const vp = (document.getElementById('ps-vault').value || vaultPhraseSession || '').trim();

  if(!vp && !code){
    const err = document.getElementById('ps-err');
    if(err){ err.textContent = 'Enter your vault passphrase (or paste the saved code in legacy mode).'; err.classList.add('show'); }
    return;
  }

  const btn = document.getElementById('ps-btn');
  const ico = document.getElementById('ps-ico');
  const txt = document.getElementById('ps-txt');
  const errEl = document.getElementById('ps-err');
  const okEl = document.getElementById('ps-ok');

  if(errEl){ errEl.classList.remove('show'); errEl.textContent=''; }
  setPreShareMsg(okEl, '', true);

  setBtnState(btn, ico, txt, 'working', '⏳', 'Creating…');
  if(btn) btn.disabled = true;
  setShareSheetState('working');

  try{
    const allowEl = document.getElementById('ps-allow');
    const allow = allowEl ? !!allowEl.checked : true;

    // Legacy path: paste the plaintext code (for locks created before share precomputation).
    if(code){
      const secret = genShareSecret();
      const c = requireWebCrypto();
      const saltBytes = new Uint8Array(16);
      c.getRandomValues(saltBytes);
      const saltB64 = bytesToB64(saltBytes);

      const iters = 310000;
      const key = await deriveKey(secret, saltB64, iters);
      const enc = await aesEncrypt(code, key);

      const payloadLegacy = {
        action: 'create',
        lock_id: currentShareLock.id,
        share_cipher_blob: enc.cipher_blob,
        share_iv: enc.iv,
        share_auth_tag: enc.auth_tag,
        share_kdf_salt: saltB64,
        share_kdf_iterations: iters,
        allow_reveal_after_date: allow ? 1 : 0,
      };

      let r = await postCsrf('api/shares.php', payloadLegacy);
      if(!r.success && (r.error_code==='reauth_required' || r.error_code==='security_setup_required')){
        const ok2 = await ensureReauth(r.methods||{});
        if(!ok2) throw new Error(r.error||'Re-authentication required');
        r = await postCsrf('api/shares.php', payloadLegacy);
      }
      if(!r.success) throw new Error(r.error || 'Failed');

      currentPreShareId = parseInt(r.share_id||'0', 10) || null;

      const out = document.getElementById('ps-out');
      if(out) out.style.display = 'block';

      const urlEl = document.getElementById('ps-url');
      const secEl = document.getElementById('ps-secret');
      if(urlEl) urlEl.value = String(r.share_url||'');
      if(secEl) secEl.value = secret;

      const revokeBtn = document.getElementById('ps-revoke');
      if(revokeBtn && currentPreShareId) revokeBtn.style.display = 'inline-flex';

      setShareSheetState('success');
      setBtnState(btn, ico, txt, 'success', '☺', 'Created');
      setPreShareMsg(okEl, 'Share link created. Copy both the link and the secret.', true);
      return;
    }

    // Preferred path: create from server-stored precomputation (no plaintext).
    const payload = {
      action: 'create_from_prep',
      lock_id: currentShareLock.id,
      allow_reveal_after_date: allow ? 1 : 0,
    };

    let r = await postCsrf('api/shares.php', payload);
    if(!r.success && (r.error_code==='reauth_required' || r.error_code==='security_setup_required')){
      const ok2 = await ensureReauth(r.methods||{});
      if(!ok2) throw new Error(r.error||'Re-authentication required');
      r = await postCsrf('api/shares.php', payload);
    }

    if(!r.success){
      const m = String(r.error||'Failed');
      if(legacyWrap && (m.includes('not initialized') || m.includes('precomputation') || m.includes('unavailable'))){
        legacyWrap.style.display = 'block';
        throw new Error('This lock can’t be shared without unlock. Paste the saved code below to create a legacy share link.');
      }
      throw new Error(m);
    }

    const wrap = r.share_secret_wrap || null;
    if(!wrap || !wrap.cipher_blob || !wrap.iv || !wrap.auth_tag || !wrap.kdf_salt){
      throw new Error('Missing share secret');
    }

    const iters = parseInt(wrap.kdf_iterations||310000, 10) || 310000;
    const key = await deriveKey(vp, wrap.kdf_salt, iters);
    const secret = await aesDecrypt(wrap.cipher_blob, wrap.iv, wrap.auth_tag, key);

    vaultPhraseSession = vp;

    currentPreShareId = parseInt(r.share_id||'0', 10) || null;

    const out = document.getElementById('ps-out');
    if(out) out.style.display = 'block';

    const urlEl = document.getElementById('ps-url');
    const secEl = document.getElementById('ps-secret');
    if(urlEl) urlEl.value = String(r.share_url||'');
    if(secEl) secEl.value = String(secret||'');

    const revokeBtn = document.getElementById('ps-revoke');
    if(revokeBtn && currentPreShareId) revokeBtn.style.display = 'inline-flex';

    setShareSheetState('success');
    setBtnState(btn, ico, txt, 'success', '☺', 'Created');
    setPreShareMsg(okEl, 'Share link created. Copy both the link and the secret.', true);

  }catch(e){
    setShareSheetState('error');

    const msg = (e && e.name==='OperationError')
      ? 'Incorrect vault passphrase or tampered data'
      : ((e && e.message) ? e.message : 'Failed');

    if(errEl){ errEl.textContent = msg; errEl.classList.add('show'); }
    setBtnState(btn, ico, txt, 'error', '⚠', 'Failed');

  }finally{
    setTimeout(()=>{
      setShareSheetState(null);
      setBtnState(btn, ico, txt, null, '🔗', 'Create share link');
      if(btn) btn.disabled = false;
    }, 900);
  }
}

async function copyRevealed(){
  if(!revealedPwd || !currentReveal || !currentReveal.id) return;
  try{
    let copied = false;
    if(window.LS && LS.copySensitive){
      copied = await LS.copySensitive(revealedPwd, {clearAfterMs: 30000});
    }else{
      await navigator.clipboard.writeText(revealedPwd);
      copied = true;
    }

    if(!copied) return;

    if(currentReveal.kind !== 'wallet'){
      await postCsrf('api/copied.php',{lock_id:currentReveal.id});
    }

    toast(tr('share.toast_copied', 'Copied (will try to clear in ~30s)'),'ok');
    startRevealClipboardCountdown(30);
    loadLocks();
  }catch{
    toast(tr('share.toast_select_manually', 'Select the text manually'),'err');
  }
}

function bytesToHex(bytes){
  return Array.from(bytes).map(b => b.toString(16).padStart(2,'0')).join('');
}

function formatSecret(hex){
  const parts = String(hex||'').match(/.{1,4}/g);
  return parts ? parts.join('-') : String(hex||'');
}

function genShareSecret(){
  const c = requireWebCrypto();
  const b = new Uint8Array(16);
  c.getRandomValues(b);
  return formatSecret(bytesToHex(b));
}

function setShareMsg(el, txt, ok){
  if(!el) return;
  el.textContent = txt || '';
  if(!txt){ el.classList.remove('show'); return; }
  el.classList.add('show');
  el.className = 'msg ' + (ok ? 'msg-ok' : 'msg-err') + ' show';
}

async function copyVal(id){
  const el = document.getElementById(id);
  const val = el ? (el.value || '') : '';
  if(!val) return;
  try{
    await navigator.clipboard.writeText(val);
    toast('Copied','ok');
  }catch{
    toast('Copy blocked','err');
  }
}

async function revokeShare(){
  if(!currentShareId) return;
  if(!requireOnlineAction()) return;
  {
    const msg = tr('my_codes.share_revoke_confirm', 'Revoke this share link? Anyone with it will lose access.');
    const ok = (window.LS && typeof window.LS.confirm === 'function')
      ? await window.LS.confirm(msg, {title: tr('common.confirm', 'Confirm'), danger: true})
      : (typeof window.uiConfirm === 'function' ? await window.uiConfirm({title: tr('common.confirm', 'Confirm'), message: msg, danger: true}) : false);
    if(!ok) return;
  }

  const okEl = document.getElementById('rv-share-ok');
  const errEl = document.getElementById('rv-share-err');
  setShareMsg(okEl, '', true);
  setShareMsg(errEl, '', false);

  const r = await postCsrf('api/shares.php', {action:'revoke', share_id: currentShareId});
  if(!r.success){
    setShareMsg(errEl, r.error || 'Failed', false);
    return;
  }

  currentShareId = null;
  const revokeBtn = document.getElementById('rv-share-revoke');
  if(revokeBtn) revokeBtn.style.display='none';
  setShareMsg(okEl, tr('my_codes.share_link_revoked', 'Link revoked.'), true);
}

async function startShareFlow(){
  if(!currentReveal || currentReveal.kind !== 'lock' || !currentReveal.id){
    toast(tr('my_codes.toast_select_lock_first','Select a lock first'), 'err');
    return;
  }
  if(!revealedPwd){
    toast(tr('my_codes.toast_decrypt_first_share','Decrypt first to generate a share link'), 'warn');
    return;
  }
  if(!requireOnlineAction()) return;

  const wrap = document.getElementById('rv-share-wrap');
  showRv(wrap);

  const shareBtn = document.getElementById('rv-share-btn');
  if(shareBtn) shareBtn.disabled = true;

  const okEl = document.getElementById('rv-share-ok');
  const errEl = document.getElementById('rv-share-err');
  setShareMsg(okEl, '', true);
  setShareMsg(errEl, '', false);

  try{
    const secret = genShareSecret();
    const c = requireWebCrypto();
    const saltBytes = new Uint8Array(16);
    c.getRandomValues(saltBytes);
    const saltB64 = bytesToB64(saltBytes);

    const iters = 310000;
    const key = await deriveKey(secret, saltB64, iters);
    const enc = await aesEncrypt(revealedPwd, key);

    const allowEl = document.getElementById('rv-share-allow');
    const allow = allowEl ? !!allowEl.checked : true;

    const payload = {
      action: 'create',
      lock_id: currentReveal.id,
      share_cipher_blob: enc.cipher_blob,
      share_iv: enc.iv,
      share_auth_tag: enc.auth_tag,
      share_kdf_salt: saltB64,
      share_kdf_iterations: iters,
      allow_reveal_after_date: allow ? 1 : 0,
    };

    let r = await postCsrf('api/shares.php', payload);
    if(!r.success && (r.error_code==='reauth_required' || r.error_code==='security_setup_required')){
      const ok2 = await ensureReauth(r.methods||{});
      if(!ok2) throw new Error(r.error||'Re-authentication required');
      r = await postCsrf('api/shares.php', payload);
    }

    if(!r.success) throw new Error(r.error || 'Failed');

    currentShareId = parseInt(r.share_id||'0', 10) || null;

    const urlEl = document.getElementById('rv-share-url');
    const secEl = document.getElementById('rv-share-secret');
    if(urlEl) urlEl.value = String(r.share_url||'');
    if(secEl) secEl.value = secret;

    const revokeBtn = document.getElementById('rv-share-revoke');
    if(revokeBtn && currentShareId){
      revokeBtn.style.display='inline-flex';
    }

    setShareMsg(okEl, 'Share link created. Copy both the link and the secret.', true);

  }catch(e){
    setShareMsg(errEl, (e && e.message) ? e.message : 'Failed', false);

  }finally{
    if(shareBtn){
      shareBtn.disabled = false;
    }
  }
}

async function runLockAction(id, action){
  if(!requireOnlineAction()) return false;

  const lockId = String(id||'');
  const act = String(action||'');
  if(!lockId || !act) return false;

  const body = {lock_id: lockId, action: act};

  let r = await postCsrf('api/confirm.php', body);
  if(!r.success && (r.error_code==='reauth_required' || r.error_code==='security_setup_required')){
    const ok = await ensureReauth(r.methods||{});
    if(!ok) return false;
    r = await postCsrf('api/confirm.php', body);
  }

  if(r.success){
    if(act === 'confirm') toast(tr('my_codes.lock_activated', 'Lock activated!'), 'ok');
    else if(act === 'reject') toast(tr('my_codes.lock_voided', 'Voided'), 'ok');
    else if(act === 'auto_save') toast(tr('my_codes.lock_auto_saved', 'Auto-saved'), 'ok');
    else toast(tr('common.save', 'Saved'), 'ok');

    loadLocks();
    return true;
  }

  toast(r.error || tr('common.failed','Failed'), 'err');
  return false;
}

async function reConfirm(id){
  return runLockAction(id, 'confirm');
}

async function delLock(kind, id, opts){
  if(!requireOnlineAction()) return false;

  const o = opts || {};
  const k = String(kind||'lock');

  const msg = (k === 'wallet')
    ? tr('my_codes.delete_confirm_wallet', 'Permanently delete this wallet code? Encrypted data will be removed.')
    : tr('my_codes.delete_confirm_lock', 'Permanently delete this lock? Encrypted data will be removed.');

  if(!o.skipConfirm){
    const ok = (window.LS && typeof window.LS.confirm === 'function')
      ? await window.LS.confirm(msg, {title: tr('common.confirm', 'Confirm'), danger: true})
      : (typeof window.uiConfirm === 'function' ? await window.uiConfirm({title: tr('common.confirm', 'Confirm'), message: msg, danger: true}) : false);
    if(!ok) return false;
  }

  const endpoint = (k === 'wallet') ? 'api/wallet_delete.php' : 'api/delete.php';
  const body = (k === 'wallet') ? {wallet_lock_id:id} : {lock_id:id};

  const r=await postCsrf(endpoint, body);
  if(r.success){
    if(!o.silent) toast(tr('my_codes.deleted', 'Deleted'),'ok');
    if(!o.skipReload) loadLocks();
    return true;
  }

  if(!o.silent){
    if(r && r.error_code === 'delete_not_allowed'){
      toast(tr('my_codes.delete_not_allowed', 'This code cannot be deleted until it has been revealed at least once.'), 'warn');
    } else if(r && r.error_code === 'delete_too_soon'){
      const ts = r.earliest_delete_at ? fmtLocalTs(r.earliest_delete_at) : '';
      const remaining = r.time_remaining ? String(r.time_remaining) : '';
      const msg = fmt(
        tr('my_codes.delete_too_soon_fmt', 'Delete available {ts}{rest}.'),
        {ts: ts || tr('my_codes.delete_too_soon_ts_unknown', 'later'), rest: remaining ? (' (' + remaining + ')') : ''}
      );
      toast(msg, 'warn');
    } else {
      toast(r.error||tr('my_codes.delete_failed', 'Delete failed'),'err');
    }
  }

  return false;
}

document.addEventListener('DOMContentLoaded', async ()=>{
  const storedSlot = parseInt(lsGet('vault_slot') || '1', 10);
  vaultSlotSession = ([1,2].includes(storedSlot) ? storedSlot : 1);

  loadStars();

  const copyUrl = document.getElementById('rv-share-copy-url');
  const copySecret = document.getElementById('rv-share-copy-secret');
  const revokeBtn = document.getElementById('rv-share-revoke');
  if(copyUrl) copyUrl.addEventListener('click', ()=>copyVal('rv-share-url'));
  if(copySecret) copySecret.addEventListener('click', ()=>copyVal('rv-share-secret'));
  if(revokeBtn) revokeBtn.addEventListener('click', revokeShare);

  const psCopyUrl = document.getElementById('ps-copy-url');
  const psCopySecret = document.getElementById('ps-copy-secret');
  const psRevoke = document.getElementById('ps-revoke');
  if(psCopyUrl) psCopyUrl.addEventListener('click', ()=>copyVal('ps-url'));
  if(psCopySecret) psCopySecret.addEventListener('click', ()=>copyVal('ps-secret'));
  if(psRevoke) psRevoke.addEventListener('click', revokePreShare);

  initLocksToolbar();
  restoreLocksToolbarState();
  updateLocksSegCounts();
  await loadLocks();
});
</script>
</body>
</html> 
