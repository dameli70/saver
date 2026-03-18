<?php
// Simple i18n layer (French default)
// - Stores language in session + cookie
// - Loads translation arrays from includes/lang/{lang}.php
// - Provides t()/e()/currentLang()/langSwitchUrl()

// Supported language codes
const I18N_SUPPORTED_LANGS = ['fr', 'en'];
const I18N_DEFAULT_LANG = 'fr';

function i18nAppBasePath(): string {
    // Similar to includes/install_guard.php:getAppBasePath, but standalone.
    $dir = rtrim(dirname($_SERVER['SCRIPT_NAME'] ?? '/'), '/');
    $dir = preg_replace('#/(api|install)$#', '', $dir);
    return ($dir === '/' ? '' : $dir);
}

function i18nIsHttps(): bool {
    return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
}

function i18nSetLang(string $lang): void {
    if (!in_array($lang, I18N_SUPPORTED_LANGS, true)) {
        $lang = I18N_DEFAULT_LANG;
    }

    if (session_status() === PHP_SESSION_ACTIVE) {
        $_SESSION['lang'] = $lang;
    }

    // Persist language in a non-HttpOnly cookie so JS can read document language choice if needed.
    $path = i18nAppBasePath();
    // Cookie path should be the app base path (or '/' for root installs).
    // Avoid a trailing slash so the cookie also matches the bare base path (e.g., '/app').
    $cookiePath = ($path !== '' ? $path : '/');

    // Clear legacy cookie paths from older versions (which used a trailing slash).
    $legacyPath = ($path !== '' ? ($path . '/') : '/');
    if ($legacyPath !== $cookiePath) {
        setcookie('lang', '', [
            'expires' => time() - 3600,
            'path' => $legacyPath,
            'secure' => i18nIsHttps(),
            'httponly' => false,
            'samesite' => 'Lax',
        ]);
    }

    setcookie('lang', $lang, [
        'expires' => time() + (86400 * 365),
        'path' => $cookiePath,
        'secure' => i18nIsHttps(),
        'httponly' => false,
        'samesite' => 'Lax',
    ]);

    $GLOBALS['I18N_LANG'] = $lang;
}

function i18nBootstrap(): void {
    if (!empty($GLOBALS['I18N_BOOTSTRAPPED'])) return;

    $lang = I18N_DEFAULT_LANG;

    if (session_status() === PHP_SESSION_ACTIVE && !empty($_SESSION['lang'])) {
        $lang = (string)$_SESSION['lang'];
    } elseif (!empty($_COOKIE['lang'])) {
        $lang = (string)$_COOKIE['lang'];
    }

    if (!in_array($lang, I18N_SUPPORTED_LANGS, true)) {
        $lang = I18N_DEFAULT_LANG;
    }

    // Ensure session+cookie are aligned to the chosen language.
    // (Safe to call early; pages call startSecureSession() before output.)
    i18nSetLang($lang);

    $dictPath = __DIR__ . '/lang/' . $lang . '.php';
    $dict = file_exists($dictPath) ? require $dictPath : [];

    $GLOBALS['I18N_DICT'] = is_array($dict) ? $dict : [];
    $GLOBALS['I18N_BOOTSTRAPPED'] = 1;
}

function currentLang(): string {
    i18nBootstrap();
    return (string)($GLOBALS['I18N_LANG'] ?? I18N_DEFAULT_LANG);
}

function htmlLangAttr(): string {
    return 'lang="' . htmlspecialchars(currentLang(), ENT_QUOTES, 'UTF-8') . '"';
}

function t(string $key, array $vars = []): string {
    i18nBootstrap();

    $dict = $GLOBALS['I18N_DICT'] ?? [];
    $s = $dict[$key] ?? $key;

    if ($vars) {
        foreach ($vars as $k => $v) {
            $s = str_replace('{' . $k . '}', (string)$v, $s);
        }
    }

    return (string)$s;
}

function e(string $key, array $vars = []): void {
    echo htmlspecialchars(t($key, $vars), ENT_QUOTES, 'UTF-8');
}

function langSwitchUrl(string $lang, ?string $returnTo = null): string {
    $base = i18nAppBasePath();

    $r = $returnTo ?? ($_SERVER['REQUEST_URI'] ?? '/');
    $r = (string)$r;

    // Only allow relative in-app paths.
    if ($r === '' || $r[0] !== '/') $r = '/';

    // For subdirectory installs, REQUEST_URI includes the base path already.
    // set_language.php expects an app-relative path (without $base) to avoid /base/base/* redirects.
    if ($base !== '' && (
        $r === $base ||
        str_starts_with($r, $base . '/') ||
        str_starts_with($r, $base . '?')
    )) {
        $r = substr($r, strlen($base));
        if ($r === '' || $r[0] !== '/') {
            $r = '/' . ltrim($r, '/');
        }
    }

    $u = ($base ? $base : '') . '/set_language.php?lang=' . rawurlencode($lang) . '&r=' . rawurlencode($r);
    return $u;
}

function i18nDefaultJsKeys(): array {
    return [
        // assets/app.js
        'js.reauth_title',
        'js.reauth_sub',
        'js.authenticator_code',
        'js.use_passkey',
        'js.use_auth_code',
        'js.waiting',
        'js.internal_error_missing_auth',
        'js.enable_totp_or_passkey',
        'js.passkey_reauth_failed',
        'js.enter_6_digit_code',
        'js.invalid_code',
        'js.cancelled',
        'js.unsupported_reauth',
        'js.reauth_failed',
        'js.copy_confirm',

        // Shared buttons
        'common.confirm',
        'common.cancel',
        'common.back',
        'common.close',

        // assets/theme.js
        'theme.switch_to_light',
        'theme.switch_to_dark',
    ];
}

function emitI18nJsGlobals(?array $keys = null): void {
    i18nBootstrap();

    // If no key list is provided, emit the entire dictionary so inline page scripts
    // can always call LS.t('some.key') without needing to maintain a per-page key list.
    if ($keys === null) {
        $keys = array_keys($GLOBALS['I18N_DICT'] ?? []);
    }

    $strings = [];
    foreach ($keys as $k) {
        $strings[$k] = t($k);
    }

    $payload = [
        'lang' => currentLang(),
        'strings' => $strings,
    ];

    echo "<script>window.LS_I18N=" . json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . ";</script>\n";
}
 