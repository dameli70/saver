(function(){
  const KEY = 'locksmith_theme';
  const root = document.documentElement;

  function t(key, fallback){
    const raw = (window && window.LS_I18N && typeof window.LS_I18N === 'object') ? window.LS_I18N : null;
    const strings = (raw && raw.strings && typeof raw.strings === 'object') ? raw.strings : {};

    if(strings && Object.prototype.hasOwnProperty.call(strings, key)){
      return String(strings[key]);
    }

    return String(fallback == null ? key : fallback);
  }

  function apply(theme){
    root.setAttribute('data-theme', theme);
  }

  function preferred(){
    const stored = localStorage.getItem(KEY);
    if(stored === 'light' || stored === 'dark') return stored;
    if(window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) return 'light';
    return 'dark';
  }

  function set(theme){
    localStorage.setItem(KEY, theme);
    apply(theme);
    window.dispatchEvent(new CustomEvent('locksmith-theme-change', { detail: theme }));
  }

  function toggle(){
    const cur = root.getAttribute('data-theme') || 'dark';
    const next = cur === 'dark' ? 'light' : 'dark';
    set(next);
    return next;
  }

  // Apply immediately (before paint) if this script is loaded in <head>.
  apply(preferred());

  window.LOCKSMITH_THEME = {
    get: () => root.getAttribute('data-theme') || 'dark',
    set,
    toggle,
  };

  function toggleLabel(){
    const cur = root.getAttribute('data-theme') || 'dark';
    return cur === 'dark'
      ? t('theme.switch_to_light', 'Switch to light mode')
      : t('theme.switch_to_dark', 'Switch to dark mode');
  }

  function initToggle(el){
    const render = () => {
      const lbl = toggleLabel();
      el.setAttribute('aria-label', lbl);
      el.setAttribute('title', lbl);
    };

    el.addEventListener('click', () => {
      toggle();
      render();
    });

    window.addEventListener('locksmith-theme-change', render);
    render();
  }

  document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('[data-theme-toggle]').forEach(initToggle);
  });
})();
