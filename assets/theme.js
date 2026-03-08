(function(){
  const KEY = 'locksmith_theme';
  const root = document.documentElement;

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
    return cur === 'dark' ? 'Switch to light mode' : 'Switch to dark mode';
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
