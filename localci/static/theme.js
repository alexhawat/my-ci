/* Apply before the stylesheet paints; appearance is a browser-local preference. */
(() => {
  const key = 'localci.theme';
  const modes = new Set(['light', 'dark', 'system']);
  const media = window.matchMedia('(prefers-color-scheme: dark)');
  let preference = 'system';
  try {
    const saved = localStorage.getItem(key);
    if (modes.has(saved)) preference = saved;
  } catch { /* Storage can be unavailable in private/restricted browser contexts. */ }
  function apply() {
    document.documentElement.dataset.theme = preference === 'system'
      ? (media.matches ? 'dark' : 'light') : preference;
    const picker = document.getElementById('theme');
    if (picker) picker.value = preference;
  }
  apply();
  media.addEventListener('change', apply);
  window.addEventListener('storage', event => {
    if (event.key !== key && event.key !== null) return;
    preference = modes.has(event.newValue) ? event.newValue : 'system';
    apply();
  });
  document.addEventListener('DOMContentLoaded', () => {
    const picker = document.getElementById('theme');
    if (!picker) return;
    apply();
    picker.addEventListener('change', () => {
      preference = modes.has(picker.value) ? picker.value : 'system';
      try { localStorage.setItem(key, preference); } catch { /* Keep the current choice in memory. */ }
      apply();
    });
  });
})();
