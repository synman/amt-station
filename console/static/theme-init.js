/* Applies a saved manual theme before first paint; without one the page follows prefers-color-scheme (theme.css). */
(function () {
  try {
    var v = localStorage.getItem('amt-console-theme');
    if (v === 'light' || v === 'dark') document.documentElement.setAttribute('data-theme', v);
  } catch (e) { /* storage blocked: follow the system */ }
}());
