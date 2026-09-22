'use strict';

// Intentionally tiny. Server-rendered pages own navigation and state; JavaScript
// is for local interaction only, not for recreating an SPA framework.
document.addEventListener('click', (event) => {
  const target = event.target.closest('[data-copy]');
  if (!target) return;
  const value = target.getAttribute('data-copy') || '';
  if (value && navigator.clipboard) navigator.clipboard.writeText(value);
});
