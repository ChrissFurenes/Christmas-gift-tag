'use strict';
document.querySelector('[data-print-now]')?.addEventListener('click', () => window.print());
document.querySelector('[data-close-print]')?.addEventListener('click', () => window.close());
// Wait for the entire page including QR-code images before showing the print dialog.
window.addEventListener('load', () => window.print(), {once: true});
